import subprocess
import sys
from time import sleep

from django.urls import reverse
from rest_framework import status

from api.settings import TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD
from config_app.models import Interface
from firewall_app.models import Policy
from parser_utils.mod_policy.policy import is_policy_applied, check_expected_policy_result_in_db
from qos_utils.utils import DOWNLOAD_IFB
from root_runner.sudo_utils import sudo_runner, sudo_file_reader
from utils.config_files import TEST_COMMANDS_FILE, TEST_PATH
from utils.test.helpers import CustomAPITestCase

username = TEST_ADMIN_USERNAME
password = TEST_ADMIN_PASSWORD


class PolicyTest(CustomAPITestCase):
    fixtures = ['test_config.json', 'config_app/fixtures/initial_data.json', 'test_entity.json']

    # def add_test_policy(self, data):
    #     serializer = PolicySerializer(data= data)
    #     if not serializer.is_valid():
    #         raise ValueError(serializer.errors)
    #     instance = serializer.save()
    #     print(instance.source_destination.src_network_list)
    #     return instance

    def setUp(self):
        super(PolicyTest, self).setUp()
        if "--debug-mode" in sys.argv:
            sudo_runner('sudo iptables -F')
            sudo_runner('sudo iptables -X')
            sudo_runner('sudo iptables -t nat -F')
            sudo_runner('sudo iptables -t nat -X')

    # def tearDown(self):
    #     if "--debug-mode" in sys.argv:
    #         sudo_runner('sudo iptables -F')
    #         sudo_runner('sudo iptables -X')
    #         sudo_runner('sudo iptables -t nat -F')
    #         sudo_runner('sudo iptables -t nat -X')

    def checkPolicy(self, policy, policy_expected_commands=None):
        if "--debug-mode" not in sys.argv:
            return check_expected_policy_result_in_db(policy_expected_commands, policy.id)

        return is_policy_applied(policy, policy_expected_commands)

    ##################################PostPolicy without source_destination######################################

    def test_post_policy(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [1],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)

        policy_id = response.json()['id']
        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=1).exists())

        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -j ACCEPT'.format(id=policy_id)],
            'nat_order': None, 'pbr_commands': [], 'nat_rule_commands': [],
            'main_rule_commands': [' ! -i lo -m set --set polset_{id}_src src -j policy_id_{id}'.format(id=policy_id)],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id)], 'main_order': 1, 'src_ip_list': ['10.10.10.1']}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    def test_post_policy_service_all_tcp_udp_icmp(self):
        # apps.get_app_config('config_app').ready()
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [7, 2, 8],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']

        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -p udp -j ACCEPT'.format(id=policy_id),
            'policy_id_{id} -p udp -j ACCEPT'.format(id=policy_id),
            'policy_id_{id} -p udp -j ACCEPT'.format(id=policy_id)],
            'nat_order': None, 'pbr_commands': [], 'nat_rule_commands': [],
            'main_rule_commands': [' ! -i lo     -j policy_id_{id}'.format(id=policy_id)],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id)], 'main_order': 2}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    def test_post_policy_service_icmp_type_code_with_allicmp(self):
        # apps.get_app_config('config_app').ready()
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [8, 9],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']

        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -p icmp --icmp-type 12/2 -j ACCEPT'.format(id=policy_id),
            'policy_id_{id} -p icmp -j ACCEPT'.format(id=policy_id)],
            'nat_order': None, 'pbr_commands': [], 'nat_rule_commands': [],
            'main_rule_commands': [' ! -i lo     -j policy_id_{id}'.format(id=policy_id)],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id)], 'main_order': 2}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    def test_post_policy_service_ip_protocol_number(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [10],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']

        policy_expected_commands = {'chain_commands': ['policy_id_{id} -p 12 -j ACCEPT'.format(id=policy_id)],
                                    'nat_order': None, 'pbr_commands': [], 'nat_rule_commands': [],
                                    'main_rule_commands': [' ! -i lo     -j policy_id_{id}'.format(id=policy_id)],
                                    'create_chains': ['-N policy_id_{id}'.format(id=policy_id)], 'main_order': 2}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    def test_post_none_policy_log(self):
        url = reverse('policy-list')
        data = {
            "nat": None,
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [3, 6],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens18", "ens19"]
            },
            'action': None,
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': True,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']

        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
        self.assertTrue(
            Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(name="ens18").exists())
        self.assertTrue(
            Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(name="ens19").exists())

        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -p tcp  -mmultiport --sport 8432  -mmultiport --dport 13243  -m state ! --state '
            'ESTABLISHED -m conntrack ! --ctstatus CONFIRMED -j LOG --log-prefix "[f:{id},{name},n]"'.format(
                id=policy_id, name=data['name']),
            'policy_id_{id} -p tcp -mmultiport --dport 1283 -m state ! --state '
            'ESTABLISHED -m conntrack ! --ctstatus CONFIRMED -j LOG --log-prefix "[f:{id},{name},n]"'.format(
                id=policy_id, name=data['name'])],
            'pbr_commands': [],
            'main_rule_commands': ['  ! -i lo   -o ens18   -j policy_id_{id}'.format(id=policy_id),
                                   '  ! -i lo   -o ens19   -j policy_id_{id}'.format(id=policy_id)],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id)],
            'nat_rule_commands': [],
            'main_order': 1}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    def test_post_none_policy_nat(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "SNAT",
                "snat_type": "interface_ip",
                "is_enabled": True
            },
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [3, 6],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens18", "ens19"]
            },
            'action': None,
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']
        nat_id = response.json()['nat']['id']

        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
        self.assertTrue(
            Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(name="ens18").exists())
        self.assertTrue(
            Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(name="ens19").exists())

        policy_expected_commands = {'chain_commands': [
            'nat_id_{id}  -p tcp  -mmultiport --sport 8432  -mmultiport --dport 13243 -j MASQUERADE -t nat'.format(
                id=nat_id),
            'nat_id_{id}  -p tcp   -mmultiport --dport 1283 -j MASQUERADE -t nat'.format(
                id=nat_id)],
            'nat_order': 2, 'pbr_commands': [],
            'nat_rule_commands': [' -o ens18   -j nat_id_{id}'.format(id=nat_id),
                                  ' -o ens19 -j nat_id_{id}'.format(id=nat_id)],
            'main_rule_commands': [],
            'create_chains': ['-t nat -N nat_id_{id}'.format(id=nat_id)],
            'main_order': 1}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    def test_post_none_policy_qos(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [1],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens80"]
            },
            'qos': {
                'download_guaranteed_bw': 2500,
                'download_max_bw': 3500,
                'traffic_priority': 'low',
                'shape_type': 'per_ip'
            },

            'action': None,
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        print(response.content)
        self.assertEqual(response.status_code, 201)

        class_id = response.json()['qos']['class_id']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}' \
                                           .format(dev=DOWNLOAD_IFB, id=class_id,
                                                   rate=data['qos']['download_guaranteed_bw'],
                                                   ceil=data['qos']['download_max_bw'], priority='3')))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc qdisc add dev {interface} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
                                               interface=DOWNLOAD_IFB, id=class_id)))

        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src 10.10.10.1 match ip dst any match mark 81 0xffff flowid 1:{class_id}' \
                                           .format(interface=DOWNLOAD_IFB, class_id=class_id)))

        policy_id = response.json()['id']
        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=1).exists())

    # def test_post_policy_multiple_service(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [2, 3, 6, 4, 5, 8],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #
    #     policy_expected_commands = {'chain_commands': [
    #         'policy_id_{id} -p udp -j ACCEPT'.format(id=policy_id),
    #         'policy_id_{id} -p tcp  -mmultiport --sport 8432  -mmultiport --dport 13243 -j ACCEPT'.format(id=policy_id),
    #         'policy_id_{id} -p udp  -mmultiport --sport 2344,123:300  -j ACCEPT'.format(id=policy_id),
    #         'policy_id_{id} -p udp  -mmultiport --sport 9000:9005,43122  -mmultiport --dport 125:980,1243 -j ACCEPT'.format(
    #             id=policy_id),
    #         'policy_id_{id} -p tcp   -mmultiport --dport 1283 -j ACCEPT'.format(id=policy_id)], 'nat_order': None,
    #         'pbr_commands': [], 'nat_rule_commands': [],
    #         'main_rule_commands': [' ! -i lo     -j policy_id_{id}'.format(id=policy_id)],
    #         'create_chains': ['-N policy_id_{id}'.format(id=policy_id)], 'main_order': 2}
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    # def test_post_policy_multiple_services_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    ##------------------------------------------SNAT---------------------------------------------##

    def test_post_policy_snat_interfaceip_drop(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "SNAT",
                "snat_type": "interface_ip",
                "is_enabled": True
            },
            'source_destination': {
                'src_network_list': [1],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'drop',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_post_policy_snat_interfaceip_anytoany(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "SNAT",
                "snat_type": "interface_ip",
                "is_enabled": True
            },
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_post_policy_snat_interfaceip_with_srcinterface(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "SNAT",
                "snat_type": "interface_ip",
                "is_enabled": True
            },
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': ["ens18", "ens19"],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)

    # def test_post_policy_snat_staticip_with_ipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_snat_staticip_with_iprangeandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000-2500",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    def test_post_policy_snat_staticip_withip(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "SNAT",
                "snat_type": "static_ip",
                "ip": "30.20.20.20",
                "is_enabled": True
            },
            'source_destination': {
                'src_network_list': [1],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens18"]
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']
        nat_id = response.json()['nat']['id']

        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -j ACCEPT'.format(id=policy_id),
            'nat_id_{id} -j SNAT --to 30.20.20.20 -t nat'.format(id=nat_id)], 'nat_order': 2,
            'pbr_commands': [], 'nat_rule_commands': [
                ' -m set --set polset_{main_id}_src src  -o ens18   -j nat_id_{id}'.format(main_id=policy_id,
                                                                                           id=nat_id)],
            'main_rule_commands': [
                ' -m set --set polset_{id}_src src  -o ens18 -j policy_id_{id}'.format(id=policy_id)],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id), '-t nat -N nat_id_{id}'.format(id=nat_id)],
            'main_order': 1,
            'src_ip_list': ['10.10.10.1', '30.20.20.20']
        }

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    # def test_post_policy_snat_staticip_withouip_withport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_snat_staticip_withouipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_service_snat_interfaceip_withoutinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    def test_post_policy_service_snat_interfaceip_with_dstinterface(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "SNAT",
                "snat_type": "interface_ip",
                "is_enabled": True
            },
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [],
                'service_list': [3, 6],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens18", "ens19"]
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        policy_id = response.json()['id']
        nat_id = response.json()['nat']['id']

        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
        self.assertTrue(
            Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(name="ens18").exists())
        self.assertTrue(
            Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(name="ens19").exists())

        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -p tcp  -mmultiport --sport 8432  -mmultiport --dport 13243 -j ACCEPT'.format(id=policy_id),
            'policy_id_{id} -p tcp   -mmultiport --dport 1283 -j ACCEPT'.format(id=policy_id),
            'nat_id_{id}  -p tcp  -mmultiport --sport 8432  -mmultiport --dport 13243 -j MASQUERADE -t nat'.format(
                id=nat_id),
            'nat_id_{id}  -p tcp   -mmultiport --dport 1283 -j MASQUERADE -t nat'.format(
                id=nat_id)],
            'nat_order': 2, 'pbr_commands': [],
            'nat_rule_commands': [' -o ens18   -j nat_id_{id}'.format(id=nat_id),
                                  ' -o ens19 -j nat_id_{id}'.format(id=nat_id)],
            'main_rule_commands': [' -o ens18 -j policy_id_{id}'.format(id=policy_id),
                                   ' -o ens19 -j policy_id_{id}'.format(id=policy_id)],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id), '-t nat -N nat_id_{id}'.format(id=nat_id)],
            'main_order': 1}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    #
    # def test_post_policy_service_snat_staticip_with_ipandport_geoip(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "3000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_service_snat_staticip_withip_withoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_service_snat_staticip_withoutip_withport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_service_snat_staticip_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_multipleservices_schedule_snat_interfaceip_withoutinterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_snat_interfaceip_withinterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_snat_staticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "20.30.10.10",
    #             "port": "5005",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "20.30.10.10")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "5005")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_snat_staticip_withip_withoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "20.30.10.10",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "20.30.10.10")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_snat_staticip_withoutip_withport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2334",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2334")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_snat_staticip_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    ##------------------------------------------DNAT---------------------------------------------##
    def test_post_policy_multipleservices_dnat_schedule_withipandport(self):
        url = reverse('policy-list')
        data = {
            "nat": {
                "nat_type": "DNAT",
                "ip": "20.30.10.10",
                "port": "5005"
            },
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [1],
                'service_list': [3, 6, 7],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': []
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': 1
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)

        policy_id = response.json()['id']
        nat_id = response.json()['nat']['id']
        policy_expected_commands = {'chain_commands': [
            'policy_id_{id} -p tcp  -mmultiport --sport 8432  -mmultiport --dport 5005 -j ACCEPT'.format(id=policy_id),
            'policy_id_{id} -p tcp   -mmultiport --dport 5005 -j ACCEPT'.format(id=policy_id),
            'nat_id_{id} -p tcp  -mmultiport --sport 8432  -mmultiport --dport 13243 -j DNAT --to 20.30.10.10:5005 -t '
            'nat '.format(
                id=nat_id),
            'nat_id_{id} -p tcp   -mmultiport --dport 1283 -j DNAT --to 20.30.10.10:5005 -t nat '.format(id=nat_id)],
            'nat_order': 2, 'pbr_commands': [],
            'nat_rule_commands': [
                '! -i lo -m set --set polset_{main_id}_dst dst -mtime --datestart 2017-05-04T19:30:00 --datestop '
                '2017-08-05T19:29:59 '
                '--timestart 22:33:04 --timestop 06:33:04 --weekdays Saturday,Sunday,Monday,Thursday -j nat_id_{'
                'id}'.format(main_id=policy_id,
                             id=nat_id)],
            'main_rule_commands': [
                '! -i lo -d 20.30.10.10 -mtime --datestart 2017-05-04T19:30:00 --datestop '
                '2017-08-05T19:29:59 '
                '--timestart 22:33:04 --timestop 06:33:04 --weekdays Saturday,Sunday,Monday,Thursday -j policy_id_{'
                'id}'.format(
                    id=policy_id)],
            'dst_ip_list': ['10.10.10.1', '20.30.10.10'],
            'create_chains': ['-N policy_id_{id}'.format(id=policy_id), '-t nat -N nat_id_{id}'.format(id=nat_id)],
            'main_order': 1}

        self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id), policy_expected_commands))

    # def test_post_policy_multipleservices_schedule_dnat_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.10.10"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "20.30.10.10")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_dnat_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "port": "5005"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "5005")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleservices_schedule_dnat_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##################################PostPolicy with src network##################################################
    #
    # def test_post_policy_srcip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=1).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcmac(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [7],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=7).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcfqdn(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [10],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=10).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcips(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=2).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcmacs(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [8],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcfqdns(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [11],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworks(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [3],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=3).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservices(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [4, 5],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_snat_interfaceip_drop(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'drop',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_snat_interfaceip_withoutinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_snat_interfaceip_withinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_snat_staticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcnetworksipsfqdns_multipleservice_schedule_snat_staticip_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_snat_staticip_withouipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_snat_staticip_withouipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_dnat_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_dnat_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcnetworksipsmacsfqdns_multipleservice_schedule_dnat_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # #####################################PostPolicy with dst network###############################################
    # def test_post_policy_dstip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [1],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=1).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstmac(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [7],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_dstfqdn(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [10],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=10).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstips(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [2],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=2).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstmacs(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [8],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_dstfqdns(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [11],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dsnetworksips(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworksipsmacsfqdns(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 8, 11],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_dstmltiplenetworkip_multiplesservice(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstmultiplenetworkip_multipleservices(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [4, 5],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstmultiplenetworkip_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_dstnetworksipsMacsfqdns_multipleservice_schedule_snat_interfaceip_drop(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 8, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'drop',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_snat_interfaceip_withoutinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_snat_interfaceip_withinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     # print(response.content)
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_snat_staticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2006",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2006")
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_snat_staticip_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 8, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_dnat_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "2006"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2006")
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_dnat_withipwhitoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_dnat_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "port": "2006"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2006")
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstnetworks_multipleservice_schedule_dnat_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 3],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # #####################################PostPolicy with src geoip###############################################
    #
    # def test_post_policy_srcgeoip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     policy_id = response.json()['id']
    #     self.assertEqual(response.status_code, 201)
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #
    #     sleep(1)
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     policy_id = response.json()['id']
    #     self.assertEqual(response.status_code, 201)
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #
    #     sleep(1)
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     policy_id = response.json()['id']
    #     self.assertEqual(response.status_code, 201)
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     sleep(1)
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatinterfaceip_drop(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'drop',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatinterfaceip_withoutInterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatinterfaceip_withinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatstaticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatstaticip_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatstaticip_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_snatstaticip_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_dnat_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_dnat_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_dnat_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_srcgeoip_multipleservice_schedule_dnat_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # #####################################PostPolicy with dst geoip###############################################
    #
    # def test_post_policy_dstgeoip(self):
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstgeoip_multipleservice(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatinterfaceip_drop(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'drop',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatinterfaceip_withoutinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatinterfaceip_withinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatstaticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatstaticip_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatstaticip_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=4).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_snatstaticip_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_dnat_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_dnat_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_dnat_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_dstgeoip_multipleservice_schedule_dnat_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6, 4],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ################################PostPolicy with incoming interface#######################################
    #
    # def test_post_policy_incominginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipleservice(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_snatinterfaceip_drop(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'drop',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_snatinterfaceip_withinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_snatstaticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_dnat_withipandport(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_dnat_withipwithoutport(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_dnat_withoutipwithport(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipleservice_schedule_dnat_withoutipandport(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ################################PostPolicy with outgoing interface#######################################
    #
    # def test_post_policy_outgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_snatinterfaceip_drop(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'drop',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_snatinterfaceip_withoutinterface(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_snatstaticip_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_snatstaticip_withipwithoutport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_snatstaticip_withoutipwithport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "port": "2000",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_snatstaticip_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "is_enabled": True
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_dnat_withipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multipleoutgoinginterface_multipleservice_schedule_dnat_withoutipandport(self):
    #     url = reverse('policy-list')
    #     data = {
    #         "nat": {
    #             "nat_type": "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with src network, geoip and interface##############################
    #
    # def test_post_policy_srcnetwork_srcgeoip_incominginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule_snat_staticip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule_dnat_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     sleep(5)
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule_dnat_withipwihtoutport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     sleep(5)
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule_dnat_withoutipwithport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     sleep(5)
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleservice_schedule_dnat_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     sleep(5)
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with dst network, geoip and interface##############################
    #
    # def test_post_policy_dstnetwork_dstgeoip_outgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000-2500")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withipwithoutport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withoutipwithport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000-2500")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [5, 11],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with src network, geoip and interface and dst geoip##############################
    #
    # def test_post_policy_srcnetwork_srcgeoip_incominginterface_dstgeoip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["AF"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipledstgeoip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 8, 11],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["NI", "CH"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=8).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["NI", "CH"])
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipledstgeoip_multipleservice_schedule(
    #         self):
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["CH", "NI"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["CH", "NI"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipledstgeoip_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["CH", "NI"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipledstgeoip_multipleservice_schedule_snat_staticip(
    #         self):
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["CH", "NI"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipledstgeoip_multipleservice_schedule_dnat_withipandport(
    #         self):
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["CH", "NI"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipledstgeoip_multipleservice_schedule_dnat_withoutipandport(
    #         self):
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["CH", "NI"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with src network, geoip and interface and dst interface##############################
    #
    # def test_post_policy_srcnetwork_srcgeoip_incominginterface_outgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface_multipleservice_schedule(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface_multipleservice_schedule_dnat_staticip_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multiplesrcgeoip_multipleincominginterface_multipleoutgoinginterface_multipleservice_schedule_dnat_staticip_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with dst network, geoip and interface and src network##############################
    #
    # def test_post_policy_srcnetwork_dstnetwork_dstgeoip_outgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5],
    #             'dst_network_list': [11],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withipwithoutport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcnetwork_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with dst network, geoip and interface and src geoip##############################
    #
    # def test_post_policy_srcgeoip_dstnetwork_dstgeoip_outgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [11],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["AF"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["MA"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["MA"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["MA"],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["MA"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["MA"],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["MA"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["MA"],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["MA"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "2000-2500")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["MA"],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat_withipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'ip': "30.20.20.20",
    #             'port': "2000-2500"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["MA"],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesrcgeoip_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat_withoutipandport(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["MA"],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##############################PostPolicy with dst network, geoip and interface and src interface##############################
    #
    # def test_post_policy_incominginterface_dstnetwork_dstgeoip_outgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [11],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["AF"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["MA", "IR"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["MA", "IR"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multipleincominginterface_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.service_list.filter(id=6).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).schedule.name, "sch")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multipleincominginterface_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_interfaceip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multipleincominginterface_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_snat_staticip(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multipleincominginterface_multipledstnetwork_multipledstgeoip_multipleoutgoinginterface_multipleservice_schedule_dnat(
    #         self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["IR", "AF"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [1, 2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ####################PostPolicy with src network, geoip and interface and dst network, geoip and interface##############################
    #
    # def test_post_policy_allsources_alldestinations(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5],
    #             'dst_network_list': [11],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["AF"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesources_multipledestinations(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["UA", "NI"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["UA", "NI"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_post_policy_multiplesources_multipledestinations_multipleservice_schedule(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["UA", "AR"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     sleep(1)
    #     policy_id = response.json()['id']
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=11).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.src_geoip_country_list, ["IR", "AF"])
    #     self.assertEqual(Policy.objects.get(id=policy_id).source_destination.dst_geoip_country_list, ["UA", "AR"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##------------------------------------------SNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesources_multipledestinations_multipleservice_schedule_snat_interfaceip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "interface_ip"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["UA", "AR"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # def test_post_policy_multiplesources_multipledestinations_multipleservice_schedule_snat_staticip(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "SNAT",
    #             'snat_type': "static_ip",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["UA", "AR"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##------------------------------------------DNAT---------------------------------------------##
    #
    # def test_post_policy_multiplesources_multipledestinations_multipleservice_schedule_dnat(self):
    #     # apps.get_app_config('config_app').ready()
    #     url = reverse('policy-list')
    #     data = {
    #         'nat': {
    #             'nat_type': "DNAT",
    #             'port': "2000"
    #         },
    #         'source_destination': {
    #             'src_network_list': [5, 11],
    #             'dst_network_list': [3, 5],
    #             'service_list': [3, 6],
    #             'src_geoip_country_list': ["IR", "AF"],
    #             'dst_geoip_country_list': ["UA", "AR"],
    #             'src_interface_list': [1, 2],
    #             'dst_interface_list': [2]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #
    # ##########################################delete policy#################################################################
    #
    # def test_delete_policy(self):
    #     policy = add_test_policy()
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #
    # def test_delete_policy_snat_interfaceip(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # def test_delete_policy_snat_statcip(self):
    #     policy = add_test_policy_with_snat_staticIp(action='accept')
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # def test_delete_policy_dnat(self):
    #     policy = add_test_policy_with_dnat(action='accept')
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     policy_id = policy.id
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # #################################updatePolicy#######################################################
    #
    # def test_update_policy_srcnetwork(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.all())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.all())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.all())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.all())
    #
    #     # iptables_content = str(subprocess.check_output('iptables -S ', shell=True))
    #     # srcList = Policy.objects.get(id=policy.id).source_destination.src_network_list.all()[0].value_list
    #     # for src in srcList:
    #     #     regex = "(\S*\s)*-s\s*" + str(src) + "(\s*\S*)*policy_id_" + str(policy_id)
    #     #     self.assertRegex(iptables_content, regex)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_source_destination(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': ["IR"],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertEqual(Policy.objects.get(id=policy.id).source_destination.src_geoip_country_list, ["IR"])
    #     self.assertEqual(Policy.objects.get(id=policy.id).source_destination.dst_geoip_country_list, ["AF"])
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_source_destination_drop(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'drop',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'drop')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_fill_source_dest(self):
    #     policy = add_test_policy_only_service(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [5],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_only_services(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1, 5],
    #             'dst_network_list': [3],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [2, 1]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_disable_policy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'drop',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': False,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy_id).action, 'drop')
    #     self.assertFalse(Policy.objects.get(id=policy.id).is_enabled)
    #
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = response.json()['id']
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #
    # def test_update_policy_source_destination_drop_schedule(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'drop',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'drop')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertEqual(Policy.objects.get(id=policy.id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_disable_policy_schedule(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'drop',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': False,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy_id).action, 'drop')
    #     self.assertFalse(Policy.objects.get(id=policy.id).is_enabled)
    #
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = response.json()['id']
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #
    # def test_update_policy_source_destination_enabling(self):
    #     policy = add_test_policy_disable(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'drop',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'drop')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy.id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_source_destination_change_schedule(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertEqual(Policy.objects.get(id=policy.id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_source_destination_enable_log(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2, 1],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_log_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy.id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_source_destination_disable_log(self):
    #     policy = add_test_policy_log(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2, 1],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).is_log_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy.id).schedule.name, "sch")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_source_destination_disable_policy_enable_log(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2, 1],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': False,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_log_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy.id).is_enabled)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     policy_id = response.json()['id']
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #
    # def test_update_policy_source_destination_ipsec(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': True,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_ipsec)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_enable_everything(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [2],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'order': 1,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': True,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_ipsec)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # #################################updatePolicy with NAT#######################################################
    #
    # ##----------------------------------policies that didn't have NAT already----------------------------------##
    #
    # ##----SNAT----##
    #
    # def test_update_policy_add_snatinterfaceip_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "interface_ip")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_snatstaticip_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": "3000",
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "3000")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_snatstaticip_withoutport_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "30.20.20.20",
    #             "port": None
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.ip, "30.20.20.20")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_snatstaticip_withoutip_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": None,
    #             "port": "6000"
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "SNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.snat_type, "static_ip")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "6000")
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_snatstaticip_withoutportandip_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": None,
    #             "port": None
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_add_snatinterfaceip_withsrcinterface_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).nat)
    #
    # def test_update_policy_add_snatstaticip_withsrcinterface_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "50.20.30.10",
    #             "port": "2020",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).nat)
    #
    # ##----DNAT----##
    #
    # def test_update_policy_add_dnat_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [5],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": "3000",
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_dnat_withoutport_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "30.20.20.20",
    #             "port": None,
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_dnat_withoutip_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": None,
    #             "port": "5002"
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_add_dnat_withoutportandip_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": None,
    #             "port": None,
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).nat)
    #
    # def test_update_policy_add_dnat_withdstinterface_for_alreadywithoutnatpolicy(self):
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "50.20.30.10",
    #             "port": "2020",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).nat)
    #
    # def test_update_policy_update_dnat_withdstgeoip_for_alreadywithoutnatpolicy(self):  # it shoul raise error
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_update_dnat_withoutservicelist_for_alreadywithoutnatpolicy(self):  # it shoul raise error
    #     policy = add_test_policy(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_update_dnat_withdstgeoipwhitoutservicelist_for_alreadywithoutnatpolicy(
    #         self):  # it shoul raise error
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # ##----------------------------------policies that had NAT already----------------------------------##
    #
    # ##----SNAT----##
    #
    # def test_update_policy_delete_snatinterfaceip_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy_id).nat)
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # def test_update_policy_update_snatinterfaceip_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_snatstaticip_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_staticIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_snatstaticip_withoutip_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_staticIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": None,
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.is_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy_id).nat.ip)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_snatstaticip_withoutport_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_staticIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": "20.10.20.2",
    #             "port": None,
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.is_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy_id).nat.port)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_snatstaticip_withoutportandip_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_staticIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "static_ip",
    #             "ip": None,
    #             "port": None,
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_snatinterfaceip_withsrcinterface_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_disable_snatinterfaceip_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': False,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_log_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy.id).is_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy.id).nat)
    #
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_id), iptables_content)
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # def test_update_policy_enable_snatinterfaceip_for_alreadywithsnatpolicy(self):
    #     policy = add_test_policy_disable(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "SNAT",
    #             "snat_type": "interface_ip",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # ##----DNAT----##
    #
    # def test_update_policy_delete_dnat_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_dnat(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy_id).nat)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # def test_update_policy_update_dnat_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [1],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy.id).nat.is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy.id).nat.nat_type, "DNAT")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_dnat_withoutip_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": None,
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).nat.is_enabled)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_dnat_withoutport_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "10.20.30.10",
    #             "port": None
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy.id).is_enabled)
    #     sleep(1)
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_dnat_withoutportandip_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": None,
    #             "port": None,
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_update_dnat_for_withdstinterface_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': [5]
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_disable_dnat_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500"
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': False,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertFalse(Policy.objects.get(id=policy_id).is_enabled)
    #
    #     iptables_content = str(subprocess.check_output('iptables -S ', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy.id), iptables_content)
    #     iptables_content = str(subprocess.check_output('iptables -S -t nat', shell=True))
    #     self.assertNotIn('nat_id_{}'.format(policy.nat.id), iptables_content)
    #
    # def test_update_policy_enable_dnat_for_alreadywithnatpolicy(self):
    #     policy = add_test_policy_disable(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     policy_id = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 200)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_log_enabled)
    #     self.assertTrue(Policy.objects.get(id=policy_id).is_enabled)
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.nat_type, "DNAT")
    #     self.assertEqual(Policy.objects.get(id=policy_id).nat.port, "4500")
    #
    #     self.assertTrue(self.checkPolicy(Policy.objects.get(id=policy_id)))
    #
    # def test_update_policy_update_dnat_withdstgeoip_for_alreadywithnatpolicy(self):  # it shoul raise error
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [3],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_update_dnat_withoutservicelist_for_alreadywithnatpolicy(self):  # it shoul raise error
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500"
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # def test_update_policy_update_dnat_withdstgeoipwhitoutservicelist_for_alreadywithnatpolicy(
    #         self):  # it shoul raise error
    #     policy = add_test_policy_with_snat_interfaceIp(action='accept')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [2],
    #             'dst_network_list': [1],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': ["AF"],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         "nat": {
    #             "nat_type": "DNAT",
    #             "ip": "20.30.50.10",
    #             "port": "4500",
    #             "is_enabled": True
    #         },
    #         'action': 'accept',
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': True,
    #         'is_ipsec': False,
    #         'schedule': 1
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy.id})
    #     response = self.client.put(url, data, format='json')
    #     sleep(1)
    #     self.assertEqual(response.status_code, 400)
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertEqual(Policy.objects.get(id=policy.id).action, 'accept')
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.src_network_list.filter(id=5).exists())
    #     self.assertFalse(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_network_list.filter(id=3).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=1).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.dst_interface_list.filter(id=2).exists())
    #     self.assertTrue(Policy.objects.get(id=policy.id).source_destination.service_list.filter(id=5).exists())
    #
    # ###########################################order policy (post)##############################################################
    #
    # def test_next_policy_addaboveformerpolicy(self):
    #     policy = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [1],
    #             'service_list': [1],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy.id,
    #         'name': 'pol2',
    #         'description': 'pol2',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     newPolicyId = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 201)
    #     self.assertEqual(Policy.objects.get(id=policy.id).next_policy, None)
    #     self.assertEqual(Policy.objects.get(id=newPolicyId).next_policy.id, policy.id)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy.id)):
    #                 order[policy.id] = result.group(1)
    #             elif (result.group(2) == str(newPolicyId)):
    #                 order[newPolicyId] = result.group(1)
    #     self.assertTrue(int(order[policy.id]) > int(order[newPolicyId]))
    #
    # def test_next_policy_NoneNextPolicy(self):
    #     policy = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [1],
    #             'service_list': [1],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': None,
    #         'name': 'pol2',
    #         'description': 'pol2',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     newPolicyId = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 201)
    #     self.assertEqual(Policy.objects.get(id=policy.id).next_policy.id, newPolicyId)
    #     self.assertEqual(Policy.objects.get(id=newPolicyId).next_policy, None)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy.id)):
    #                 order[policy.id] = result.group(1)
    #             elif (result.group(2) == str(newPolicyId)):
    #                 order[newPolicyId] = result.group(1)
    #     self.assertTrue(int(order[policy.id]) < int(order[newPolicyId]))
    #
    # def test_next_policy_wrongnextpolicy(self):
    #     policy = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [],
    #             'dst_network_list': [1],
    #             'service_list': [1],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': 4506,
    #         'name': 'pol2',
    #         'description': 'pol2',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 400)
    #
    # def test_next_policy_addbellowmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': None,
    #         'name': 'pol3',
    #         'description': 'pol3',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     # url = reverse('policy-detail', kwargs={'pk': policy_1.id})
    #     # response = self.client.put(url, data, format='json')
    #     response = self.client.post(url, data, format='json')
    #     newPolicyId = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(response.status_code, 201)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy.id, newPolicyId)
    #     self.assertEqual(Policy.objects.get(id=newPolicyId).next_policy, None)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(newPolicyId)):
    #                 order[newPolicyId] = result.group(1)
    #     self.assertTrue(int(order[policy_1.id]) < int(policy_2.id))
    #     self.assertTrue(int(order[policy_2.id]) < int(order[newPolicyId]))
    #
    # def test_next_policy_addabovemultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy_1.id,
    #         'name': 'pol3',
    #         'description': 'pol3',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     newPolicyId = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=newPolicyId).next_policy.id, policy_1.id)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_2.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy, None)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(newPolicyId)):
    #                 order[newPolicyId] = result.group(1)
    #     self.assertTrue(int(order[newPolicyId]) < int(policy_1.id))
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_2.id]))
    #
    # def test_next_policy_addinmiddleofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     url = reverse('policy-list')
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy_2.id,
    #         'name': 'pol3',
    #         'description': 'pol3',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #
    #     response = self.client.post(url, data, format='json')
    #     self.assertEqual(response.status_code, 201)
    #     newPolicyId = response.json()['id']
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=newPolicyId).next_policy.id, policy_2.id)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, newPolicyId)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy, None)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(newPolicyId)):
    #                 order[newPolicyId] = result.group(1)
    #     self.assertTrue(int(order[policy_1.id]) < int(newPolicyId))
    #     self.assertTrue(int(order[newPolicyId]) < int(order[policy_2.id]))
    #
    # #################################update order (put)################################################
    #
    # def test_next_policy_putthelowerpolicyaboveofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy_for_policy_order(action='accept', name='pol3')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy_1.id,
    #         'name': 'pol3',
    #         'description': 'pol3',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy_3.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 200)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy.id, policy_1.id)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_2.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy, None)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_3.id]) < int(order[policy_1.id]))
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_2.id]))
    #
    # def test_next_policy_putthelowerpolicyinmiddleofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy_for_policy_order(action='accept', name='pol3')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy_2.id,
    #         'name': 'pol3',
    #         'description': 'pol3',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy_3.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 200)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_3.id)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy.id, policy_2.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy, None)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_3.id]))
    #     self.assertTrue(int(order[policy_3.id]) < int(order[policy_2.id]))
    #
    # def test_next_policy_putthemiddlepolicyaboveofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy_for_policy_order(action='accept', name='pol3')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy_1.id,
    #         'name': 'pol2',
    #         'description': 'pol2',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy_2.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 200)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy, None)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_3.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy.id, policy_1.id)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_2.id]) < int(order[policy_1.id]))
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_3.id]))
    #
    # def test_next_policy_putthemiddlepolicybellowofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy_for_policy_order(action='accept', name='pol3')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': None,
    #         'name': 'pol2',
    #         'description': 'pol2',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy_2.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 200)
    #     sleep(1)
    #
    #     # print(Policy.objects.get(id=policy_1.id).next_policy.id)
    #     # print(Policy.objects.get(id=policy_3.id).next_policy.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy, None)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_3.id)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy.id, policy_2.id)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_3.id]))
    #     self.assertTrue(int(order[policy_3.id]) < int(order[policy_2.id]))
    #
    # def test_next_policy_putthefirstpolicyinmiddleofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy_for_policy_order(action='accept', name='pol3')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': policy_3.id,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy_1.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 200)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy, None)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_3.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy.id, policy_1.id)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_2.id]) < int(order[policy_1.id]))
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_3.id]))
    #
    # def test_next_policy_putthefirstpolicybellowofmultiplepolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy_for_policy_order(action='accept')
    #     sleep(1)
    #     policy_2 = add_test_policy_for_policy_order(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy_for_policy_order(action='accept', name='pol3')
    #     sleep(1)
    #     data = {
    #         'source_destination': {
    #             'src_network_list': [1],
    #             'dst_network_list': [],
    #             'service_list': [],
    #             'src_geoip_country_list': [],
    #             'dst_geoip_country_list': [],
    #             'src_interface_list': [],
    #             'dst_interface_list': []
    #         },
    #         'action': 'accept',
    #         'next_policy': None,
    #         'name': 'pol1',
    #         'description': 'pol1',
    #         'is_enabled': True,
    #         'is_log_enabled': False,
    #         'is_ipsec': False,
    #         'schedule': None
    #     }
    #     url = reverse('policy-detail', kwargs={'pk': policy_1.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, 200)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy, None)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy.id, policy_1.id)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy.id, policy_3.id)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_2.id)):
    #                 order[policy_2.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_2.id]) < int(order[policy_3.id]))
    #     self.assertTrue(int(order[policy_3.id]) < int(order[policy_1.id]))
    #
    # ##################################delete order (delete)#######################################################
    #
    # def test_next_policy_delete_allpolicies(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy(action='accept', name='pol1')
    #     sleep(1)
    #     policy_2 = add_test_policy(action='accept', name='pol2')
    #     sleep(1)
    #
    #     url = reverse('policy-detail', kwargs={'pk': policy_2.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.filter(id=policy_2.id).count(), 0)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy, None)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_2.id), iptables_content)
    #
    #     url = reverse('policy-detail', kwargs={'pk': policy_1.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.filter(id=policy_1.id).count(), 0)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_1.id), iptables_content)
    #
    # def test_next_policy_delete_middlepolicy(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy(action='accept', name='pol1')
    #     sleep(1)
    #     policy_2 = add_test_policy(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy(action='accept', name='pol3')
    #     sleep(1)
    #
    #     url = reverse('policy-detail', kwargs={'pk': policy_2.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.filter(id=policy_2.id).count(), 0)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy.id, policy_3.id)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy, None)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_2.id), iptables_content)
    #
    #     iptables_content = str(subprocess.check_output('iptables -nvL FORWARD --line-number', shell=True))
    #     order = {}
    #     regex = "(\d+)\s+\d+\s+\d+\s+policy_id_(\d+)"
    #     for line in iptables_content.split('\\n'):
    #         result = re.search(regex, line, re.M)
    #         if result:
    #             if (result.group(2) == str(policy_1.id)):
    #                 order[policy_1.id] = result.group(1)
    #             elif (result.group(2) == str(policy_3.id)):
    #                 order[policy_3.id] = result.group(1)
    #     self.assertTrue(int(order[policy_1.id]) < int(order[policy_3.id]))
    #
    # def test_next_policy_delete_firstandlastpolicy(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy(action='accept', name='pol1')
    #     sleep(1)
    #     policy_2 = add_test_policy(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy(action='accept', name='pol3')
    #     sleep(1)
    #
    #     url = reverse('policy-detail', kwargs={'pk': policy_1.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy_3.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.filter(id=policy_1.id).count(), 0)
    #     self.assertEqual(Policy.objects.filter(id=policy_3.id).count(), 0)
    #     self.assertEqual(Policy.objects.get(id=policy_2.id).next_policy, None)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_1.id), iptables_content)
    #     self.assertNotIn('policy_id_{}'.format(policy_3.id), iptables_content)
    #     self.assertIn('policy_id_{}'.format(policy_2.id), iptables_content)
    #
    # def test_next_policy_delete_firstandsecondpolicy(self):
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy(action='accept', name='pol1')
    #     sleep(1)
    #     policy_2 = add_test_policy(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy(action='accept', name='pol3')
    #     sleep(1)
    #
    #     url = reverse('policy-detail', kwargs={'pk': policy_1.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy_2.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.filter(id=policy_1.id).count(), 0)
    #     self.assertEqual(Policy.objects.filter(id=policy_2.id).count(), 0)
    #     self.assertEqual(Policy.objects.get(id=policy_3.id).next_policy, None)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_1.id), iptables_content)
    #     self.assertNotIn('policy_id_{}'.format(policy_2.id), iptables_content)
    #     self.assertIn('policy_id_{}'.format(policy_3.id), iptables_content)
    #
    # def test_next_policy_delete_firstandsecondpolicy(self):
    #     # url = reverse('policy-list')
    #     # data = {
    #     #     "nat": {
    #     #         "nat_type": "DNAT"
    #     #     },
    #     #     'source_destination': {
    #     #         'src_network_list': [5,8,11],
    #     #         'dst_network_list': [],
    #     #         'service_list': [3,6],
    #     #         'src_geoip_country_list': [],
    #     #         'dst_geoip_country_list': [],
    #     #         'src_interface_list': [],
    #     #         'dst_interface_list': []
    #     #     },
    #     #     'action': 'accept',
    #     #     'name': 'pol1',
    #     #     'description': 'pol1',
    #     #     'is_enabled': True,
    #     #     'is_log_enabled': False,
    #     #     'is_ipsec': False,
    #     #     'schedule': 1
    #     # }
    #     # response = self.client.post(url, data, format='json')
    #     # self.assertEqual(response.status_code, 400)
    #     # sleep(1)
    #     # apps.get_app_config('config_app').ready()
    #     policy_1 = add_test_policy(action='accept', name='pol1')
    #     sleep(1)
    #     policy_2 = add_test_policy(action='accept', name='pol2')
    #     sleep(1)
    #     policy_3 = add_test_policy(action='accept', name='pol3')
    #     sleep(1)
    #
    #     url = reverse('policy-detail', kwargs={'pk': policy_2.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     url = reverse('policy-detail', kwargs={'pk': policy_3.id})
    #     response = self.client.delete(url, format='json')
    #     self.assertEqual(response.status_code, 204)
    #     sleep(1)
    #     self.assertEqual(Policy.objects.filter(id=policy_3.id).count(), 0)
    #     self.assertEqual(Policy.objects.filter(id=policy_2.id).count(), 0)
    #     self.assertEqual(Policy.objects.get(id=policy_1.id).next_policy, None)
    #     sleep(1)
    #     iptables_content = str(subprocess.check_output('iptables -S', shell=True))
    #     self.assertNotIn('policy_id_{}'.format(policy_3.id), iptables_content)
    #     self.assertNotIn('policy_id_{}'.format(policy_2.id), iptables_content)
    #     self.assertIn('policy_id_{}'.format(policy_1.id), iptables_content)





def check_file_content(file, content):
    status, file_content = sudo_file_reader(file)
    if status:
        if content not in file_content:
            return False
        return True


class QOSTest(CustomAPITestCase):
    fixtures = ['config_app/fixtures/test_config.json', 'entity_app/fixtures/test_entity.json', 'test_data.json']

    def setUp(self):
        subprocess.run('mkdir -p {}/  > /dev/null 2>&1'.format(TEST_PATH), shell=True, stderr=subprocess.STDOUT,
                       universal_newlines=True)
        subprocess.run('touch {}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), shell=True, stderr=subprocess.STDOUT,
                       universal_newlines=True)

    def tearDown(self):
        import os
        Interface.objects.all().delete()
        cmd = 'rm -rf {}/'.format(TEST_PATH)
        os.system(cmd)

    def test_post_qos_policy_src(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [1],
                'dst_network_list': [],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens80"]
            },
            'qos':{
                'download_guaranteed_bw':2500,
                'download_max_bw':3500,
                'traffic_priority':'low',
                'shape_type':'per_session'
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        class_id = response.json()['qos']['class_id']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}' \
                                           .format(dev=DOWNLOAD_IFB, id=class_id,
                                                   rate=data['qos']['download_guaranteed_bw'],
                                                   ceil=data['qos']['download_max_bw'], priority='3')))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc qdisc add dev {interface} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
                                               interface=DOWNLOAD_IFB, id=class_id)))

        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src 0.0.0.0/0 match ip dst any match mark 81 0xffff flowid 1:{class_id}' \
                                           .format(interface=DOWNLOAD_IFB, class_id=class_id)))

        policy_id = response.json()['id']
        self.assertTrue(Policy.objects.get(id=policy_id).source_destination.src_network_list.filter(id=1).exists())


    def test_post_qos_policy_dst(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [],
                'dst_network_list': [2],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens80"]
            },
            'qos':{
                'download_guaranteed_bw':2500,
                'download_max_bw':3500,
                'traffic_priority':'low',
                'shape_type':'per_session'
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        class_id = response.json()['qos']['class_id']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}' \
                                           .format(dev=DOWNLOAD_IFB, id=class_id,
                                                   rate=data['qos']['download_guaranteed_bw'],
                                                   ceil=data['qos']['download_max_bw'], priority='3')))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc qdisc add dev {interface} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
                                               interface=DOWNLOAD_IFB, id=class_id)))

        # self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
        #                                    'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src any match ip dst 3.6.6.6 match mark 81 0xffff flowid 1:{class_id}' \
        #                                    .format(interface=DOWNLOAD_IFB, class_id=class_id)))
        # self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
        #                                    'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src any match ip dst 44.55.66.33 match mark 81 0xffff flowid 1:{class_id}' \
        #                                    .format(interface=DOWNLOAD_IFB, class_id=class_id)))


    def test_post_qos_policy_src_dst(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [3],
                'dst_network_list': [2],
                'service_list': [],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens80"]
            },
            'qos':{
                'download_guaranteed_bw':2500,
                'download_max_bw':3500,
                'traffic_priority':'low',
                'shape_type':'per_ip'
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        class_id = response.json()['qos']['class_id']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}' \
                                           .format(dev=DOWNLOAD_IFB, id=class_id,
                                                   rate=data['qos']['download_guaranteed_bw'],
                                                   ceil=data['qos']['download_max_bw'], priority='3')))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc qdisc add dev {interface} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
                                               interface=DOWNLOAD_IFB, id=class_id)))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc filter add dev {interface} parent {id}: handle {id} flow hash keys dst divisor 1024' \
                                           .format(interface=DOWNLOAD_IFB, id=class_id)))
        # self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
        #                                    'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src 2.6.2.6 match ip dst 3.6.6.6 match mark 81 0xffff flowid 1:{class_id}' \
        #                                    .format(interface=DOWNLOAD_IFB, class_id=class_id)))
        # self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
        #                                    'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src 2.6.2.6 match ip dst 44.55.66.33 match mark 81 0xffff flowid 1:{class_id}' \
        #                                    .format(interface=DOWNLOAD_IFB, class_id=class_id)))

    def test_post_qos_policy_service(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [3],
                'dst_network_list': [2],
                'service_list': [6],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens80"]
            },
            'qos':{
                'download_guaranteed_bw':2500,
                'download_max_bw':3500,
                'traffic_priority':'low',
                'shape_type':'per_ip'
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        class_id = response.json()['qos']['class_id']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}' \
                                           .format(dev=DOWNLOAD_IFB, id=class_id,
                                                   rate=data['qos']['download_guaranteed_bw'],
                                                   ceil=data['qos']['download_max_bw'], priority='3')))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc qdisc add dev {interface} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
                                               interface=DOWNLOAD_IFB, id=class_id)))
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
                                           'tc filter add dev {interface} parent {id}: handle {id} flow hash keys dst divisor 1024' \
                                           .format(interface=DOWNLOAD_IFB, id=class_id)))
        # self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
        #                                    'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src 2.6.2.6 match ip dst 3.6.6.6 match ip protocol 6 0xff match ip dport 1283 0xffff match mark 81 0xffff flowid 1:{class_id}' \
        #                                    .format(interface=DOWNLOAD_IFB, class_id=class_id)))
        # self.assertTrue(check_file_content(TEST_COMMANDS_FILE,
        #                                    'tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip src 2.6.2.6 match ip dst 44.55.66.33 match ip protocol 6 0xff match ip dport 1283 0xffff match mark 81 0xffff flowid 1:{class_id}' \
        #                                    .format(interface=DOWNLOAD_IFB, class_id=class_id)))


    def test_delete_qos_policy(self):
        url = reverse('policy-list')
        data = {
            'source_destination': {
                'src_network_list': [3],
                'dst_network_list': [2],
                'service_list': [6],
                'src_geoip_country_list': [],
                'dst_geoip_country_list': [],
                'src_interface_list': [],
                'dst_interface_list': ["ens80"]
            },
            'qos': {
                'download_guaranteed_bw': 2500,
                'download_max_bw': 3500,
                'traffic_priority': 'low',
                'shape_type': 'per_ip'
            },
            'action': 'accept',
            'name': 'pol1',
            'description': 'pol1',
            'is_enabled': True,
            'is_log_enabled': False,
            'is_ipsec': False,
            'schedule': None
        }
        response = self.client.post(url, data, format='json')
        import json
        json_acceptable_string = response.content.decode('utf-8').replace("'", "\"")
        pol_id = (json.loads(json_acceptable_string)).get('id')
        class_id = (json.loads(json_acceptable_string)).get('qos').get('class_id')
        sleep(1)
        url = reverse('policy-detail', kwargs={'pk': pol_id})
        response = self.client.delete(url, format='json')
        self.assertEqual(response.status_code, 204)
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class del dev {} parent 1:1 classid 1:'.format(DOWNLOAD_IFB)))

    def test_config_interface_bandwidth(self):
        url = reverse('interface-detail', kwargs={'pk': Interface.objects.get(name="ens19")})
        data = {
            "type": "WAN",
            "download_bandwidth": 10000,
            "upload_bandwidth": 2000
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        interface_name = response.json()['name']
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'ip link set dev {} up'.format(DOWNLOAD_IFB)))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'ifconfig {} up'.format(DOWNLOAD_IFB)))
        #
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc qdisc add dev {dev} root handle 1:0 htb default {id}'
        #                                    .format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID)))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class add dev {dev} parent 1:0 classid 1:1 htb rate {download_bw}kbps ceil {download_bw}kbps'
        #                                    .format(dev=DOWNLOAD_IFB, download_bw=data['download_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'iptables -t mangle -C FORWARD -i {dev} -j MARK --set-mark {mark}'
        #                                    .format(dev=interface_name, mark=interface_id)))
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {download_bw}kbps ceil {download_bw}kbps'
        #                                    .format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID, download_bw=data['download_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc qdisc add dev {dev} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'
        #                                    .format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID)))
        #
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc qdisc add dev {dev} root handle 1:0 htb default {id}'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID)))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class add dev {dev} parent 1:0 classid 1:1 htb rate {upload_bw}kbps ceil {upload_bw}kbps'
        #                                    .format(dev=interface_name, upload_bw=data['upload_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {upload_bw}kbps ceil {upload_bw}kbps'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID, upload_bw=data['upload_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc qdisc add dev {dev} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID)))


    def test_update_config_interface_bandwidth(self):
        url = reverse('interface-detail', kwargs={'pk': Interface.objects.get(name="ens80")})
        data = {
            "type": "WAN",
            "download_bandwidth": 50000,
            "upload_bandwidth": 3000
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        interface_name = response.json()['name']
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc class change dev {dev} parent 1:0 classid 1:1 htb rate {bw}kbps ceil {bw}kbps'
        #                                    .format(dev=DOWNLOAD_IFB, bw=data['download_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class change dev {dev} parent 1:1 classid 1:{id} htb rate {bw}kbps ceil {bw}kbps prio 7'
        #                                    .format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID,bw=data['download_bandwidth'])))
        #
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class change dev {dev} parent 1:0 classid 1:1 htb rate {bw}kbps ceil {bw}kbps'
        #                                    .format(dev=interface_name, bw=data['upload_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class change dev {dev} parent 1:1 classid 1:{id} htb rate {bw}kbps ceil {bw}kbps prio 7'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID,
        #                                            bw=data['upload_bandwidth'])))

    def test_clear_config_interface_bandwidth(self):
        url = reverse('interface-detail', kwargs={'pk': Interface.objects.get(name="ens80")})
        data = {
            "type": "WAN",
            "download_bandwidth": None,
            "upload_bandwidth": None
        }
        response = self.client.patch(url, data, format='json')
        interface_name = response.json()['name']
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc qdisc del dev {} root'.format(DOWNLOAD_IFB)))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'iptables -t mangle -D FORWARD -i {dev} -j MARK --set-mark {mark}'
        #                                    .format(dev=interface_name, mark=interface_id)))
        #
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc qdisc del dev {} root'.format(interface_name)))

    def test_config_another_interface_bandwidth(self):
        url = reverse('interface-detail', kwargs={'pk': Interface.objects.get(name="ens19")})
        data1 = {
            "type": "WAN",
            "download_bandwidth": 10000,
            "upload_bandwidth": 2000
        }
        response = self.client.patch(url, data1, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        url = reverse('interface-detail', kwargs={'pk': Interface.objects.get(name="ens20")})
        data2 = {
            "type": "WAN",
            "download_bandwidth": 30000,
            "upload_bandwidth": 4000
        }
        response = self.client.patch(url, data2, format='json')
        interface_name = response.json()['name']
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc qdisc add dev {dev} root handle 1:0 htb default {id}'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID)))
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc class add dev {dev} parent 1:0 classid 1:1 htb rate {upload_bw}kbps ceil {upload_bw}kbps'
        #                                    .format(dev=interface_name, upload_bw=data2['upload_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {upload_bw}kbps ceil {upload_bw}kbps'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID,
        #                                            upload_bw=data2['upload_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH,
        #                                    'tc qdisc add dev {dev} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'
        #                                    .format(dev=interface_name, id=DEFAULT_CLASS_ID)))
        #
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class change dev {dev} parent 1:0 classid 1:1 htb rate {bw}kbps ceil {bw}kbps'
        #                                    .format(dev=DOWNLOAD_IFB, bw=data1['download_bandwidth']+data2['download_bandwidth'])))
        # # self.assertTrue(check_file_content(COMMANDS_PATH, 'tc class change dev {dev} parent 1:0 classid 1:{id} htb rate{bw}kbps ceil {bw}kbps'
        # #                                    .format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID, bw=data1['download_bandwidth']+data2['download_bandwidth'])))
        # self.assertTrue(check_file_content(COMMANDS_PATH, 'iptables -t mangle -A FORWARD -t mangle -i {dev} -j MARK --set-mark {mark}'
        #                                    .format(dev=interface_name, mark=interface_id)))