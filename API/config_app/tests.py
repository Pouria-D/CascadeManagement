import os
import os
import re
from time import sleep

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from api.settings import TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD
from brand import BRAND
from config_app.models import NTPConfig, LogServer, Update, Interface, UpdateConfig, DNSConfig, \
    HighAvailability, Setting
from config_app.utils import TIMEOUT_DURATION_FOR_SSH, HA_CLUSTER_PASS, CLUSTER_NAME, HA_USER
from firewall_input_app.models import Source, InputFirewall
from root_runner.utils import command_runner
from utils.config_files import TEST_PATH, TEST_COMMANDS_FILE, DNSMASQ_CONFIG_FILE, DNS_UPSTREAM_FILE, \
    RSYSLOG_CONFIG_FILE, NTP_CONFIG_FILE, RC_LOCAL_FILE
from utils.test.helpers import check_file_content, ntp_config_file, rsyslogconfig_file, \
    dnsmasqconfig_file, create_rsyslog_server_config_for_test, add_test_rsyslog_server_1, add_test_rsyslog_server_2, \
    CustomAPITestCase

username = TEST_ADMIN_USERNAME
password = TEST_ADMIN_PASSWORD

INTERFACE_IDX = 0


# class InterfaceTest(APITestCase):

#     def setUp(self):
#         super(InterfaceTest, self).setUp()
#         set_system_interfaces()
#
#     def test_retrieve_interface(self):
#         interfaces = Interface.objects.all().order_by('id')
#         url = reverse('interface-detail', kwargs={'pk': interfaces[INTERFACE_IDX].id})
#         response = self.client.get(url)
#         self.assertNotEqual(len(response.json()), 0)
#
#     def test_put_interface_status(self):
#         interfaces = Interface.objects.all().order_by('id')
#         url = reverse('interface-detail', kwargs={'pk': interfaces[INTERFACE_IDX].id})
#
#         data = {'id': interfaces[INTERFACE_IDX].id,
#                 'name': interfaces[INTERFACE_IDX].name,
#                 'description': interfaces[INTERFACE_IDX].description,
#                 'alias': interfaces[INTERFACE_IDX].alias,
#                 'ip_list': json.dumps(interfaces[INTERFACE_IDX].ip_list) if interfaces[INTERFACE_IDX].ip_list else [],
#                 'gateway': interfaces[INTERFACE_IDX].gateway,
#                 'is_default_gateway': interfaces[INTERFACE_IDX].is_default_gateway,
#                 'is_dhcp_enabled': True,
#                 'type': 'LAN' if not interfaces[INTERFACE_IDX].type else interfaces[INTERFACE_IDX].type,
#                 'is_enabled': False,
#                 'link_type': interfaces[INTERFACE_IDX].link_type,
#                 'pppoe_username': interfaces[INTERFACE_IDX].pppoe_username,
#                 'pppoe_password': interfaces[INTERFACE_IDX].pppoe_password,
#                 'mtu': interfaces[INTERFACE_IDX].mtu
#                 }
#         response = self.client.put(url, data, format='json')
#         # print("response in test_put_interface_status:", response, response.content.decode('utf8'))
#         self.assertEqual(response.status_code, 200)
#
#         self.assertEqual(interfaces[INTERFACE_IDX].is_enabled,
#                          not (is_interface_active(interfaces[INTERFACE_IDX].name)))
#
#         nmcli_cmd = 'nmcli connection up ' + interfaces[INTERFACE_IDX].name
#         command_runner(nmcli_cmd)
#
#         Interface.objects.all().delete()
#
#     def test_put_interface_address(self):
#         interfaces = Interface.objects.all().order_by('id')
#         url = reverse('interface-detail', kwargs={'pk': interfaces[INTERFACE_IDX].id})
#
#         data = {'id': interfaces[INTERFACE_IDX].id,
#                 'name': interfaces[INTERFACE_IDX].name,
#                 'description': interfaces[INTERFACE_IDX].description,
#                 'alias': interfaces[INTERFACE_IDX].alias,
#                 'ip_list': [{"ip": "10.10.10.10", "mask": "255.255.255.0"},
#                             {"ip": "20.20.20.20", "mask": "255.255.255.0"}],
#                 'gateway': "10.10.10.1",
#                 'is_default_gateway': interfaces[INTERFACE_IDX].is_default_gateway,
#                 'is_dhcp_enabled': False,
#                 'type': 'LAN' if not interfaces[INTERFACE_IDX].type else interfaces[INTERFACE_IDX].type,
#                 'is_enabled': interfaces[INTERFACE_IDX].is_enabled,
#                 'link_type': interfaces[INTERFACE_IDX].link_type,
#                 'pppoe_username': interfaces[INTERFACE_IDX].pppoe_username,
#                 'pppoe_password': interfaces[INTERFACE_IDX].pppoe_password,
#                 'mtu': interfaces[INTERFACE_IDX].mtu
#                 }
#         response = self.client.put(url, data, format='json')
#         # print("response in test_put_interface_address:", response, response.content.decode('utf8'))
#         self.assertEqual(response.status_code, 200)
#
#         self.assertEqual(get_interface_ip(interfaces[INTERFACE_IDX].name),
#                          [{"ip": "10.10.10.10", "mask": "255.255.255.0"},
#                           {"ip": "20.20.20.20", "mask": "255.255.255.0"}])
#
#         nmcli_cmd = list()
#         nmcli_cmd.append(
#             "nmcli connection modify %s ipv4.method 'auto' ipv4.addresses '' ipv4.gateway ''" % interfaces[
#                 INTERFACE_IDX].name)
#         nmcli_cmd.append('nmcli con down %s' % interfaces[INTERFACE_IDX].name)
#         nmcli_cmd.append('nmcli con up %s' % interfaces[INTERFACE_IDX].name)
#
#         for cmd in nmcli_cmd:
#             command_runner(cmd)
#
#         Interface.objects.all().delete()
#
#     def test_put_interface_is_default_gateway(self):
#         interfaces = Interface.objects.all().order_by('id')
#         url = reverse('interface-detail', kwargs={'pk': interfaces[INTERFACE_IDX].id})
#
#         old_default_gw = get_primary_default_gateway_interface_name()
#
#         data = {'id': interfaces[INTERFACE_IDX].id,
#                 'name': interfaces[INTERFACE_IDX].name,
#                 'description': interfaces[INTERFACE_IDX].description,
#                 'alias': interfaces[INTERFACE_IDX].alias,
#                 'ip_list': interfaces[INTERFACE_IDX].ip_list if interfaces[INTERFACE_IDX].ip_list else [],
#                 'gateway': interfaces[INTERFACE_IDX].gateway,
#                 'is_default_gateway': True,
#                 'is_dhcp_enabled': True,
#                 'type': 'LAN' if not interfaces[INTERFACE_IDX].type else interfaces[INTERFACE_IDX].type,
#                 'is_enabled': interfaces[INTERFACE_IDX].is_enabled,
#                 'link_type': interfaces[INTERFACE_IDX].link_type,
#                 'pppoe_username': interfaces[INTERFACE_IDX].pppoe_username,
#                 'pppoe_password': interfaces[INTERFACE_IDX].pppoe_password,
#                 'mtu': interfaces[INTERFACE_IDX].mtu
#                 }
#         response = self.client.put(url, data, format='json')
#
#         self.assertEqual(response.status_code, 200)
#
#         is_default_gateway = False
#         if get_primary_default_gateway_interface_name() == interfaces[INTERFACE_IDX].name:
#             is_default_gateway = True
#
#         self.assertEqual(is_default_gateway, True)
#
#         new_default_gw = get_primary_default_gateway_interface_name()
#         self.assertEqual(new_default_gw, interfaces[INTERFACE_IDX].name)
#         #
#         # if not old_default_gw:
#         #     cmd = 'ip route del default table main'
#         #     sudo_runner(cmd)
#         #
#         # if old_default_gw and new_default_gw != old_default_gw:
#         #     set_primary_default_gateway(old_default_gw, new_default_gw)
#         # Interface.objects.all().delete()
#
#     def test_put_ethernet_to_pppoe(self):
#         interfaces = Interface.objects.all().order_by('id')
#         url = reverse('interface-detail', kwargs={'pk': interfaces[INTERFACE_IDX].id})
#
#         if interfaces[INTERFACE_IDX].link_type != 'Ethernet':
#             return
#
#         cmd = 'ifconfig | grep ppp | wc -l'
#         output = command_runner(cmd)
#         ppp_connection_old = int(output[0])
#
#         data = {'id': interfaces[INTERFACE_IDX].id,
#                 'name': interfaces[INTERFACE_IDX].name,
#                 'description': interfaces[INTERFACE_IDX].description,
#                 'alias': interfaces[INTERFACE_IDX].alias,
#                 'ip_list': json.dumps(interfaces[INTERFACE_IDX].ip_list) if interfaces[INTERFACE_IDX].ip_list else [],
#                 'gateway': interfaces[INTERFACE_IDX].gateway,
#                 'is_default_gateway': interfaces[INTERFACE_IDX].is_default_gateway,
#                 'is_dhcp_enabled': True,
#                 'type': 'LAN' if not interfaces[INTERFACE_IDX].type else interfaces[INTERFACE_IDX].type,
#                 'is_enabled': interfaces[INTERFACE_IDX].is_enabled,
#                 'link_type': 'PPPOE',
#                 'pppoe_username': 'naghdi',
#                 'pppoe_password': '123qwe!',
#                 'mtu': interfaces[INTERFACE_IDX].mtu
#                 }
#         response = self.client.put(url, data, format='json')
#         # print("response in test_put_ethernet_to_pppoe:", response, response.content.decode('utf8'))
#
#         self.assertEqual(response.status_code, 200)
#
#         cmd = 'ifconfig | grep ppp | wc -l'
#         ps = command_runner(cmd)
#         ppp_connection_new = int(ps[0])
#
#         self.assertEqual(ppp_connection_old + 1, ppp_connection_new)
#
#         cmd = 'nmcli connection delete ' + interfaces[INTERFACE_IDX].name
#         sudo_runner(cmd)


class NTPConfigTest(APITestCase):
    def setUp(self):
        if not os.path.exists('{}/etc'.format(TEST_PATH)):
            os.system('mkdir -p {}/etc'.format(TEST_PATH))
        ntp_config_file()
        with open('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), 'w+') as commands_file:
            commands_file.write('')

    def test_post_ntp_server1(self):
        url = reverse('ntp-list')
        ntp_server_list = ['200.20.20.2', 'time.ir']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)
        self.assertEqual(NTPConfig.objects.first().status, 'succeeded')

        for ntp_server in ntp_server_list:
            self.assertTrue(
                check_file_content('{}{}'.format(TEST_PATH, NTP_CONFIG_FILE), ntp_server))
        cmd = 'service ntp stop'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        cmd = 'service ntp start'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))

    def test_post_ntp_server2(self):
        url = reverse('ntp-list')
        ntp_server_list = ['test.com']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)
        self.assertEqual(NTPConfig.objects.first().status, 'succeeded')

        for ntp_server in ntp_server_list:
            self.assertTrue(
                check_file_content('{}{}'.format(TEST_PATH, NTP_CONFIG_FILE), ntp_server))
        cmd = 'service ntp stop'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        cmd = 'service ntp start'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))

    def test_post_ntp_server3(self):
        url = reverse('ntp-list')
        ntp_server_list = ['test.com']
        response = self.client.post(url,
                                    {"ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)
        self.assertEqual(NTPConfig.objects.first().status, 'succeeded')

        for ntp_server in ntp_server_list:
            self.assertFalse(
                check_file_content('{}{}'.format(TEST_PATH, NTP_CONFIG_FILE), ntp_server))
        cmd = 'service ntp stop'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))

    def test_post_ntp_server_twice(self):
        url = reverse('ntp-list')
        ntp_server_list = ['200.20.20.2', 'time.ir']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)

        """new ntp servers write on old ones"""
        ntp_server_list = ['100.10.10.10', 'ntp.ir']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(NTPConfig.objects.all().count(), 1)

    def test_post_ntp_server_400_1(self):
        url = reverse('ntp-list')
        ntp_server_list = []
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')
        # print("response:", response.content.decode('utf8'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_ntp_server_400_2(self):
        url = reverse('ntp-list')
        ntp_server_list = "test"
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_ntp_server_400_3(self):
        url = reverse('ntp-list')
        ntp_server_list = ["test-com"]
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_ntp_server_400_4(self):
        url = reverse('ntp-list')
        ntp_server_list = ["19.10.2.22.1"]
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_ntp_server_400_5(self):
        url = reverse('ntp-list')
        ntp_server_list = ["test/com", "10.0.0.1"]
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_stop_ntp(self):
        url = reverse('ntp-list')
        ntp_server_list = ['200.20.20.2', 'time.ir']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)
        self.assertEqual(NTPConfig.objects.first().status, 'succeeded')
        cmd = 'service ntp stop'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        cmd = 'service ntp start'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        # stop ntp
        ntp_config = NTPConfig.objects.get()
        url = reverse('ntp-detail', kwargs={'pk': ntp_config.id})
        # try:
        #     with transaction.atomic():
        #
        #         response = self.client.put(url,
        #                                {'is_enabled': False, 'ntp_server': []}, format='json')
        #
        #
        # except IntegrityError:
        #     pass
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertEqual(NTPConfig.objects.first().status, 'succeeded')
        # cmd = 'service ntp stop'
        # self.assertTrue(
        #     check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))

    def test_delete_ntp(self):
        url = reverse('ntp-list')
        ntp_server_list = ['200.20.20.2', 'time.ir']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)

        ntp_config = NTPConfig.objects.get()
        url = reverse('ntp-detail', kwargs={'pk': ntp_config.id})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_ntp(self):
        url = reverse('ntp-list')
        ntp_server_list = ['200.20.20.2', 'time.ir']
        response = self.client.post(url,
                                    {'is_enabled': True, "ntp_server_list": ntp_server_list}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NTPConfig.objects.all().count(), 1)

        ntp_config = NTPConfig.objects.get()
        url = reverse('ntp-detail', kwargs={'pk': ntp_config.id})

        # try:
        #
        #     with self.assertRaises(IntegrityError):
        #
        #         with transaction.atomic():
        #             response = self.client.put(url,
        #                                {'is_enabled': True, 'ntp_server_list': ['test.com']}, format='json')
        #
        # except IntegrityError:
        #     pass
        # self.assertEqual(response.status_code, status.HTTP_200_OK)
        # self.assertEqual(NTPConfig.objects.first().status, 'succeeded')
        # self.assertEqual(NTPConfig.objects.first().ntp_server_list, ['test.com'])


class RsyslogConfigTest(APITestCase):
    def setUp(self):
        if not os.path.exists('{}/etc'.format(TEST_PATH)):
            os.system('mkdir -p {}/etc'.format(TEST_PATH))
        rsyslogconfig_file()

    def tearDown(self):
        if os.path.exists('{}/etc'.format(TEST_PATH)):
            os.system('rm -r {}/etc'.format(TEST_PATH))

    def test_post_rsyslog_server_1(self):
        url = reverse('log-server-list')
        data = {
            "address": "10.10.10.10",
            "port": 3333,
            "protocol": "udp",
            "service_list": ["ssh", "vpn"],
            "is_secure": False
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(LogServer.objects.get(address='10.10.10.10').status, 'succeeded')

        config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], False, "vpn", "ssh")
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))

    def test_post_rsyslog_server_2(self):
        url = reverse('log-server-list')
        data = {
            "address": "10.10.10.11",
            "port": 3333,
            "protocol": "tcp",
            "service_list": ["firewall", "vpn"],
            "is_secure": False
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(LogServer.objects.get(address='10.10.10.11').status, 'succeeded')

        config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], False, "firewall", "vpn")
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))

    def test_post_rsyslog_server_3(self):
        url = reverse('log-server-list')
        data = {
            "address": "10.10.10.12",
            "port": 3333,
            "protocol": "tcp",
            "service_list": ["firewall", "vpn", "ssh"],
            "is_secure": False
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(LogServer.objects.get(address='10.10.10.12').status, 'succeeded')

        config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], False, "firewall", "vpn", "ssh")
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))

    def test_post_rsyslog_server_4(self):
        url = reverse('log-server-list')
        data = {
            "is_enabled": False,
            "address": "10.10.10.13",
            "port": 3333,
            "protocol": "tcp",
            "service_list": ["firewall", "vpn", "ssh"],
            "is_secure": False
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(LogServer.objects.get(address='10.10.10.13').status, 'succeeded')

        config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], False, "firewall", "vpn", "ssh")
        self.assertFalse(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))

    def test_put_rsyslog_server_1(self):
        instance = add_test_rsyslog_server_1()

        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        data = {
            "is_enabled": True,
            "address": "10.10.10.14",
            "port": 3333,
            "protocol": "tcp",
            "service_list": ["firewall", "ssh"],
            "is_secure": False
        }
        response = self.client.put(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(LogServer.objects.get(address='10.10.10.14').status, 'succeeded')

        new_config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], False, "firewall", "ssh")
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), new_config_rgx))

    def test_put_rsyslog_server_2(self):
        instance = add_test_rsyslog_server_1()

        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        data = {
            "is_enabled": False,
            "address": "10.10.10.15",
            "port": 3333,
            "protocol": "tcp",
            "service_list": ["firewall"],
            "is_secure": False
        }
        response = self.client.put(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(LogServer.objects.get(address='10.10.10.15').status, 'succeeded')

        new_config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], False, "firewall")
        self.assertFalse(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), new_config_rgx))

    def test_put_rsyslog_server_3(self):
        instance = add_test_rsyslog_server_2()

        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        data = {
            "is_enabled": False,
            "address": "10.10.10.16",
            "port": 3333,
            "protocol": "tcp",
            "service_list": ["firewall", "vpn", "ssh"],
            "is_secure": True
        }
        response = self.client.put(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(LogServer.objects.get(address='10.10.10.16').status, 'succeeded')

        new_config_rgx = create_rsyslog_server_config_for_test(
            data['address'], data['port'], data['protocol'], data['is_secure'], "firewall", "vpn", "ssh")
        self.assertFalse(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), new_config_rgx))

    def test_patch_rsyslog_server_1(self):
        instance = add_test_rsyslog_server_1()

        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        data = {
            "address": "10.10.10.60",
            "protocol": "tcp",
        }
        response = self.client.patch(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(LogServer.objects.get(address='10.10.10.60').status, 'succeeded')

        new_config_rgx = create_rsyslog_server_config_for_test(
            data['address'], instance.port, data['protocol'], instance.is_secure, "firewall", "vpn")
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), new_config_rgx))

    def test_patch_rsyslog_server_2(self):
        instance = add_test_rsyslog_server_1()

        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        data = {
            'is_enabled': True,
            "is_secure": True

        }
        response = self.client.patch(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(LogServer.objects.get(address=instance.address).status, 'succeeded')

        config_rgx = create_rsyslog_server_config_for_test(
            instance.address, instance.port, instance.protocol, True, "firewall", "vpn")
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))

    def test_patch_rsyslog_server_3(self):
        instance = add_test_rsyslog_server_1()

        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        data = {
            'is_enabled': False
        }
        response = self.client.patch(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(LogServer.objects.get(address=instance.address).status, 'succeeded')

        config_rgx = create_rsyslog_server_config_for_test(
            instance.address, instance.port, instance.protocol, instance.is_secure, "firewall", "vpn")
        self.assertFalse(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))

    def test_delete_rsyslog(self):
        instance = add_test_rsyslog_server_1()
        url = reverse('log-server-detail', kwargs={'pk': instance.pk})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(LogServer.objects.all().count(), 0)

        config_rgx = create_rsyslog_server_config_for_test(
            instance.address, instance.port, instance.protocol, instance.is_secure, "ssh", "vpn")
        self.assertFalse(
            check_file_content('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), config_rgx))


# class StaticRouteTest(APITestCase):
#     def tearDown(self):
#         command_runner('rm -rf {}/route.txt'.format(TEST_PATH))
#
#     def test_post_static_route(self):
#         interface = Interface.objects.all()[0]
#
#         # post static route
#         url = reverse('static-route-list')
#         data = {
#             "name": "test1",
#             "description": "test1",
#             "is_enabled": True,
#             "destination_ip": "192.168.15.0",
#             "destination_mask": 24,
#             "gateway": "192.168.15.10",
#             "interface": interface.id,
#             "metric": 1000
#         }
#         response = self.client.post(url, data, format='json')
#
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertEqual(StaticRoute.objects.all().count(), 1)
#
#         # check in ip route table
#         static_route_id = json.loads(response.content)['id']
#         static_route = StaticRoute.objects.get(id=static_route_id)
#         find = check_static_route_existence(static_route)
#         self.assertEqual(find, True)
#
#         # delete this new static route
#         cmd = delete_static_route_cmd(static_route)
#         sudo_runner(cmd)
#
#     def test_delete_static_route(self):
#         instance = add_test_static_route()
#
#         old_instance = deepcopy(instance)
#         url = reverse('static-route-detail', kwargs={'pk': instance.id})
#         response = self.client.delete(url)
#         self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
#         self.assertEqual(StaticRoute.objects.all().count(), 0)
#         find = check_static_route_existence(old_instance)
#         self.assertEqual(find, False)


# class BackupTests(APITestCase):
#     fixtures = ['config_app/fixtures/initial_data.json']
#
#     def test_create_new_backup(self):
#         url = reverse('backup-list')
#
#         data = {
#             'description': 'test_backup'
#         }
#
#         response = self.client.post(url, data, format='json')
#
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertEqual(response.json()['status'], 'succeeded')
#
#     def test_download_backup_file(self):
#         backup = self.create_sample_backup()
#         url = reverse('backup-file', kwargs={'pk': backup.id})
#         response = self.client.get(url, format='json')
#         with open('playground/sg_backup_test.bak', 'wb') as f:
#             f.write(response.content)
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#
#     # def test_upload_backup_file(self):
#     #     backup = self.create_sample_backup(is_uploaded_by_user=True)
#     #     url = reverse('backup-file', kwargs={'pk': backup.id})
#     #
#     #     with open('utils/test/sg_backup_test.bak', 'rb') as f:
#     #         data = {'file': f}
#     #         response = self.client.post(url, data)
#     #
#     #     self.assertEqual(response.status_code, status.HTTP_200_OK)
#     #     self.assertEqual(Backup.objects.get(id=backup.id).description, 'sample backup description')
#     #     self.assertEqual(Backup.objects.get(id=backup.id).version, '1.0.0.343')
#     #     self.assertEqual(str(Backup.objects.get(id=backup.id).datetime), '2018-07-14 13:56:49.771066+00:00')
#
#     def test_delete_backup(self):
#         backup = self.create_sample_backup()
#         url = reverse('backup-detail', kwargs={'pk': backup.id})
#         response = self.client.delete(url)
#         self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
#
#     def test_restore_backup_from_internal_backup(self):
#         backup = self.create_sample_backup()
#         url = reverse('backup-restore', kwargs={'pk': backup.id})
#         response = self.client.post(url)
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#
#     # def test_restore_backup_from_uploaded_backup(self):
#     #     backup = self.create_sample_backup(is_uploaded_by_user=True)
#     #
#     #     url = reverse('backup-file', kwargs={'pk': backup.id})
#     #     with open('utils/test/sg_backup_test.bak', 'rb') as f:
#     #         data = {'file': f}
#     #         self.client.post(url, data)
#     #
#     #     url = reverse('backup-restore', kwargs={'pk': backup.id})
#     #     response = self.client.post(url)
#     #     self.assertEqual(response.status_code, status.HTTP_200_OK)
#
#     def test_upload_invalid_file(self):
#         backup = self.create_sample_backup(is_uploaded_by_user=True)
#         url = reverse('backup-file', kwargs={'pk': backup.id})
#         f = open('playground/firewall_test.py', 'rb')
#         data = {
#             'file': f
#         }
#         response = self.client.post(url, data)
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#
#     def create_sample_backup(self, is_uploaded_by_user=False):
#         data = {
#             'description': 'sample backup description',
#             'is_uploaded_by_user': is_uploaded_by_user
#         }
#
#         serializer = BackupSerializer(data=data)
#         assert serializer.is_valid()
#         instance = serializer.save()
#         return instance


class SystemServiceTests(APITestCase):
    fixtures = ['config_app/fixtures/initial_data.json']

    def test_get_list_of_services(self):
        url = reverse('system-service-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class SettingTests(APITestCase):
    fixtures = ['config_app/fixtures/initial_data.json']

    def test_get_list_of_settings(self):
        url = reverse('setting-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    #     def test_upload_ssl_certificate(self):
    #         url = reverse('setting-detail', kwargs={'pk': 'ssl_certificate'})
    #         data = {
    #             'data': {'public_key': """"-----BEGIN CERTIFICATE-----
    # MIIDqzCCApOgAwIBAgIJAJTySnG8bQPdMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNV
    # BAYTAklSMRAwDgYDVQQIDAdJc2ZhaGFuMRAwDgYDVQQHDAdJc2ZhaGFuMRUwEwYD
    # VQQKDAxQYXlhbSBQYXJkYXoxDjAMBgNVBAsMBU5hcmluMRIwEAYDVQQDDAluYXJp
    # bi5sb2MwHhcNMTgwODExMDgyNTA2WhcNMTkwODExMDgyNTA2WjBsMQswCQYDVQQG
    # EwJJUjEQMA4GA1UECAwHSXNmYWhhbjEQMA4GA1UEBwwHSXNmYWhhbjEVMBMGA1UE
    # CgwMUGF5YW0gUGFyZGF6MQ4wDAYDVQQLDAVOYXJpbjESMBAGA1UEAwwJbmFyaW4u
    # bG9jMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQSkhkEQRnDKryKd
    # tZoP2zdAEjx5vp0XR6U7OVUhiZWlxabUD8jx0by5YwCze4C8CST5/EnFEOPNXzvU
    # W4PtKMysft+5kYZNNx7Ex7QIBGAcbzzPXg8bMEVBtb8dcY+f6DaVJG7kv+Nrn/im
    # v6DWwoNWPtE1mb9LMvSgwR+oK+5wYJQpihXK1ZD/0URzPISPRgK1nBnax8YD9cOo
    # VD1a1SIYgHeS88MdHRkaEKxm6WZa34ox3WO1hkDrLjx28CrISnSVVOTcQb0UEyzt
    # Il1EUtt6yQupOmX3XYjkzXOE0NJAf9I3I9+nJPGpnJ8BaS6fjEMEtYB+pDTlQZDf
    # f387UwIDAQABo1AwTjAdBgNVHQ4EFgQUbx9SX3+wvw534INShBmn6JH2WYgwHwYD
    # VR0jBBgwFoAUbx9SX3+wvw534INShBmn6JH2WYgwDAYDVR0TBAUwAwEB/zANBgkq
    # hkiG9w0BAQsFAAOCAQEAgEeVLE1zIdTphuFuKDBEE6Zu+FKF6iAnFerUpAGeXohm
    # cSIorDXoGVG4InBe+MHBwnDDWraYvMNxcHTqufeNkxOjsBhiOx/Fdqij842pqiJ3
    # U/+GtSQSKxTeQuMmvLPd0oWj2HAkN4Z7smtJeP8LWweGMmWEKtRwlTIQXISDLMdB
    # zNrrQ0NysgagOnFWfNXnXp9BX7/BMYzoFkFNvIEepu3eGEkkqIkHNW+gQWiR7Gr/
    # +lYmWZRX/P/xvP1hZDiKt0pN1aRdFFOVQEB23rKmYaxb9rn/UnCmQWtgRbZg8v/P
    # SbisBtpUyM7pj46oaVQV1p6QSPb7k5+H9tGvfcDHyA==
    # -----END CERTIFICATE-----""",
    #                      'private_key': """-----BEGIN PRIVATE KEY-----
    # MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFBKSGQRBGcMqv
    # Ip21mg/bN0ASPHm+nRdHpTs5VSGJlaXFptQPyPHRvLljALN7gLwJJPn8ScUQ481f
    # O9Rbg+0ozKx+37mRhk03HsTHtAgEYBxvPM9eDxswRUG1vx1xj5/oNpUkbuS/42uf
    # +Ka/oNbCg1Y+0TWZv0sy9KDBH6gr7nBglCmKFcrVkP/RRHM8hI9GArWcGdrHxgP1
    # w6hUPVrVIhiAd5Lzwx0dGRoQrGbpZlrfijHdY7WGQOsuPHbwKshKdJVU5NxBvRQT
    # LO0iXURS23rJC6k6ZfddiOTNc4TQ0kB/0jcj36ck8amcnwFpLp+MQwS1gH6kNOVB
    # kN9/fztTAgMBAAECggEAMUTQ8/XvYP4x4YwxjkmBr5tofWb8NwvH15Xdcp/0bBit
    # RPlMTMo+lumwHq79M2RlIZBKp6m3C1s8b5VhrKUYOLy+YlgGavr/8knSgfJmktmK
    # ItM9NFNoxDB9lzq83TpCjeqgb2T/9XCk6HNhF8jcC/aWKc1drx4kaxC75q/I+XsN
    # 8JOPNm9lSR4jIKsciQY3G6rpbWIYDw8zstLNUYnwURUpgR2HhHtIe8r5fxARsYdz
    # l9CjPlRDzT210dCxaJ5riIsy2rtHnK+JOYrzfh3Fvl0k4lyQZhLr/Oz1XbdwHixv
    # Wf05HEw3PaG06KOYKkroEH23ei9dYf1piZaGsT/xQQKBgQDi71lymlFmip6gdEmn
    # Rfd5zEfO6nsArTK3MHG+JyLJu4gJCvsYLKeHy4CUwxTMs82NasY1BkZjun/VtZqS
    # 67mkycuMX2TNvam6B0Jn0vuFMB8amQJ5s33rN8G9adoFTDAdDLfZEI0hDAYN0eBc
    # WfJoXZsa/1yjgFFPrehEmdCJ8wKBgQDeQGSIg2pscEHELeGFH4rhHkn3IyfloQ/A
    # BDb/tg7WmBZDaFFfnS+n49dDPpqC9QVEfmZP7MGYcDYwFHOqu6uCVWV8pL3UUMLE
    # s0S+Hqx920poGWUpTNdNNU4nrOCOoQG14fdoaG6RwJ63oy+5AiDz4lLAfcDkmbsy
    # n2NvLf6BIQKBgQDg7TUuFvBJf2mcRcZe6kVQzn36A4So9gIHeheyzl13r800kVKw
    # 8kmWmci3KehqwGgjG8qa8b5AyLA95QLxTn0xbOW4GzDxj2Qzw1A5UfAEYd7iYPgI
    # IjTTN+9qSwlSKOKjWGC839/R+nXhqr0DLA/NC8JZbvOmBuAQ5qEJpZ8BqwKBgF02
    # KHPQmevM0OhUTcclSXvM1jyeM/dsq0xe+Coa0vJRatTuhWJSbFA/kGKVePv/gywM
    # zyAqLa+fMDrN+QzcFLxe0GeMOEk5bdZNUUFjX/iQ5g3uyKyfm5S4DIU7ThrDkBIW
    # KUtSsTzTyj0+ZZ90MxnWC9rLYwD9MLO0gWF5qsnBAoGBAI9XzydoWjTPqz7Y8lXX
    # CfKE9h8BxyQRHj7pK8Y1VoRkLGAgoSw+aIVaPn6SmOdi9DQzm/cp4cFwuB8BvA6l
    # kv6wSoVYisHhMcS6UgGDm/Z+dp1QORb9sp2FtfamXDF6pMAQlG/XJisp2ZIlxfaY
    # q8qubtQb1TmOYWVKaDwAY97p
    # -----END PRIVATE KEY-----"""
    #                      }
    #         }
    #         response = self.client.put(url, data, format='json')
    #         print(response.content)
    #
    #         self.assertEqual(response.status_code, status.HTTP_200_OK)
    #         self.assertDictEqual(Setting.objects.get(key='ssl_certificate').data, data['data'])
    #
    #         s, o = sudo_file_reader('/etc/ssl/certs/nginx-selfsigned.crt')
    #         self.maxDiff = None
    #         self.assertEqual(data['data']['public_key'], o)
    #
    #         s, o = sudo_file_reader('/etc/ssl/private/nginx-selfsigned.key')
    #         self.maxDiff = None
    #         self.assertEqual(data['data']['private_key'], o)

    def test_validate_ssl_certificate_public_and_private_exists(self):
        url = reverse('setting-detail', kwargs={'pk': 'ssl_certificate'})
        data = {
            'data': {'public_key': """"-----BEGIN CERTIFICATE-----
MIIEATCCAumgAwIBAgIJAP7X6OTL4bbUMA0GCSqGSIb3DQEBCwUAMIGWMQswCQYD
VQQGEwJJUjEQMA4GA1UECAwHSXNmYWhhbjEQMA4GA1UEBwwHSXNmYWhhbjEVMBMG
A1UECgwMUGF5YW0gUGFyZGF6MQ4wDAYDVQQLDAVOYXJpbjEXMBUGA1UEAwwOMTky
LjE2OC4xNS4yMDExIzAhBgkqhkiG9w0BCQEWFGluZm9AcGF5YW1wYXJkYXouY29t
MB4XDTE4MDUyMDA0MjA0MVoXDTE5MDUyMDA0MjA0MVowgZYxCzAJBgNVBAYTAklS
MRAwDgYDVQQIDAdJc2ZhaGFuMRAwDgYDVQQHDAdJc2ZhaGFuMRUwEwYDVQQKDAxQ
YXlhbSBQYXJkYXoxDjAMBgNVBAsMBU5hcmluMRcwFQYDVQQDDA4xOTIuMTY4LjE1
LjIwMTEjMCEGCSqGSIb3DQEJARYUaW5mb0BwYXlhbXBhcmRhei5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3KYvvTFvsSkjfEcEda+DfxN4Cd6U5
240iLR+zcgfv/7kY1eQHxfnDEHQ0aJGJJ6NJw7XzZ1aYZtENXievdJYg1s+OV3gh
pPnvDt3L63/vRkZJyVR+q52wBS+X6cUxGHnU25h2yd7of+u2dDv0tvtISKxGTXXv
B+V3c0umW697YDIPJmkEDAyvVBCeBzJATwAxgffeZO10M2Irq8T7xol0zuOq4mZV
A9PAILbRWPPhhCIx94oFjDR1xkHdz5JR/vhUDvrXWpbNWFy3klxu1/G54rwnXv8M
ya9bQepAlIA77VaWKHk0nPFgTbyQySeXTm03rnRd5xsM2KEpJKq2Th/3AgMBAAGj
UDBOMB0GA1UdDgQWBBRwMpBF1Sdei/Zst+1QywaW7A/9xTAfBgNVHSMEGDAWgBRw
MpBF1Sdei/Zst+1QywaW7A/9xTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBTZphp9n/XTTa38bcJGBPAobxoFxfzzurpZvk1OiN1KM1/xPENALWIyjsk
guuJ0zxaGCbkCMDbdqb1FUTcb4C3I+FwDpKKUCqIoBpu5NePqrYFdH7yYI9mPibe
xruZOggrOr4Pm5Wsre6c83Y9degR2HCdIPZpxejiGXrazNiyO/QgnARD46cy6e5e
10/M0ZsU56Z4nYxl/5nMMs9TmaWoOheRiF54LPdmyXUVSE3mq6f4HhMnzsB5YTCU
uMKWmGn5Ws2iZeXXaYfSSTc7ORV3D5EPMB2j5j1Ac6/OQEhkFrDc4K2eKL/DbvUH
SoySW0H8g14uQd8wi25HrH3pElwo
-----END CERTIFICATE-----"""
                     }
        }
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UpdateTests(APITestCase):
    new_version = '1.0.0.2'

    def tearDown(self):
        super(UpdateTests, self).tearDown()
        command_runner('rm -rf /var/ngfw/{brand}.v{ver}.tar.xz'.format(brand=BRAND, ver=self.new_version))
        command_runner('rm -rf /var/ngfw/{brand}.v{ver}.tar.xz.gpg'.format(brand=BRAND, ver=self.new_version))
        command_runner('rm -rf install.yml')

    def test_check_no_update(self):
        url = reverse('update-check')
        response = self.client.get(url + '?test=400')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    # def test_check_with_update(self):
    #     url = reverse('update-check')
    #     response = self.client.get(url + '?test=200')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(Update.objects.filter(status='available').count(), 1)

    def test_download_update(self):
        Update.objects.create(version=self.new_version, status='available', server_id=1)
        url = reverse('update-download')
        response = self.client.get(url + '?test=true')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Update.objects.filter(status='downloaded').count(), 1)

    # def test_validate_update(self):
    #     Update.objects.create(version=self.new_version, server_id=1, status='downloaded')
    #     command_runner(
    #         'cp -rf utils/test/{}.v{}.tar.xz.gpg /var/ngfw/'.format(BRAND, self.new_version))
    #     url = reverse('update-validate')
    #     response = self.client.get(url + '?test=true')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(Update.objects.filter(status='validated').count(), 1)

    # def test_install_update(self):
    #     Update.objects.create(version=self.new_version, server_id=1, status='validated')
    #     command_runner(
    #         'cp -rf utils/test/{}.v{}.tar.xz /var/ngfw/'.format(BRAND, self.new_version))
    #     url = reverse('update-install')
    #     response = self.client.get(url + '?test=true')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(Update.objects.filter(status='installed').count(), 1)


class DNSConfigurationTest(APITestCase):
    def setUp(self):
        if not os.path.exists('{}/etc'.format(TEST_PATH)):
            os.system('mkdir -p {}/etc'.format(TEST_PATH))
        dnsmasqconfig_file()
        with open('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), 'w+') as commands_file:
            commands_file.write('')

    def test_dns_server_config_fail_1(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        response = self.client.put(url, {
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dns_server_config_fail_2(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        response = self.client.put(url, {
            "tertiary_dns_server": "192.168.15.2",
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')
        # print(response.status_code)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dns_server_config_fail_3(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        response = self.client.put(url, {
            "secondary_dns_server": "192.168.15.1",
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dns_server_config_fail_4(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        response = self.client.put(url, {
            "secondary_dns_server": "192.168.15.1",
            "tertiary_dns_server": "192.168.10.13",
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dns_server_config_put1(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.get(primary_dns_server=primary_dns_server).status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=lo'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'strict-order'))

    def test_dns_server_config_put2(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nstrict-order\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=lo'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'strict-order'))

    def test_dns_server_config_put3(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nall-servers\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=lo'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'strict-order'))

    def test_dns_server_config_put4(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "",
            "is_strict_order": False,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=lo'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'all-servers'))

    def test_dns_server_config_put5(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nstrict-order\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "",
            "is_strict_order": False,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=lo'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'all-servers'))

    def test_dns_server_config_put6(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nexpand-hosts\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "test",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))

    def test_dns_server_config_put7(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\ndomain=\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": "test",
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain='))

    def test_dns_server_config_put8(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = 'test'
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain={}'.format(local_domain)))

    def test_dns_server_config_put9(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nexpand-hosts\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = "test"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain={}'.format(local_domain)))

    def test_dns_server_config_put10(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\ndomain=NGFW\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = "test"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain={}'.format(local_domain)))

    def test_dns_server_config_put11(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nexpand-hosts\ndomain=NGFW\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = "test"
        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": []
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain={}'.format(local_domain)))

    def test_dns_server_config_put12(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\ninterface=test\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = "test"

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": ["eth2"]
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=eth2'))

    def test_dns_server_config_put13(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = "test"

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": ["eth2"]
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=eth2'))

    def test_dns_server_config_put14(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        secondary_dns_server = "192.168.15.3"
        local_domain = "test"

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "secondary_dns_server": secondary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": ["eth2"]
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), secondary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=eth2'))

    def test_dns_server_config_put15(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        secondary_dns_server = "192.168.15.3"
        tertiary_dns_server = "127.16.13.13"
        local_domain = "test"

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "secondary_dns_server": secondary_dns_server,
            "tertiary_dns_server": tertiary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": True,
            "interface_list": ["eth2"]
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), secondary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), tertiary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=eth2'))

    def test_dns_server_config_put16(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        secondary_dns_server = "192.168.15.3"
        tertiary_dns_server = "127.16.13.13"
        local_domain = "test"

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "secondary_dns_server": secondary_dns_server,
            "tertiary_dns_server": tertiary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": False,
            "interface_list": ["eth2"]
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), secondary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), tertiary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=eth2'))

    def test_dns_server_config_put17(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        secondary_dns_server = "192.168.15.3"
        tertiary_dns_server = "127.16.13.13"
        local_domain = "test"

        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth2",
            ip_list=[{"ip": "91.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        Interface.objects.create(
            name="eth3",
            description="",
            alias="eth3",
            ip_list=[{"ip": "93.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        response = self.client.put(url, {
            "primary_dns_server": primary_dns_server,
            "secondary_dns_server": secondary_dns_server,
            "tertiary_dns_server": tertiary_dns_server,
            "local_domain": local_domain,
            "is_strict_order": False,
            "interface_list": ["eth1", "eth2", "eth3"]
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), secondary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), tertiary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'interface=eth1,eth2,eth3'))

    def test_dns_server_config_patch1(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        secondary_dns_server = "192.168.15.3"

        response = self.client.patch(url, {
            "primary_dns_server": primary_dns_server,
            "secondary_dns_server": secondary_dns_server,
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), secondary_dns_server))

    def test_dns_server_config_patch2(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        local_domain = 'test'
        response = self.client.patch(url, {
            "local_domain": local_domain,
            "is_strict_order": True,
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain={}'.format(local_domain)))

    def test_dns_server_config_patch3(self):
        with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'a+') as dnsmasq_conf:
            dnsmasq_conf.write('\nexpand-hosts\n')
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})
        primary_dns_server = "10.1.2.3"
        local_domain = "test"
        response = self.client.patch(url, {
            "primary_dns_server": primary_dns_server,
            "local_domain": local_domain,
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(DNSConfig.objects.all().count(), 1)
        self.assertEqual(DNSConfig.objects.first().status, 'succeeded')

        cmd = 'service dnsmasq restart'
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), cmd))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNS_UPSTREAM_FILE), primary_dns_server))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'expand-hosts'))
        self.assertTrue(
            check_file_content('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'domain={}'.format(local_domain)))

    def test_dns_server_config_post_fail(self):
        url = reverse('dns-config-list')

        response = self.client.post(url, {
            "primary_dns_server": "4.2.2.4"
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_dns_server_config_delete_fail(self):
        dns_config = DNSConfig.objects.first()
        url = reverse('dns-config-detail', kwargs={'pk': dns_config.id})

        delete_response = self.client.delete(url)
        self.assertEqual(delete_response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class UpdateConfigTest(APITestCase):
    def test_create_update1(self):
        url = reverse('update-manager-list')
        update_server = 'test.com'
        response = self.client.post(url,
                                    {'is_update_enabled': True, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_create_update2(self):
        url = reverse('update-manager-list')
        update_server = '10.1.1.10'
        response = self.client.post(url,
                                    {'is_update_enabled': True, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_create_update3(self):
        url = reverse('update-manager-list')
        response = self.client.post(url,
                                    {'is_update_enabled': False}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_create_update4(self):
        url = reverse('update-manager-list')
        update_server = '10.1.1.10'
        response = self.client.post(url,
                                    {'is_update_enabled': False, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_create_update_fail1(self):
        url = reverse('update-manager-list')
        update_server = 'test'
        response = self.client.post(url,
                                    {'is_update_enabled': True, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_update_fail2(self):
        url = reverse('update-manager-list')
        update_server = '192.168'
        response = self.client.post(url,
                                    {'is_update_enabled': True, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_update_fail3(self):
        url = reverse('update-manager-list')
        update_server = '192.168.15.1 192.168.35.2'
        response = self.client.post(url,
                                    {'is_update_enabled': True, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_update_fail4(self):
        url = reverse('update-manager-list')
        update_server = '192.168.15.16.2'
        response = self.client.post(url,
                                    {'is_update_enabled': True, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_update_fail5(self):
        url = reverse('update-manager-list')
        update_server = '192.168.15.16.2'
        response = self.client.post(url,
                                    {'is_update_enabled': False, 'update_server': update_server}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_update1(self):
        UpdateConfig.objects.create(id=1,
                                    is_update_enabled=False,
                                    update_server='test.com')

        url = reverse('update-manager-detail', kwargs={'pk': 1})
        update_server = '10.1.1.10'
        response = self.client.put(url,
                                   {'is_update_enabled': True, 'update_server': update_server}
                                   , format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_put_update2(self):
        UpdateConfig.objects.create(id=1,
                                    is_update_enabled=True,
                                    update_server='test.com')

        url = reverse('update-manager-detail', kwargs={'pk': 1})
        update_server = '10.1.1.10'
        response = self.client.put(url,
                                   {'is_update_enabled': True, 'update_server': update_server}
                                   , format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_put_updat3(self):
        UpdateConfig.objects.create(id=1,
                                    is_update_enabled=True,
                                    update_server='test.com')

        url = reverse('update-manager-detail', kwargs={'pk': 1})
        update_server = '10.1.1.10'
        response = self.client.put(url,
                                   {'is_update_enabled': False, 'update_server': update_server}
                                   , format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(UpdateConfig.objects.all().count(), 1)

    def test_stop_start_update(self):
        UpdateConfig.objects.create(id=1,
                                    is_update_enabled=True,
                                    update_server='test.com')

        url = reverse('update-manager-detail', kwargs={'pk': 1})
        response = self.client.put(url,
                                   {'is_update_enabled': False,
                                    'update_server': 'test.com'}
                                   , format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        url = reverse('update-manager-detail', kwargs={'pk': 1})
        response = self.client.put(url,
                                   {'is_update_enabled': True,
                                    'update_server': 'test.com'}
                                   , format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(UpdateConfig.objects.first().is_update_enabled, True)
        self.assertEqual(UpdateConfig.objects.first().update_server, 'test.com')


class BridgeConfigTest(APITestCase):

    def test_create_bridge1(self):
        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'gateway': '6.6.6.6',
            'mode': 'bridge',
            'mtu': 75,
            'data': [{"is_stp_enabled": "true", "interface": "eth1"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 2)

    def test_create_bridge2(self):
        Interface.objects.create(
            name="eth0",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )
        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth2",
            ip_list=[{"ip": "8.8.8.8", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )
        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'ip_list': [{"ip": "9.9.9.9", "mask": "255.248.0.0"}],
            'gateway': '5.5.5.5',
            'mode': 'bridge',
            'mtu': 75,
            'data': [{"is_stp_enabled": "true", "interface": ["eth0", "eth1"]}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 3)

    def test_create_bridge_fail1(self):
        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'gateway': '6.6.6.6',
            'mode': 'bridge',
            'mtu': 7575,
            'data': [{"is_stp_enabled": "true", "interface": "eth1"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Interface.objects.all().count(), 1)

    def test_create_bridge_fail2(self):
        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': '@narin@',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'gateway': '6.6.6.6',
            'mode': 'bridge',
            'mtu': 75,
            'data': [{"is_stp_enabled": "true", "interface": "eth1"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Interface.objects.all().count(), 1)

    def test_create_bridge_fail3(self):
        Interface.objects.create(
            name="eth0",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'gateway': '6.6.6.6',
            'mode': 'bridge',
            'mtu': 75,
            'data': [{"is_stp_enabled": "true", "interface": "eth0"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(Interface.objects.all().count(), 2)

    def test_put_bridge(self):
        Interface.objects.create(

            name="eth0",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500

        )

        Interface.objects.create(
            name='narin',
            ip_list=[{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            gateway='6.6.6.6',
            mode='bridge',
            mtu=75,
            data=[{"is_stp_enabled": "true", "interface": "eth0"}],
            is_enabled=True

        )

        url = reverse('interface-detail', kwargs={'pk': "narin"})
        data = {

            'name': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'gateway': '6.6.6.6',
            'mode': 'bridge',
            'mtu': 175,
            'data': [{"is_stp_enabled": "true", "interface": "eth0"}],
            'is_enabled': True
        }

        response = self.client.put(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_200_OK)
        self.assertEquals(Interface.objects.all().count(), 2)

    def test_put_bridge2(self):
        Interface.objects.create(

            name="eth0",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500

        )

        Interface.objects.create(
            name='narin',
            ip_list=[{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            gateway='6.6.6.6',
            mode='bridge',
            mtu=75,
            data=[{"is_stp_enabled": "true", "interface": "eth0"}],
            is_enabled=True

        )

        url = reverse('interface-detail', kwargs={'pk': "narin"})
        data = {

            'name': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'gateway': '6.6.6.6',
            'mode': 'bridge',
            'mtu': 5000,
            'data': [{"is_stp_enabled": "true", "interface": "eth0"}],
            'is_enabled': True
        }

        response = self.client.put(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEquals(Interface.objects.all().count(), 2)


class VlanConfigTest(APITestCase):

    def test_create_vlan1(self):
        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth1",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 175,
            'data': [{"vlan_id": "75", "interface": "eth1"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 2)

    def test_create_vlan2(self):
        Interface.objects.create(
            name="eth4",
            description="",
            alias="eth1",
            ip_list=[{"ip": "6.6.6.6", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 575,
            'data': [{"vlan_id": "75", "interface": "eth4"}],
            'is_enabled': False
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 2)

    def test_create_vlan3(self):
        Interface.objects.create(
            name="eth4",
            description="",
            alias="eth1",
            ip_list=[{"ip": "6.6.6.6", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 75,
            'data': [{"vlan_id": "75", "interface": "eth4"}],
            'is_enabled': True
        }

        data2 = {

            'name': 'narin1',
            'alias': 'narin1',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 75,
            'data': [{"vlan_id": "35", "interface": "eth4"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 2)

        response = self.client.post(url, data2, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 3)

    def test_create_vlan_fail1(self):
        Interface.objects.create(
            name="eth4",
            description="",
            alias="eth1",
            ip_list=[{"ip": "6.6.6.6", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 7575,
            'data': [{"vlan_id": "75", "interface": "eth4"}],
            'is_enabled': False
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Interface.objects.all().count(), 1)

    def test_create_vlan_fail2(self):
        Interface.objects.create(
            name="eth4",
            description="",
            alias="eth1",
            ip_list=[{"ip": "6.6.6.6", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 75,
            'data': [{"vlan_id": "757575", "interface": "eth4"}],
            'is_enabled': False
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Interface.objects.all().count(), 1)

    def test_create_vlan_fail3(self):
        Interface.objects.create(
            name="eth4",
            description="",
            alias="eth1",
            ip_list=[{"ip": "6.6.6.6", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 75,
            'data': [{"vlan_id": "75", "interface": ""}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Interface.objects.all().count(), 1)

    def test_create_vlan_fail4(self):
        Interface.objects.create(
            name="eth4",
            description="",
            alias="eth1",
            ip_list=[{"ip": "6.6.6.6", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        url = reverse('interface-list')
        data = {

            'name': 'narin',
            'alias': 'narin',
            'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
            'mode': 'vlan',
            'mtu': 75,
            'data': [{"vlan_id": "75", "interface": "eth4"}],
            'is_enabled': True
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Interface.objects.all().count(), 2)

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Interface.objects.all().count(), 2)

    # def test_put_vlan1(self):
    #     Interface.objects.create(
    #
    #         name="eth0",
    #         description="",
    #         alias="eth1",
    #         ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
    #         gateway="",
    #         is_default_gateway=True,
    #         is_dhcp_enabled=True,
    #         type="",
    #         is_enabled=True,
    #         link_type="Ethernet",
    #         pppoe_username="",
    #         pppoe_password="",
    #         mtu=1500
    #
    #     )
    #
    #     Interface.objects.create(
    #         name='narin',
    #         ip_list=[{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
    #         gateway='6.6.6.6',
    #         mode='vlan',
    #         mtu=75,
    #         data=[{"vlan_id": "12", "interface": "eth0"}],
    #         is_enabled=True
    #
    #     )
    #
    #     url = reverse('interface-detail', kwargs={'pk': "narin"})
    #     data = {
    #
    #         'name': 'narin',
    #         'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
    #         'gateway': '6.6.6.6',
    #         'mode': 'vlan',
    #         'mtu': 175,
    #         'data': [{"vlan_id": "12", "interface": "eth0"}],
    #         'is_enabled': True
    #     }
    #
    #     response = self.client.put(url, data, format='json')
    #     self.assertEquals(response.status_code, status.HTTP_200_OK)
    #     self.assertEquals(Interface.objects.all().count(), 2)
    #
    # def test_put_vlan2(self):
    #     Interface.objects.create(
    #
    #         name="eth0",
    #         description="",
    #         alias="eth1",
    #         ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
    #         gateway="",
    #         is_default_gateway=True,
    #         is_dhcp_enabled=True,
    #         type="",
    #         is_enabled=True,
    #         link_type="Ethernet",
    #         pppoe_username="",
    #         pppoe_password="",
    #         mtu=1500
    #
    #     )
    #
    #     Interface.objects.create(
    #         name='narin',
    #         ip_list=[{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
    #         gateway='6.6.6.6',
    #         mode='vlan',
    #         mtu=75,
    #         data=[{"vlan_id": "12", "interface": "eth0"}],
    #         is_enabled=True
    #
    #     )
    #
    #     url = reverse('interface-detail', kwargs={'pk': "narin"})
    #     data = {
    #
    #         'name': 'narin',
    #         'ip_list': [{"ip": "6.6.6.6", "mask": "255.248.0.0"}],
    #         'gateway': '6.6.6.6',
    #         'mode': 'vlan',
    #         'mtu': 75,
    #         'data': [{"vlan_id": "75", "interface": "eth0"}],
    #         'is_enabled': True
    #     }
    #
    #     response = self.client.put(url, data, format='json')
    #     self.assertEquals(response.status_code, status.HTTP_200_OK)
    #     self.assertEquals(Interface.objects.all().count(), 2)


class HighAvailabilityTest(CustomAPITestCase):

    def setUp(self):
        Interface.objects.create(
            name="eth1",
            description="",
            alias="eth1",
            ip_list=[{"ip": "192.168.85.121", "mask": "255.255.255.0"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )
        source = Source.objects.create()
        InputFirewall.objects.create(
            name='HA5',
            is_log_enabled='False',
            is_enabled='True',
            permission='system',
            protocol='tcp',
            port=22,
            service_list=['cli'],
            source=source
        )
        # Setting.objects.create(
        #     key="ssh-port",
        #     data={"value": 22},
        #     display_name="Admin CLI ssh port",
        #     type="number",
        #     category="Access Settings"
        # )

        if not os.path.exists('{}/etc'.format(TEST_PATH)):
            os.system('mkdir -p {}/etc'.format(TEST_PATH))
        if not os.path.exists('{}/etc/rc.local'.format(TEST_PATH)):
            os.system('touch {}/etc/rc.local'.format(TEST_PATH))
        with open('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), 'w+') as commands_file:
            commands_file.write('')

    def tearDown(self):
        HighAvailability.objects.all().delete()
        Setting.objects.all().delete()
        Interface.objects.all().delete()
        cmd = 'rm -rf {}'.format(TEST_PATH)
        os.system(cmd)

    def test_post_ha_enable(self):
        url = reverse('highavailability-list')
        data = {
            "peer1_address": "192.168.85.121",
            "peer2_address": "192.168.85.190",
            "cluster_address_list": [
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            "configured_peer_interface_mac": "eth1#192.168.85.1",
            "is_enabled": True,
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
        expected_commands = 'systemctl enable pcsd.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl enable pacemaker.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl enable corosync.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'service pcsd restart'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        restart_cmd = 'service corosync restart\nservice pacemaker restart'
        expected_rc_local_cmd = 'grep -qxF "{restart_command}" {file} || echo "\n{restart_command}" >> {file}' \
            .format(restart_command=restart_cmd, file=RC_LOCAL_FILE)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_rc_local_cmd))
        expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                       'sudo -S systemctl enable pcsd.service; ' \
                       'sudo -S systemctl enable pacemaker.service;' \
                       'sudo -S systemctl enable corosync.service; ' \
                       'sudo -S service pcsd restart;"'.format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
                                                               ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        restart_cmd = 'service corosync restart\nservice pacemaker restart'
        # expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
        #       'sudo grep -qxF \'{restart_command}\' {file} || sudo echo \'{restart_command}\' >> {file}"' \
        #     .format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
        #             ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd,
        #             file=RC_LOCAL_FILE)
        # self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_auth_cmd = 'pcs cluster auth {peer1} {peer2} -u {user} -p {password}' \
            .format(peer1=data['peer1_address'], peer2=data['peer2_address'], user=HA_USER, password=HA_CLUSTER_PASS)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_auth_cmd))

        expected_cluster_setup_cmd = "pcs cluster setup --name {cluster_name} {peer1} {peer2} --start --force --enable". \
            format(cluster_name=CLUSTER_NAME, peer1=data['peer1_address'], peer2=data['peer2_address'])
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cluster_setup_cmd))
        nic = data['cluster_address_list'][0].get("nic")
        cidr = data['cluster_address_list'][0].get("cidr")
        match_obj = re.search(r'(.*?)/(.*)', cidr)
        cluster_ip = match_obj.group(1)
        cluster_mask = match_obj.group(2)
        clusterip_name = "ClusterIP_{}_{}".format(cluster_ip, cluster_mask)
        expected_cmd = 'pcs resource delete {}'.format(clusterip_name)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = "pcs resource create {} ocf:heartbeat:IPaddr2 ip={} cidr_netmask={} nic={} op monitor interval=30s". \
            format(clusterip_name, cluster_ip, cluster_mask, nic)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        service_list = [{'name': 'dnsmasq', 'type': 'lsb'},
                        {'name': 'ipsec', 'type': 'lsb'},
                        {'name': 'ha_syncer', 'type': 'systemd'}]
        expected_cmd = 'pcs resource delete {}'.format(service_list[0]['name'])
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        for service in service_list:
            expected_cmd = 'pcs resource delete {}'.format(service['name'])
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
            expected_cmd = 'pcs resource create {service_name} {service_type}:{service_name} op monitor interval=30s timeout=60s on-fail=ignore'.format(
                service_name=service['name'], service_type=service['type'])
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
            expected_cmd = 'pcs constraint colocation add {} with {} INFINITY'.format(service['name'], clusterip_name)
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = 'timeout --foreground {duration} scp -P {ssh_port} /tmp/dumpdata.json {user}@{ip}:/tmp/'.format(
            user='ngfw',
            ip=data['peer2_address'],
            ssh_port=ssh_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "/opt/narin/.env/bin/python /opt/narin/api/manage.py syncdata /tmp/dumpdata.json"'.format(
            user='ngfw', ip=data['peer2_address'], ssh_port=ssh_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        self.assertTrue(HighAvailability.objects.filter(status='succeeded').exists())

    def test_post_ha_disable(self):
        url = reverse('highavailability-list')
        data = {
            "peer1_address": "192.168.85.121",
            "peer2_address": "192.168.85.190",
            "cluster_address_list": [
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            "configured_peer_interface_mac": "eth1#192.168.85.1",
            "is_enabled": False,
        }
        sleep(0.5)
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(HighAvailability.objects.filter(status='succeeded').exists())

    # def test_put_ha_succeeded_enable_to_enable(self):
    #     instance = HighAvailability.objects.create(
    #         peer1_address="192.168.85.121",
    #         peer2_address="192.168.85.190",
    #         cluster_address_list=[
    #             "192.168.85.250/24"
    #         ],
    #         is_enabled=True,
    #         status='succeeded'
    #     )
    #     data = {
    #         "peer1_address": "192.168.85.121",
    #         "peer2_address": "192.168.85.185",
    #         "cluster_address_list": [
    #             "192.168.85.230/24"
    #         ],
    #         "is_enabled": True,
    #     }
    #     url = reverse('highavailability-detail', kwargs={'pk': instance.id})
    #     response = self.client.put(url, data, format='json')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     expected_cmd = "pcs cluster stop"
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #     expected_cmd = "pcs cluster destroy --all"
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #     expected_cmd = 'rm /var/lib/pcsd/tokens'
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #     expected_auth_cmd = 'pcs cluster auth {peer1} {peer2} -u {user} -p {password}' \
    #         .format(peer1=data['peer1_address'], peer2=data['peer2_address'], user=HA_USER, password=HA_CLUSTER_PASS)
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_auth_cmd))
    #
    #     expected_cluster_setup_cmd = "pcs cluster setup --name {cluster_name} {peer1} {peer2} --start --force --enable". \
    #         format(cluster_name=CLUSTER_NAME, peer1=data['peer1_address'], peer2=data['peer2_address'])
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cluster_setup_cmd))
    #
    #     match_obj = re.search(r'(.*?)/(.*)', data['cluster_address_list'][0])
    #     cluster_ip = match_obj.group(1)
    #     cluster_mask = match_obj.group(2)
    #     clusterip_name = "ClusterIP_{}_{}".format(cluster_ip, cluster_mask)
    #     expected_cmd = 'pcs resource delete {}'.format(clusterip_name)
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #
    #     expected_cmd = "pcs resource create {} ocf:heartbeat:IPaddr2 ip={} cidr_netmask={} op monitor interval=30s". \
    #         format(clusterip_name, cluster_ip, cluster_mask)
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #
    #     service_list = [{'name': 'dnsmasq', 'type': 'lsb'},
    #                     {'name': 'ipsec', 'type': 'lsb'},
    #                     {'name': 'ha_syncer', 'type': 'systemd'}]
    #     expected_cmd = 'pcs resource delete {}'.format(service_list[0]['name'])
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #     for service in service_list:
    #         expected_cmd = 'pcs resource delete {}'.format(service['name'])
    #         self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #         expected_cmd = 'pcs resource create {service_name} {service_type}:{service_name} op monitor interval=30s timeout=60s on-fail=ignore'.format(
    #             service_name=service['name'], service_type=service['type'])
    #         self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #         expected_cmd = 'pcs constraint colocation add {} with {} INFINITY'.format(service['name'], clusterip_name)
    #         self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #     ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
    #     expected_cmd = 'timeout --foreground {duration} scp -P {ssh_port} /tmp/dumpdata.json {user}@{ip}:/tmp/'.format(
    #         user='ngfw',
    #         ip=data['peer2_address'],
    #         ssh_port=ssh_port,
    #         duration=TIMEOUT_DURATION_FOR_SSH)
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #
    #     expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "/opt/narin/.env/bin/python /opt/narin/api/manage.py syncdata /tmp/dumpdata.json"'.format(
    #         user='ngfw', ip=data['peer2_address'], ssh_port=ssh_port,
    #         duration=TIMEOUT_DURATION_FOR_SSH)
    #     self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
    #
    #     self.assertTrue(HighAvailability.objects.filter(status='succeeded').exists())

    def test_put_ha_failed_enable_to_enable(self):
        instance = HighAvailability.objects.create(
            peer1_address="192.168.85.121",
            peer2_address="192.168.85.190",
            cluster_address_list=[
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            configured_peer_interface_mac="eth1#192.168.85.1",
            is_enabled=True,
            status='failed'
        )
        data = {
            "peer1_address": "192.168.85.121",
            "peer2_address": "192.168.85.185",
            "cluster_address_list": [
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            "configured_peer_interface_mac": "eth1#192.168.85.1",
            "is_enabled": True,
        }
        url = reverse('highavailability-detail', kwargs={'pk': instance.id})
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_cmd = "pcs cluster stop"
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        expected_cmd = "pcs cluster destroy --all"
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        expected_cmd = 'rm /var/lib/pcsd/tokens'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
        expected_commands = 'systemctl enable pcsd.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl enable pacemaker.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl enable corosync.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'service pcsd restart'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        restart_cmd = 'service corosync restart\nservice pacemaker restart'
        expected_rc_local_cmd = 'grep -qxF "{restart_command}" {file} || echo "\n{restart_command}" >> {file}' \
            .format(restart_command=restart_cmd, file=RC_LOCAL_FILE)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_rc_local_cmd))
        expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                       'sudo -S systemctl enable pcsd.service; ' \
                       'sudo -S systemctl enable pacemaker.service;' \
                       'sudo -S systemctl enable corosync.service; ' \
                       'sudo -S service pcsd restart;"'.format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
                                                               ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        # restart_cmd = 'service corosync restart\nservice pacemaker restart'
        # expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
        #          'sudo grep -qxF \'{restart_command}\' {file} || sudo echo \'\n{restart_command}\' >> {file}"' \
        #     .format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
        #             ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd,
        #             file=RC_LOCAL_FILE)
        # self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_auth_cmd = 'pcs cluster auth {peer1} {peer2} -u {user} -p {password}' \
            .format(peer1=data['peer1_address'], peer2=data['peer2_address'], user=HA_USER, password=HA_CLUSTER_PASS)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_auth_cmd))

        expected_cluster_setup_cmd = "pcs cluster setup --name {cluster_name} {peer1} {peer2} --start --force --enable". \
            format(cluster_name=CLUSTER_NAME, peer1=data['peer1_address'], peer2=data['peer2_address'])
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cluster_setup_cmd))
        nic = data['cluster_address_list'][0].get("nic")
        cidr = data['cluster_address_list'][0].get("cidr")
        match_obj = re.search(r'(.*?)/(.*)', cidr)
        cluster_ip = match_obj.group(1)
        cluster_mask = match_obj.group(2)
        clusterip_name = "ClusterIP_{}_{}".format(cluster_ip, cluster_mask)
        expected_cmd = 'pcs resource delete {}'.format(clusterip_name)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = "pcs resource create {} ocf:heartbeat:IPaddr2 ip={} cidr_netmask={} nic={} op monitor interval=30s". \
            format(clusterip_name, cluster_ip, cluster_mask, nic)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        service_list = [{'name': 'dnsmasq', 'type': 'lsb'},
                        {'name': 'ipsec', 'type': 'lsb'},
                        {'name': 'ha_syncer', 'type': 'systemd'}]
        expected_cmd = 'pcs resource delete {}'.format(service_list[0]['name'])
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        for service in service_list:
            expected_cmd = 'pcs resource delete {}'.format(service['name'])
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
            expected_cmd = 'pcs resource create {service_name} {service_type}:{service_name} op monitor interval=30s timeout=60s on-fail=ignore'.format(
                service_name=service['name'], service_type=service['type'])
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
            expected_cmd = 'pcs constraint colocation add {} with {} INFINITY'.format(service['name'], clusterip_name)
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
        expected_cmd = 'timeout --foreground {duration} scp -P {ssh_port} /tmp/dumpdata.json {user}@{ip}:/tmp/'.format(
            user='ngfw',
            ip=data['peer2_address'],
            ssh_port=ssh_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "/opt/narin/.env/bin/python /opt/narin/api/manage.py syncdata /tmp/dumpdata.json"'.format(
            user='ngfw', ip=data['peer2_address'], ssh_port=ssh_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        self.assertTrue(HighAvailability.objects.filter(status='succeeded').exists())

    def test_put_ha_enable_to_disable(self):
        instance = HighAvailability.objects.create(
            peer1_address="192.168.85.121",
            peer2_address="192.168.85.190",
            cluster_address_list=[
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            configured_peer_interface_mac="eth1#192.168.85.1",
            is_enabled=True,
            status='succeeded'
        )
        data = {
            "peer1_address": "192.168.85.121",
            "peer2_address": "192.168.85.185",
            "cluster_address_list": [
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            "configured_peer_interface_mac": "eth1#192.168.85.1",
            "is_enabled": False,
        }
        url = reverse('highavailability-detail', kwargs={'pk': instance.id})
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
        expected_commands = "pcs cluster stop"
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = "pcs cluster destroy --all"
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'rm /var/lib/pcsd/tokens'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl disable pcsd.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl disable pacemaker.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl disable corosync.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'service pcsd stop'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                            'sudo -S systemctl disable pcsd.service; ' \
                            'sudo -S systemctl disable pacemaker.service;' \
                            'sudo -S systemctl disable corosync.service; ' \
                            'sudo -S service pcsd stop;"'.format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
                                                                 ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        restart_cmd = 'service \(corosync\|pacemaker\) restart'
        expected_commands = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                            'sudo -S sed -i \'s/{restart_command}//g\' {file} "' \
            .format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
                    ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd,
                    file=RC_LOCAL_FILE)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        self.assertTrue(HighAvailability.objects.filter(status='succeeded').exists())

    def test_put_ha_disable_to_enable(self):
        instance = HighAvailability.objects.create(
            peer1_address="192.168.85.121",
            peer2_address="192.168.85.190",
            cluster_address_list=[
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            configured_peer_interface_mac="eth1#192.168.85.1",
            is_enabled=False,
            status='succeeded'
        )
        data = {
            "peer1_address": "192.168.85.121",
            "peer2_address": "192.168.85.185",
            "cluster_address_list": [
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            "configured_peer_interface_mac": "eth1#192.168.85.1",
            "is_enabled": True,
        }
        url = reverse('highavailability-detail', kwargs={'pk': instance.id})
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
        expected_commands = 'systemctl enable pcsd.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl enable pacemaker.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl enable corosync.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'service pcsd restart'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        restart_cmd = 'service corosync restart\nservice pacemaker restart'
        expected_rc_local_cmd = 'grep -qxF "{restart_command}" {file} || echo "\n{restart_command}" >> {file}' \
            .format(restart_command=restart_cmd, file=RC_LOCAL_FILE)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_rc_local_cmd))
        expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                       'sudo -S systemctl enable pcsd.service; ' \
                       'sudo -S systemctl enable pacemaker.service;' \
                       'sudo -S systemctl enable corosync.service; ' \
                       'sudo -S service pcsd restart;"'.format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
                                                               ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        restart_cmd = 'service corosync restart\nservice pacemaker restart'
        # expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
        #         'sudo grep -qxF \'{restart_command}\' {file} || sudo echo \'\n{restart_command}\' >> {file}"' \
        #     .format(user='ngfw', ip=data['peer2_address'], passwd='ngfw',
        #             ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd,
        #             file=RC_LOCAL_FILE)
        # self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_auth_cmd = 'pcs cluster auth {peer1} {peer2} -u {user} -p {password}' \
            .format(peer1=data['peer1_address'], peer2=data['peer2_address'], user=HA_USER, password=HA_CLUSTER_PASS)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_auth_cmd))

        expected_cluster_setup_cmd = "pcs cluster setup --name {cluster_name} {peer1} {peer2} --start --force --enable". \
            format(cluster_name=CLUSTER_NAME, peer1=data['peer1_address'], peer2=data['peer2_address'])
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cluster_setup_cmd))
        nic = data['cluster_address_list'][0].get("nic")
        cidr = data['cluster_address_list'][0].get("cidr")
        match_obj = re.search(r'(.*?)/(.*)', cidr)
        cluster_ip = match_obj.group(1)
        cluster_mask = match_obj.group(2)
        clusterip_name = "ClusterIP_{}_{}".format(cluster_ip, cluster_mask)
        expected_cmd = 'pcs resource delete {}'.format(clusterip_name)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = "pcs resource create {} ocf:heartbeat:IPaddr2 ip={} cidr_netmask={} nic={} op monitor interval=30s". \
            format(clusterip_name, cluster_ip, cluster_mask, nic)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        service_list = [{'name': 'dnsmasq', 'type': 'lsb'},
                        {'name': 'ipsec', 'type': 'lsb'},
                        {'name': 'ha_syncer', 'type': 'systemd'}]
        expected_cmd = 'pcs resource delete {}'.format(service_list[0]['name'])
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        for service in service_list:
            expected_cmd = 'pcs resource delete {}'.format(service['name'])
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
            expected_cmd = 'pcs resource create {service_name} {service_type}:{service_name} op monitor interval=30s timeout=60s on-fail=ignore'.format(
                service_name=service['name'], service_type=service['type'])
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
            expected_cmd = 'pcs constraint colocation add {} with {} INFINITY'.format(service['name'], clusterip_name)
            self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = 'timeout --foreground {duration} scp -P {ssh_port} /tmp/dumpdata.json {user}@{ip}:/tmp/'.format(
            user='ngfw',
            ip=data['peer2_address'],
            ssh_port=ssh_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))

        expected_cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "/opt/narin/.env/bin/python /opt/narin/api/manage.py syncdata /tmp/dumpdata.json"'.format(
            user='ngfw', ip=data['peer2_address'], ssh_port=ssh_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_cmd))
        self.assertTrue(HighAvailability.objects.filter(status='succeeded').exists())

    def test_put_ha_enable_to_disable(self):
        instance = HighAvailability.objects.create(
            peer1_address="192.168.85.121",
            peer2_address="192.168.85.190",
            cluster_address_list=[
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            configured_peer_interface_mac="eth1#192.168.85.1",
            is_enabled=False,
            status='succeeded'
        )
        data = {
            "peer1_address": "192.168.85.121",
            "peer2_address": "192.168.85.185",
            "cluster_address_list": [
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            "is_enabled": False,
        }
        url = reverse('highavailability-detail', kwargs={'pk': instance.id})
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(HighAvailability.objects.filter(status='succeeded', peer2_address='192.168.85.185').exists())

    def test_delete_ha(self):
        instance = HighAvailability.objects.create(
            peer1_address="192.168.85.121",
            peer2_address="192.168.85.190",
            cluster_address_list=[
                {"nic": "eth1", "cidr": "192.168.85.250/24"}
            ],
            configured_peer_interface_mac="eth1#192.168.85.1",
            is_enabled=True,
        )
        url = reverse('highavailability-detail', kwargs={'pk': instance.id})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(HighAvailability.objects.filter().exists())
        ssh_port = Setting.objects.filter(key="ssh-port").values_list("data").get()[0]['value']
        https_port = Setting.objects.filter(key="https-port").values_list("data").get()[0]['value']
        expected_commands = "pcs cluster stop"
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = "pcs cluster destroy --all"
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'rm /var/lib/pcsd/tokens'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'timeout --foreground {duration} ssh -t {user}@{ip_address} -p {ssh_port} "curl -X' \
                            ' "DELETE" -k https://127.0.0.1:{https_port}/api/config/highavailability/{id}"'.format(
            user='ngfw',
            ip_address=instance.peer2_address, id=instance.id,
            ssh_port=ssh_port, https_port=https_port,
            duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl disable pcsd.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl disable pacemaker.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'systemctl disable corosync.service'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'service pcsd stop'
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        expected_commands = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                            'sudo -S systemctl disable pcsd.service; ' \
                            'sudo -S systemctl disable pacemaker.service;' \
                            'sudo -S systemctl disable corosync.service; ' \
                            'sudo -S service pcsd stop;"'.format(user='ngfw', ip=instance.peer2_address, passwd='ngfw',
                                                                 ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
        self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
        restart_cmd = 'service \(corosync\|pacemaker\) restart'
        # expected_commands = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
        #       'sudo sed -i \'s/{restart_command}//g\' {file} "' \
        #     .format(user='ngfw', ip=instance.peer2_address, passwd='ngfw',
        #             ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd,
        #             file=RC_LOCAL_FILE)
        # self.assertTrue(check_file_content('{}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), expected_commands))
