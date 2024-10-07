import os

from django.test import TransactionTestCase
from django.urls import reverse
from rest_framework import status

from api.settings import TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD
from entity_app.models import Address
from root_runner.sudo_utils import sudo_file_reader
from utils.config_files import IPSEC_CONF_FILE, IPSEC_SECRETS_FILE, TEST_COMMANDS_FILE, TEST_PATH, GRE_CONFIGS_PATH, \
    IPIP_CONFIGS_PATH, VTUND_CONFIGS_PATH
from utils.test.helpers import CustomAPITestCase, add_test_vpn, add_test_vpn_tunnel_gre, \
    add_test_vpn_tunnel_vtun_server, add_test_vpn_tunnel_ipip, add_test_vpn_tunnel_vtun_client
from vpn_app.models import VPN

username = TEST_ADMIN_USERNAME
password = TEST_ADMIN_PASSWORD


def check_file_content(file, content):
    status, file_content = sudo_file_reader(file)
    if status:
        if content not in file_content:
            return False
        return True


def create_vtun_conf(data):
    virtual_local_endpoint = Address.objects.get(id=data['tunnel']['virtual_local_endpoint']).value_list[0].split("/")[
        0]
    virtual_remote_endpoint = \
        Address.objects.get(id=data['tunnel']['virtual_remote_endpoint']).value_list[0].split("/")[0]
    expected_vtun_conf_text = "options {" + "\n"
    expected_vtun_conf_text += "port " + str(data['tunnel']['service_port']) + "; # Listen on this port\n"
    expected_vtun_conf_text += "#bindaddr { iface lo; };\n"
    expected_vtun_conf_text += "#syslog  local4;\n"
    expected_vtun_conf_text += "#bindaddr { iface lo; };\n"
    expected_vtun_conf_text += "# Path to various programs\n"
    expected_vtun_conf_text += "#ppp         /usr/sbin/pppd;\n"
    expected_vtun_conf_text += "ifconfig         /sbin/ifconfig;\n"
    expected_vtun_conf_text += "#firewall         /sbin/ipchains;\n"
    expected_vtun_conf_text += "#ip         /usr/sbin/ip;\n}\n"
    expected_vtun_conf_text += "# virtual tunnel definition.\n"
    expected_vtun_conf_text += data['name'] + "  {\n"
    expected_vtun_conf_text += "passwd  Secure_G@tEw@y!2O!7;\n"
    expected_vtun_conf_text += "#ppp         /usr/sbin/pppd;\n"
    expected_vtun_conf_text += "type tun;\n"
    expected_vtun_conf_text += "proto " + data['tunnel']['service_protocol'] + ";\n"
    expected_vtun_conf_text += "compress no;\t# Compression is off by default\n"
    expected_vtun_conf_text += "encrypt no;\t# Max Speed by default, No Shaping \n"
    expected_vtun_conf_text += "keepalive yes;\n"
    expected_vtun_conf_text += "speed 0;\n"
    expected_vtun_conf_text += "stat yes;\n"
    expected_vtun_conf_text += "persist yes;\n"
    expected_vtun_conf_text += "multi no;\n"
    expected_vtun_conf_text += "up {\n"
    expected_vtun_conf_text += "\tifconfig " + '"%% ' + \
                               virtual_local_endpoint \
                               + " pointopoint " + virtual_remote_endpoint \
                               + " mtu " + str(data['tunnel']['mtu']) + '"' + ";\n"
    expected_vtun_conf_text += "};\n"
    expected_vtun_conf_text += "down {\n"
    expected_vtun_conf_text += "ifconfig " + '"%% ' + 'down ";\n'
    expected_vtun_conf_text += "};\n}"

    return expected_vtun_conf_text


def create_tunnel_config(data):
    Local_pub_key_path = ""
    Peer_pub_key = ""
    auth_by = "psk"
    if data['authentication_method'] == "RSA":
        auth_by = "rsasig"
    dhg_trans = {
        '1': 'modp768',
        '2': 'modp1024',
        '5': 'modp1536',
        '14': 'modp2048',
        '15': 'modp3072',
        '16': 'modp4096'
    }
    # if data['phase2_encryption_algorithm'] == 'paya256':
    #     data['phase2_encryption_algorithm'] = 'camellia256'
    ike = data['phase1_encryption_algorithm'] + "-" + data['phase1_authentication_algorithm'] + "-" + dhg_trans[
        data['phase1_diffie_hellman_group']] + "!"
    esp = data['phase2_encryption_algorithm'] + "-" + data['phase2_authentication_algorithm'] + "-" + dhg_trans[
        data['phase2_diffie_hellman_group']] + "!"
    local_network_list = []
    for localN in data['local_network']:
        add = Address.objects.get(id=localN)
        for value in add.value_list:
            local_network_list.append(value)

    remote_network_list = []
    for remoteN in data['remote_network']:
        add = Address.objects.get(id=remoteN)
        for value in add.value_list:
            remote_network_list.append(value)

    local_endpoint = Address.objects.get(id=data['local_endpoint']).value_list[0].split("/")[0]
    remote_endpoint = Address.objects.get(id=data['remote_endpoint']).value_list[0].split("/")[0]

    tunnel_conf_text = "\n\nconn " + data['name'] + " \n"
    tunnel_conf_text += "\tauthby=\"" + auth_by + "\"\n"
    tunnel_conf_text += "\tauto=\"start\"\n"
    tunnel_conf_text += "\ttype=\"tunnel\"\n"
    tunnel_conf_text += "\tcompress=\"no\"\n"
    tunnel_conf_text += "\trekeymargin=\"540s\"\n"
    tunnel_conf_text += "\tleft=\"" + local_endpoint + "\"\n"
    tunnel_conf_text += "\tleftsubnet=\"" + ",".join(local_network_list) + "\"\n"
    tunnel_conf_text += "\tright=\"" + remote_endpoint + "\"\n"
    tunnel_conf_text += "\trightsubnet=\"" + ",".join(remote_network_list) + "\"\n"
    tunnel_conf_text += "\tike=\"" + ike + "\"\n"
    tunnel_conf_text += "\tesp=\"" + esp + "\"\n"
    tunnel_conf_text += "\tikelifetime=\"" + str(int(data['phase1_lifetime']) * 3600) + "\"\n"
    tunnel_conf_text += "\tkeylife=\"" + str(int(data['phase2_lifetime']) * 3600) + "\"\n"

    if data['authentication_method'] == 'preshared':
        tunnel_conf_text += "\tleftid=\"" + data['local_id'] + "\"\n"
        tunnel_conf_text += "\trightid=\"" + data['peer_id'] + "\"\n"

    if data['authentication_method'] == "RSA":
        tunnel_conf_text += "\tleftcert=" + 'cert_' + data['certificate'].name + '.crt' + "\n"
        tunnel_conf_text += "\tleftid=\"" + data['local_id'] + "\"\n"
        tunnel_conf_text += "\trightid=\"" + data['peer_id'] + "\"\n"

    tunnel_conf_text += "\tkeyexchange=\"ikev2\"\n"
    if data['dpd']:
        dpd_timeout = "900"
        tunnel_conf_text += "\tdpdaction = \"restart\"\n"
        tunnel_conf_text += "\tdpddelay = \"30s\"\n"
        tunnel_conf_text += "\tdpdtimeout = \"" + dpd_timeout + "s\"\n"
    return tunnel_conf_text


class VPNTest(CustomAPITestCase):
    fixtures = ['entity_app/fixtures/test_entity.json', 'config_app/fixtures/initial_data.json']

    def tearDown(self):
        import os
        VPN.objects.all().delete()
        cmd = 'rm -rf {}'.format(TEST_PATH)
        os.system(cmd)

    def test_post_vpn(self):
        url = reverse('site-to-site-list')
        data = {
            "name": "vpn_post",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 1,
            "local_id": "loc_pos",
            "remote_endpoint": 12,
            "peer_id": "peer_pos",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')

        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])

        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_vpn_wrong_endpoint(self):
        url = reverse('site-to-site-list')
        data = {
            "name": "vpn_post",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 4,
            "local_id": "loc_pos",
            "remote_endpoint": 13,
            "peer_id": "peer_pos",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_vpn_gre_tunnel(self):
        url = reverse('site-to-site-list')

        data = {
            "tunnel": {
                "type": "gre",
                "virtual_local_endpoint": 15,
                "virtual_remote_endpoint": 16,
                "mtu": 1500,
                "mode": None,
                "server_endpoint": None,
                "service_protocol": None,
                "service_port": None,
                "real_local_endpoint": 13,
                "real_remote_endpoint": 14
            },
            "name": "vpn_test2",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 17,
            "local_id": "qabc3",
            "remote_endpoint": 12,
            "peer_id": "qabc4",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        real_remote_endpoint = Address.objects.get(id=data['tunnel']['real_remote_endpoint']).value_list[0].split("/")[
            0]
        real_local_endpoint = Address.objects.get(id=data['tunnel']['real_local_endpoint']).value_list[0].split("/")[0]
        virtual_local_endpoint = \
            Address.objects.get(id=data['tunnel']['virtual_local_endpoint']).value_list[0].split("/")[0]
        gre_config_file = '{}{}/gre_tun.conf'.format(GRE_CONFIGS_PATH, data['name'])
        expected_gre_config = '#!/bin/bash\n'
        expected_gre_config += 'modprobe ip_gre \n'
        expected_gre_config += "INF=': ' read -r -a result <<< `ip tunnel show | grep 'remote {}[ ]\+local {}'`\n". \
            format(real_remote_endpoint, real_local_endpoint)
        expected_gre_config += 'if [ "X${result[0]::-1}" != "X" ]; then sudo ip tunnel del ${result[0]::-1}; fi\n'
        expected_gre_config += 'ip tunnel add ' + data['name'] + ' mode gre remote ' + \
                               str(real_remote_endpoint) + ' local ' + str(
            real_local_endpoint) + ' ttl 255\n'
        expected_gre_config += 'ip link set ' + data['name'] + ' up' + '\n'
        expected_gre_config += 'ip addr add ' + str(virtual_local_endpoint) + '/24 dev ' + data[
            'name'] + '\n'
        expected_gre_config += 'ifconfig ' + data['name'] + ' mtu ' + str(data['tunnel']['mtu']) + ' up\n'
        self.assertTrue(
            check_file_content(gre_config_file, expected_gre_config))

        expected_commands = 'bash {}'.format(gre_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -A gre_chain -s ' + str(
            real_remote_endpoint) + ' -m comment --comment ' + data['name'] + ' -j ACCEPT'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S gre_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_vpn_ipip_tunnel(self):
        url = reverse('site-to-site-list')

        data = {
            "tunnel": {
                "type": "ipip",
                "virtual_local_endpoint": 15,
                "virtual_remote_endpoint": 16,
                "mtu": 1500,
                "mode": None,
                "server_endpoint": None,
                "service_protocol": None,
                "service_port": None,
                "real_local_endpoint": 13,
                "real_remote_endpoint": 14
            },
            "name": "vpn_test3",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 17,
            "local_id": "loc",
            "remote_endpoint": 12,
            "peer_id": "peer",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')

        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))
        real_local_endpoint = Address.objects.get(id=data['tunnel']['real_local_endpoint']).value_list[0].split("/")[0]
        real_remote_endpoint = Address.objects.get(id=data['tunnel']['real_remote_endpoint']).value_list[0].split("/")[
            0]
        virtual_local_endpoint = \
            Address.objects.get(id=data['tunnel']['virtual_local_endpoint']).value_list[0].split("/")[0]
        ipip_config_file = '{}{}/ipip_tun.conf'.format(IPIP_CONFIGS_PATH, data['name'])
        expected_ipip_config = "#!/bin/bash\n"
        expected_ipip_config += "modprobe ip_gre \n"
        expected_ipip_config += "ip tunnel add " + data['name'] + " mode ipip remote " + \
                                str(real_remote_endpoint) + " local " + \
                                str(real_local_endpoint) + " ttl 255\n"
        expected_ipip_config += "ip link set " + data['name'] + " up" + "\n"
        expected_ipip_config += "ip addr add " + str(virtual_local_endpoint) + "/24 dev " + \
                                data['name'] + "\n"
        expected_ipip_config += "ifconfig " + data['name'] + " mtu " + str(data['tunnel']['mtu']) + " up\n"
        self.assertTrue(
            check_file_content(ipip_config_file, expected_ipip_config))

        expected_commands = 'sh {}'.format(ipip_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -A ipip_chain -s ' + str(
            real_remote_endpoint) + ' -m comment --comment ' + data['name'] + ' -j ACCEPT'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S ipip_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_vpn_vtun_tunnel_client(self):
        url = reverse('site-to-site-list')

        data = {
            "tunnel": {
                "type": "vtun",
                "virtual_local_endpoint": 12,
                "virtual_remote_endpoint": 14,
                "mtu": 1500,
                "mode": "client",
                "server_endpoint": 13,
                "service_protocol": "tcp",
                "service_port": 20,
                "real_local_endpoint": 1,
                "real_remote_endpoint": 15
            },
            "name": "vpn_test4",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 16,
            "local_id": "esf",
            "remote_endpoint": 17,
            "peer_id": "teh",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        vtun_config_file = '{}client/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, data['name'])
        expected_vtun_conf_text = create_vtun_conf(data)
        self.assertTrue(
            check_file_content(vtun_config_file, expected_vtun_conf_text))

        server_endpoint = Address.objects.get(id=data['tunnel']['server_endpoint']).value_list[0].split("/")[0]
        expected_commands = 'vtund -f {path}client/{name}/vtund.conf {name} {endpoint}'.format(path=VTUND_CONFIGS_PATH,
                                                                                               name=data['name'],
                                                                                               endpoint=server_endpoint)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -I vtun_chain -p tcp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_iptables_rule = 'iptables -S vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_vpn_vtun_tunnel_client_without_server(self):
        url = reverse('site-to-site-list')

        data = {
            "tunnel": {
                "type": "vtun",
                "virtual_local_endpoint": 12,
                "virtual_remote_endpoint": 13,
                "mtu": 1500,
                "mode": "client",
                "server_endpoint": None,
                "service_protocol": "tcp",
                "service_port": 20,
                "real_local_endpoint": 17,
                "real_remote_endpoint": 15
            },
            "name": "vpn_test4",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 16,
            "local_id": "esf",
            "remote_endpoint": 14,
            "peer_id": "teh",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_post_vpn_vtun_tunnel_server_tcp(self):
        url = reverse('site-to-site-list')

        data = {
            "tunnel": {
                "type": "vtun",
                "virtual_local_endpoint": 12,
                "virtual_remote_endpoint": 13,
                "mtu": 1500,
                "mode": "server",
                "server_endpoint": None,
                "service_protocol": "tcp",
                "service_port": 20,
                "real_local_endpoint": 14,
                "real_remote_endpoint": 15
            },
            "name": "vpn_test5",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 16,
            "local_id": "esf1",
            "remote_endpoint": 17,
            "peer_id": "teh1",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')

        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        vtun_config_file = '{}server/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, data['name'])
        expected_vtun_conf_text = create_vtun_conf(data)
        self.assertTrue(
            check_file_content(vtun_config_file, expected_vtun_conf_text))

        expected_commands = 'vtund -s -f {}'.format(vtun_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -I vtun_chain -p tcp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -I vtun_chain -p udp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertFalse(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_vpn_vtun_tunnel_server_udp(self):
        url = reverse('site-to-site-list')

        data = {
            "tunnel": {
                "type": "vtun",
                "virtual_local_endpoint": 17,
                "virtual_remote_endpoint": 16,
                "mtu": 1500,
                "mode": "server",
                "server_endpoint": None,
                "service_protocol": "udp",
                "service_port": 20,
                "real_local_endpoint": 15,
                "real_remote_endpoint": 14
            },
            "name": "vpn_test5",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 13,
            "local_id": "esf1",
            "remote_endpoint": 12,
            "peer_id": "teh1",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        response = self.client.post(url, data, format='json')

        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        vtun_config_file = '{}server/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, data['name'])
        expected_vtun_conf_text = create_vtun_conf(data)
        self.assertTrue(
            check_file_content(vtun_config_file, expected_vtun_conf_text))

        expected_commands = 'vtund -s -f {}'.format(vtun_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -I vtun_chain -p tcp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -I vtun_chain -p udp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_put_vpn(self):
        old_vpn_instance, old_data = add_test_vpn()
        data = {
            "name": "testee",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 13,
            "local_id": "esf2e",
            "remote_endpoint": 14,
            "peer_id": "teh2e",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [15]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))
        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        expected_command = 'ipsec down {}'.format(old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

    def test_put_vpn_gre_to_vtun(self):
        old_vpn_instance, old_data = add_test_vpn_tunnel_gre()
        data = {
            "tunnel": {
                "type": "vtun",
                "virtual_local_endpoint": 1,
                "virtual_remote_endpoint": 12,
                "mtu": 1500,
                "mode": "server",
                "server_endpoint": None,
                "service_protocol": "udp",
                "service_port": 20,
                "real_local_endpoint": 13,
                "real_remote_endpoint": 14
            },
            "name": "vpn_test5",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 15,
            "local_id": "esf1",
            "remote_endpoint": 16,
            "peer_id": "teh1",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_vpn_gre_to_ipip(self):
        old_vpn_instance, old_data = add_test_vpn_tunnel_gre()
        data = {
            "tunnel": {
                "type": "ipip",
                "virtual_local_endpoint": 12,
                "virtual_remote_endpoint": 13,
                "mtu": 1500,
                "mode": None,
                "server_endpoint": None,
                "service_protocol": None,
                "service_port": None,
                "real_local_endpoint": 14,
                "real_remote_endpoint": 15
            },
            "name": "vpn_test_ipip",
            "description": "test ipip tunnel",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 100,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 200,
            "local_endpoint": 16,
            "local_id": "loc_ccc",
            "remote_endpoint": 17,
            "peer_id": "peer_pppp",
            "authentication_method": "preshared",
            "preshared_key": "123wewewegggqwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        expected_command = 'ip link set {old_name} down\nip tunnel del {old_name}'.format(
            old_name=old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, GRE_CONFIGS_PATH, old_vpn_instance.name)))
        self.assertTrue(os.path.exists('{}{}{}'.format(TEST_PATH, IPIP_CONFIGS_PATH, data['name'])))

        expected_iptables_rule = 'iptables -D gre_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        virtual_local_endpoint = \
            Address.objects.get(id=data['tunnel']['virtual_local_endpoint']).value_list[0].split("/")[
                0]
        real_remote_endpoint = \
            Address.objects.get(id=data['tunnel']['real_remote_endpoint']).value_list[0].split("/")[
                0]
        real_local_endpoint = \
            Address.objects.get(id=data['tunnel']['real_local_endpoint']).value_list[0].split("/")[
                0]
        ipip_config_file = '{}{}/ipip_tun.conf'.format(IPIP_CONFIGS_PATH, data['name'])
        expected_ipip_config = "#!/bin/bash\n"
        expected_ipip_config += "modprobe ip_gre \n"
        expected_ipip_config += "ip tunnel add " + data['name'] + " mode ipip remote " + \
                                str(real_remote_endpoint) + " local " + \
                                str(real_local_endpoint) + " ttl 255\n"
        expected_ipip_config += "ip link set " + data['name'] + " up" + "\n"
        expected_ipip_config += "ip addr add " + str(virtual_local_endpoint) + "/24 dev " + \
                                data['name'] + "\n"
        expected_ipip_config += "ifconfig " + data['name'] + " mtu " + str(data['tunnel']['mtu']) + " up\n"
        self.assertTrue(
            check_file_content(ipip_config_file, expected_ipip_config))

        expected_commands = 'sh {}'.format(ipip_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -A ipip_chain -s ' + str(
            real_remote_endpoint) + ' -m comment --comment ' + data['name'] + ' -j ACCEPT'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S ipip_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

    def test_put_vpn_gre_to_gre(self):
        old_vpn_instance, old_data = add_test_vpn_tunnel_gre()
        data = {
            "tunnel": {
                "type": "gre",
                "virtual_local_endpoint": 1,
                "virtual_remote_endpoint": 12,
                "mtu": 1500,
                "mode": None,
                "server_endpoint": None,
                "service_protocol": None,
                "service_port": None,
                "real_local_endpoint": 13,
                "real_remote_endpoint": 14
            },
            "name": "vpn_test_gre",
            "description": "test gre tunnel",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 100,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 200,
            "local_endpoint": 15,
            "local_id": "loc_ccc",
            "remote_endpoint": 16,
            "peer_id": "peer_pppp",
            "authentication_method": "preshared",
            "preshared_key": "123wewewegggqwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        expected_command = 'ip link set {old_name} down\nip tunnel del {old_name}'.format(
            old_name=old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, GRE_CONFIGS_PATH, old_vpn_instance.name)))
        self.assertTrue(os.path.exists('{}{}{}'.format(TEST_PATH, GRE_CONFIGS_PATH, data['name'])))

        expected_iptables_rule = 'iptables -D gre_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        virtual_local_endpoint = \
            Address.objects.get(id=data['tunnel']['virtual_local_endpoint']).value_list[0].split("/")[
                0]
        real_remote_endpoint = \
            Address.objects.get(id=data['tunnel']['real_remote_endpoint']).value_list[0].split("/")[
                0]
        real_local_endpoint = \
            Address.objects.get(id=data['tunnel']['real_local_endpoint']).value_list[0].split("/")[
                0]
        gre_config_file = '{}{}/gre_tun.conf'.format(GRE_CONFIGS_PATH, data['name'])
        expected_gre_config = '#!/bin/bash\n'
        expected_gre_config += 'modprobe ip_gre \n'
        expected_gre_config += "INF=': ' read -r -a result <<< `ip tunnel show | grep 'remote {}[ ]\+local {}'`\n". \
            format(real_remote_endpoint, real_local_endpoint)
        expected_gre_config += 'if [ "X${result[0]::-1}" != "X" ]; then sudo ip tunnel del ${result[0]::-1}; fi\n'
        expected_gre_config += 'ip tunnel add ' + data['name'] + ' mode gre remote ' + \
                               str(real_remote_endpoint) + ' local ' + str(
            real_local_endpoint) + ' ttl 255\n'
        expected_gre_config += 'ip link set ' + data['name'] + ' up' + '\n'
        expected_gre_config += 'ip addr add ' + str(virtual_local_endpoint) + '/24 dev ' + data[
            'name'] + '\n'
        expected_gre_config += 'ifconfig ' + data['name'] + ' mtu ' + str(data['tunnel']['mtu']) + ' up\n'
        self.assertTrue(
            check_file_content(gre_config_file, expected_gre_config))

        expected_commands = 'bash {}'.format(gre_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -A gre_chain -s ' + str(
            real_remote_endpoint) + ' -m comment --comment ' + data['name'] + ' -j ACCEPT'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S gre_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

    def test_put_vpn_without_tunnel_to_ipip(self):
        old_vpn_instance, old_data = add_test_vpn()
        data = {
            "tunnel": {
                "type": "ipip",
                "virtual_local_endpoint": 12,
                "virtual_remote_endpoint": 13,
                "mtu": 1500,
                "mode": None,
                "server_endpoint": None,
                "service_protocol": None,
                "service_port": None,
                "real_local_endpoint": 14,
                "real_remote_endpoint": 16
            },
            "name": "vpn_test_ipip",
            "description": "test ipip tunnel",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 100,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 200,
            "local_endpoint": 15,
            "local_id": "loc_ccc",
            "remote_endpoint": 17,
            "peer_id": "peer_pppp",
            "authentication_method": "preshared",
            "preshared_key": "123wewewegggqwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        self.assertTrue(os.path.exists('{}{}{}'.format(TEST_PATH, IPIP_CONFIGS_PATH, data['name'])))

        real_local_endpoint = \
            Address.objects.get(id=data['tunnel']['real_local_endpoint']).value_list[0].split("/")[
                0]
        real_remote_endpoint = \
            Address.objects.get(id=data['tunnel']['real_remote_endpoint']).value_list[0].split("/")[
                0]
        virtual_local_endpoint = \
            Address.objects.get(id=data['tunnel']['virtual_local_endpoint']).value_list[0].split("/")[
                0]
        ipip_config_file = '{}{}/ipip_tun.conf'.format(IPIP_CONFIGS_PATH, data['name'])
        expected_ipip_config = "#!/bin/bash\n"
        expected_ipip_config += "modprobe ip_gre \n"
        expected_ipip_config += "ip tunnel add " + data['name'] + " mode ipip remote " + \
                                str(real_remote_endpoint) + " local " + \
                                str(real_local_endpoint) + " ttl 255\n"
        expected_ipip_config += "ip link set " + data['name'] + " up" + "\n"
        expected_ipip_config += "ip addr add " + str(virtual_local_endpoint) + "/24 dev " + \
                                data['name'] + "\n"
        expected_ipip_config += "ifconfig " + data['name'] + " mtu " + str(data['tunnel']['mtu']) + " up\n"
        self.assertTrue(
            check_file_content(ipip_config_file, expected_ipip_config))

        expected_commands = 'sh {}'.format(ipip_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -A ipip_chain -s ' + str(
            real_remote_endpoint) + ' -m comment --comment ' + data['name'] + ' -j ACCEPT'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S ipip_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_vpn_without_tunnel_to_vtun(self):
        old_vpn_instance, old_data = add_test_vpn()
        data = {
            "tunnel": {
                "type": "vtun",
                "virtual_local_endpoint": 12,
                "virtual_remote_endpoint": 13,
                "mtu": 1500,
                "mode": "server",
                "server_endpoint": None,
                "service_protocol": "udp",
                "service_port": 20,
                "real_local_endpoint": 14,
                "real_remote_endpoint": 16
            },
            "name": "vpn_test5",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 17,
            "local_id": "esf1",
            "remote_endpoint": 15,
            "peer_id": "teh1",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        vtun_config_file = '{}server/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, data['name'])
        expected_vtun_conf_text = create_vtun_conf(data)
        self.assertTrue(
            check_file_content(vtun_config_file, expected_vtun_conf_text))

        expected_commands = 'vtund -s -f {}'.format(vtun_config_file)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_commands))

        expected_iptables_rule = 'iptables -I vtun_chain -p tcp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -I vtun_chain -p udp --dport ' + str(
            data['tunnel']['service_port']) + ' -j ACCEPT -m comment --comment ' + data['name']
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))
        expected_iptables_rule = 'iptables -S vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_vpn_gre_to_without_tunnel(self):
        old_vpn_instance, old_data = add_test_vpn_tunnel_gre()
        data = {
            "name": "vpn_post",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 12,
            "local_id": "loc_pos",
            "remote_endpoint": 13,
            "peer_id": "peer_pos",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        expected_command = 'ip link set {old_name} down\nip tunnel del {old_name}'.format(
            old_name=old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, GRE_CONFIGS_PATH, old_vpn_instance.name)))

        expected_iptables_rule = 'iptables -D gre_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_vpn_vtun_to_without_tunnel(self):
        old_vpn_instance, old_data = add_test_vpn_tunnel_vtun_server()
        data = {
            "name": "vpn_post",
            "description": "test",
            "is_enabled": True,
            "phase1_encryption_algorithm": "3des",
            "phase1_authentication_algorithm": "md5",
            "phase1_diffie_hellman_group": "2",
            "phase1_lifetime": 10,
            "phase2_encryption_algorithm": "3des",
            "phase2_authentication_algorithm": "md5",
            "phase2_diffie_hellman_group": "2",
            "phase2_lifetime": 2,
            "local_endpoint": 14,
            "local_id": "loc_pos",
            "remote_endpoint": 15,
            "peer_id": "peer_pos",
            "authentication_method": "preshared",
            "preshared_key": "123qwe!",
            "dpd": False,
            "local_network": [1],
            "remote_network": [2]
        }
        url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
        response = self.client.put(url, data, format='json')
        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=old_vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
        expected_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=data['local_id'], peer_id=data['peer_id'],
                   preshared_key=data['preshared_key'], name=data['name'])
        self.assertTrue(check_file_content(IPSEC_SECRETS_FILE, expected_secret))

        former_tunnel_config = create_tunnel_config(old_data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
        expected_tunnel_config = create_tunnel_config(data)
        self.assertTrue(check_file_content(IPSEC_CONF_FILE, expected_tunnel_config))

        self.assertFalse(os.path.exists('{}{}server/{}'.format(TEST_PATH, VTUND_CONFIGS_PATH, old_vpn_instance.name)))

        expected_iptables_rule = 'iptables -D vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(old_vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class VPNTest2(TransactionTestCase):
    fixtures = ['entity_app/fixtures/test_entity.json', 'config_app/fixtures/initial_data.json']

    def test_delete_vpn(self):
        vpn_instance, data = add_test_vpn()
        url = reverse('site-to-site-detail', kwargs={'pk': vpn_instance.id})
        try:

            response = self.client.delete(url, data, format='json')
        except:
            pass

        self.assertEqual(VPN.objects.filter(id=vpn_instance.id).count(), 0)

        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=vpn_instance.local_id, peer_id=vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))

        former_tunnel_config = create_tunnel_config(data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))

        expected_command = 'ipsec down {}'.format(vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_vpn_gre(self):
        vpn_instance, data = add_test_vpn_tunnel_gre()
        url = reverse('site-to-site-detail', kwargs={'pk': vpn_instance.id})
        response = self.client.delete(url, data, format='json')

        self.assertEqual(VPN.objects.filter(id=vpn_instance.id).count(), 0)

        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=vpn_instance.local_id, peer_id=vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))

        former_tunnel_config = create_tunnel_config(data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))

        expected_command = 'ip link set {old_name} down\nip tunnel del {old_name}'.format(
            old_name=vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, GRE_CONFIGS_PATH, vpn_instance.name)))

        expected_iptables_rule = 'iptables -D gre_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_vpn_ipip(self):
        vpn_instance, data = add_test_vpn_tunnel_ipip()
        url = reverse('site-to-site-detail', kwargs={'pk': vpn_instance.id})
        response = self.client.delete(url, data, format='json')

        self.assertEqual(VPN.objects.filter(id=vpn_instance.id).count(), 0)

        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=vpn_instance.local_id, peer_id=vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))

        former_tunnel_config = create_tunnel_config(data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))

        expected_command = 'ip link set {old_name} down\nip tunnel del {old_name}'.format(
            old_name=vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, IPIP_CONFIGS_PATH, vpn_instance.name)))

        expected_iptables_rule = 'iptables -D ipip_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_vpn_vtun_server(self):
        vpn_instance, data = add_test_vpn_tunnel_vtun_server()
        # add_test_vpn_tunnel_vtun_server2()
        url = reverse('site-to-site-detail', kwargs={'pk': vpn_instance.id})
        response = self.client.delete(url, data, format='json')

        self.assertEqual(VPN.objects.filter(id=vpn_instance.id).count(), 0)

        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=vpn_instance.local_id, peer_id=vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))

        former_tunnel_config = create_tunnel_config(data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))

        expected_command = 'kill -9'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, VTUND_CONFIGS_PATH, vpn_instance.name)))

        expected_iptables_rule = 'iptables -D vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_vpn_vtun_client(self):
        vpn_instance, data = add_test_vpn_tunnel_vtun_client()
        url = reverse('site-to-site-detail', kwargs={'pk': vpn_instance.id})
        response = self.client.delete(url, data, format='json')

        self.assertEqual(VPN.objects.filter(id=vpn_instance.id).count(), 0)

        former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
            format(local_id=vpn_instance.local_id, peer_id=vpn_instance.peer_id,
                   preshared_key=data['preshared_key'], name=vpn_instance.name)
        self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))

        former_tunnel_config = create_tunnel_config(data)
        self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))

        expected_command = 'kill -9'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertFalse(os.path.exists('{}{}{}'.format(TEST_PATH, VTUND_CONFIGS_PATH, vpn_instance.name)))

        expected_iptables_rule = 'iptables -D vtun_chain'
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_iptables_rule))

        expected_command = 'ipsec down {}'.format(vpn_instance.name)
        self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    # def test_put_vpn_enable_to_disable(self):
    #     old_vpn_instance, old_data = add_test_vpn()
    #     data = {
    #         "name": "test2",
    #         "description": "test",
    #         "is_enabled": False,
    #         "phase1_encryption_algorithm": "3des",
    #         "phase1_authentication_algorithm": "md5",
    #         "phase1_diffie_hellman_group": "1",
    #         "phase1_lifetime": 10,
    #         "phase2_encryption_algorithm": "3des",
    #         "phase2_authentication_algorithm": "md5",
    #         "phase2_diffie_hellman_group": "2",
    #         "phase2_lifetime": 2,
    #         "local_endpoint": 13,
    #         "local_id": "esf2",
    #         "remote_endpoint": 12,
    #         "peer_id": "teh2",
    #         "authentication_method": "preshared",
    #         "preshared_key": "123qwe!",
    #         "dpd": False,
    #         "local_network": [1],
    #         "remote_network": [2]
    #     }
    #
    #     url = reverse('site-to-site-detail', kwargs={'pk': old_vpn_instance.id})
    #     response = self.client.put(url, data, format='json')
    #
    #     former_secret = '{local_id} {peer_id}  : PSK "{preshared_key}"   #{name}'. \
    #         format(local_id=old_vpn_instance.local_id, peer_id=old_vpn_instance.peer_id,
    #                preshared_key=data['preshared_key'], name=old_vpn_instance.name)
    #     self.assertFalse(check_file_content(IPSEC_SECRETS_FILE, former_secret))
    #
    #     former_tunnel_config = create_tunnel_config(old_data)
    #     self.assertFalse(check_file_content(IPSEC_CONF_FILE, former_tunnel_config))
    #
    #     expected_command = 'ipsec down {}'.format(old_vpn_instance.name)
    #     self.assertTrue(check_file_content(TEST_COMMANDS_FILE, expected_command))
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
