from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APITransactionTestCase

from auth_app.models import Token
from config_app.models import Interface
from config_app.serializers import LogServerSerializer, StaticRouteWriteSerializer
from config_app.utils import create_rsyslog_server_config_for_ip_address
from entity_app.serializers import AddressSerializer
from firewall_app.serializers import PolicySerializer
from utils.config_files import TEST_PATH, RSYSLOG_CONFIG_FILE, NTP_CONFIG_FILE, DNSMASQ_CONFIG_FILE
from vpn_app.serializers import VPNWriteSerializer


class CustomAPITestCase(APITestCase):
    def setUp(self):
        user = User.objects.create(username='admin', is_staff=True, is_superuser=True)
        token = Token.objects.create(user=user, ip='127.0.0.1').key
        self.client.defaults['HTTP_AUTHORIZATION'] = 'Token {}'.format(token)


class CustomAPITransactionTestCase(APITransactionTestCase):
    def setUp(self):
        user = User.objects.create(username='admin', is_staff=True, is_superuser=True)
        token = Token.objects.create(user=user, ip='127.0.0.1').key
        self.client.defaults['HTTP_AUTHORIZATION'] = 'Token {}'.format(token)


def add_test_policy_for_policy_order(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [],
            'dst_network_list': [1],
            'service_list': [],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [],
            'dst_interface_list': []
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy_disable(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [1, 5],
            'dst_network_list': [3],
            'service_list': [5],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [1],
            'dst_interface_list': [2, 1]
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': False,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy_log(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [1, 5],
            'dst_network_list': [3],
            'service_list': [5],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [1],
            'dst_interface_list': [2, 1]
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': False,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [1, 5],
            'dst_network_list': [3],
            'service_list': [5],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [1],
            'dst_interface_list': [2, 1]
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy_with_snat_interfaceIp(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [1, 5],
            'dst_network_list': [3],
            'service_list': [5],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [],
            'dst_interface_list': [2, 1]
        },
        "nat": {
            "nat_type": "SNAT",
            "snat_type": "interface_ip",
            "is_enabled": True
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy_with_snat_staticIp(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [1, 5],
            'dst_network_list': [3],
            'service_list': [5],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [],
            'dst_interface_list': [2, 1]
        },
        "nat": {
            "nat_type": "SNAT",
            "snat_type": "static_ip",
            "ip": "50.0.50.2",
            "port_list": [4000],
            "is_enabled": True
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy_with_dnat(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [1, 5],
            'dst_network_list': [3],
            'service_list': [5],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [],
            'dst_interface_list': [2, 1]
        },
        "nat": {
            "nat_type": "DNAT",
            "ip": "50.0.50.2",
            "port_list": [4000],
            "is_enabled": True
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_policy_only_service(action='accept', name='pol1', next_policy=None):
    data = {
        'source_destination': {
            'src_network_list': [],
            'dst_network_list': [],
            'service_list': [3],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [],
            'dst_interface_list': []
        },
        'action': action,
        'name': name,
        'next_policy': next_policy,
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    serializer = PolicySerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance


def add_test_rsyslog_server_1():
    data = {
        'is_enabled': True,
        'address': '13.12.10.9',
        'port': 2569,
        'protocol': 'udp',
        'service_list': ['vpn', 'firewall'],
        'is_secure': False
    }

    serializer = LogServerSerializer(data=data)
    assert serializer.is_valid()
    instance = serializer.save()

    old_config_rgx = create_rsyslog_server_config_for_test(
        data['address'], data['port'], data['protocol'], data['is_secure'], "firewall", "vpn")

    with open('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE)) as f:
        if not old_config_rgx in f.read():
            raise Exception('no config in {}'.format(RSYSLOG_CONFIG_FILE))

    return instance


def add_test_rsyslog_server_2():
    data = {
        'is_enabled': False,
        'address': '13.13.13.13',
        'port': 1369,
        'protocol': 'tcp',
        'service_list': ['vpn', 'ssh'],
        'is_secure': False
    }

    serializer = LogServerSerializer(data=data)
    assert serializer.is_valid()
    instance = serializer.save()

    old_config_rgx = create_rsyslog_server_config_for_test(
        data['address'], data['port'], data['protocol'], data['is_secure'], "ssh", "vpn")

    with open('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE)) as f:
        if old_config_rgx in f.read():
            raise Exception('exist config in {}'.format(RSYSLOG_CONFIG_FILE))

    return instance


def add_test_address():
    data = {
        "name": "aaaa1",
        "description": "desc",
        "type": "ip",
        "value_list": [
            "111.12.1.11"
        ],
        "is_user_defined": True
    }

    serializer = AddressSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn():
    data = {
        "name": "testvpn",
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
        "local_id": "local_id",
        "remote_endpoint": 12,
        "peer_id": "peer_id",
        "authentication_method": "preshared",
        "preshared_key": "123qwe!",
        "dpd": False,
        "local_network": [1],
        "remote_network": [2]
    }

    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn2():
    data = {
        "name": "testvpn",
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
        "local_id": "local_id",
        "remote_endpoint": 3,
        "peer_id": "peer_id",
        "authentication_method": "preshared",
        "preshared_key": "123qwe!",
        "dpd": False,
        "local_network": [1],
        "remote_network": [2]
    }

    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn_tunnel_gre():
    data = {

        "tunnel": {
            "type": "gre",
            "virtual_local_endpoint": 12,
            "virtual_remote_endpoint": 17,
            "mtu": 1500,
            "mode": None,
            "server_endpoint": None,
            "service_protocol": None,
            "service_port": None,
            "real_local_endpoint": 15,
            "real_remote_endpoint": 16
        },
        "name": "vpn_test",
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
        "local_id": "abc",
        "remote_endpoint": 1,
        "peer_id": "abcdef",
        "authentication_method": "preshared",
        "preshared_key": "123qwe!",
        "dpd": False,
        "local_network": [1],
        "remote_network": [2]
    }
    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn_tunnel_ipip():
    data = {

        "tunnel": {
            "type": "ipip",
            "virtual_local_endpoint": 1,
            "virtual_remote_endpoint": 17,
            "mtu": 1500,
            "mode": None,
            "server_endpoint": None,
            "service_protocol": None,
            "service_port": None,
            "real_local_endpoint": 15,
            "real_remote_endpoint": 14
        },
        "name": "vpn_test",
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
        "local_id": "abc",
        "remote_endpoint": 12,
        "peer_id": "abcdef",
        "authentication_method": "preshared",
        "preshared_key": "123qwe!",
        "dpd": False,
        "local_network": [1],
        "remote_network": [2]
    }
    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn_tunnel_vtun_server():
    data = {
        "tunnel": {
            "type": "vtun",
            "virtual_local_endpoint": 14,
            "virtual_remote_endpoint": 15,
            "mtu": 1500,
            "mode": "server",
            "server_endpoint": None,
            "service_protocol": "udp",
            "service_port": 20,
            "real_local_endpoint": 13,
            "real_remote_endpoint": 12
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
    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn_tunnel_vtun_server2():
    data = {
        "tunnel": {
            "type": "vtun",
            "virtual_local_endpoint": 12,
            "virtual_remote_endpoint": 14,
            "mtu": 1500,
            "mode": "server",
            "server_endpoint": None,
            "service_protocol": "udp",
            "service_port": 200,
            "real_local_endpoint": 13,
            "real_remote_endpoint": 17
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
        "local_endpoint": 15,
        "local_id": "esf11",
        "remote_endpoint": 16,
        "peer_id": "teh11",
        "authentication_method": "preshared",
        "preshared_key": "123qwe!",
        "dpd": False,
        "local_network": [2],
        "remote_network": [1]
    }
    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_vpn_tunnel_vtun_client():
    data = {
        "tunnel": {
            "type": "vtun",
            "virtual_local_endpoint": 14,
            "virtual_remote_endpoint": 12,
            "mtu": 1500,
            "mode": "client",
            "server_endpoint": 13,
            "service_protocol": "tcp",
            "service_port": 20,
            "real_local_endpoint": 16,
            "real_remote_endpoint": 17
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
        "local_endpoint": 1,
        "local_id": "esf",
        "remote_endpoint": 15,
        "peer_id": "teh",
        "authentication_method": "preshared",
        "preshared_key": "123qwe!",
        "dpd": False,
        "local_network": [1],
        "remote_network": [2]
    }
    serializer = VPNWriteSerializer(data=data)
    if not serializer.is_valid():
        raise ValueError(serializer.errors)
    instance = serializer.save()
    return instance, data


def add_test_static_route():
    interface = Interface.objects.all()[0]

    data = {
        "name": "test1",
        "description": "test1",
        "is_enabled": True,
        "destination_ip": "192.168.15.0",
        "destination_mask": 24,
        "gateway": "192.168.15.10",
        "interface": interface.name,
        "metric": 1000
    }

    serializer = StaticRouteWriteSerializer(data=data)
    assert serializer.is_valid()
    instance = serializer.save()
    return instance


def ntp_config_file():
    content = '''
# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help

driftfile /var/lib/ntp/ntp.drift

# Enable this if you want statistics to be logged.
#statsdir /var/log/ntpstats/

statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable

# Specify one or more NTP servers.

# Use servers from the NTP Pool Project. Approved by Ubuntu Technical Board
# on 2011-02-08 (LP: #104525). See http://www.pool.ntp.org/join.html for
# more information.
pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst

# Use Ubuntu's ntp server as a fallback.
pool ntp.ubuntu.com

# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for
# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrictions>
# might also be helpful.
#
# Note that "restrict" applies to both servers and clients, so a configuration
# that might be intended to block requests from certain clients could also end
# up blocking replies from your own upstream servers.

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited

# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
restrict ::1

# Needed for adding pool entries
restrict source notrap nomodify noquery

# Clients from this (example!) subnet have unlimited access, but only if
# cryptographically authenticated.
#restrict 192.168.123.0 mask 255.255.255.0 notrust


# If you want to provide time to your local subnet, change the next line.
# (Again, the address is an example only.)
#broadcast 192.168.123.255

# If you want to listen to time broadcasts on your local subnet, de-comment the
# next lines.  Please do this only if you trust everybody on the network!
#disable auth
#broadcastclient

#Changes recquired to use pps synchonisation as explained in documentation:
#http://www.ntp.org/ntpfaq/NTP-s-config-adv.htm#AEN3918

#server 127.127.8.1 mode 135 prefer    # Meinberg GPS167 with PPS
#fudge 127.127.8.1 time1 0.0042        # relative to PPS for my hardware

#server 127.127.22.1                   # ATOM(PPS)
#fudge 127.127.22.1 flag3 1            # enable PPS API'''

    with open('{}{}'.format(TEST_PATH, NTP_CONFIG_FILE), 'w+') as ntp_conf:
        ntp_conf.write(content)


def rsyslogconfig_file():
    content = '''
#  /etc/rsyslog.conf    Configuration file for rsyslog.
#
#                       For more information see
#                       /usr/share/doc/rsyslog-doc/html/rsyslog_conf.html
#
#  Default logging rules can be found in /etc/rsyslog.d/50-default.conf


#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
module(load="imklog")   # provides kernel logging support
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")

# provides TCP syslog reception
#module(load="imtcp")
#input(type="imtcp" port="514")

# Enable non-kernel facility klog messages
$KLogPermitNonKernelFacility on

###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Use traditional timestamp format.
# To enable high precision timestamps, comment out the following line.
#
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Filter duplicated messages

$RepeatedMsgReduction on

#
# Set the default permissions for all log files.
#
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

# 
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf

auth,authpriv,local7,local2,kern,daemon.* @127.0.0.1:30001'''

    with open('{}{}'.format(TEST_PATH, RSYSLOG_CONFIG_FILE), 'w+') as rsyslog_conf:
        rsyslog_conf.write(content)


def dnsmasqconfig_file():
    content = '''
==========================   
# This is dnsmasq file
==========================

# ...

# Log lots of extra information about DHCP transactions.
#log-dhcp

# Include another lot of configuration options.
#conf-file=/etc/dnsmasq.more.conf
#conf-dir=/etc/dnsmasq.d

# Include all the files in a directory except those ending in .bak
#conf-dir=/etc/dnsmasq.d,.bak

# Include all files in a directory which end in .conf
#conf-dir=/etc/dnsmasq.d/,*.conf'''

    with open('{}{}'.format(TEST_PATH, DNSMASQ_CONFIG_FILE), 'w+') as dnsmasq_conf:
        dnsmasq_conf.write(content)


def check_file_content(file, content):
    with open(file, 'r+') as ntp_conf:
        ntp_conf_content = ntp_conf.read()
        if content not in ntp_conf_content:
            return False
        return True


def create_rsyslog_server_config_for_test(address, port, protocol, is_secure, *service_list):
    return create_rsyslog_server_config_for_ip_address(address, port, protocol, is_secure, service_list)
