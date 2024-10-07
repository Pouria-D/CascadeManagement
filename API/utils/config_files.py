import os

current = os.path.dirname(os.path.realpath(__file__)) + '/'

API_PATH = '/opt/narin/api/'

# for test
TEST_COMMANDS_FILE = '/commands.txt'
TEST_PATH = '/tmp/django_test'
NETWORK_IFACES_D_CONF_PATH = '/etc/network/interfaces.d/'
NETWORK_IF_UP_CONF_PATH = '/etc/network/if-up.d/'
NETWORK_CONF_PATH = '/etc/network/'

# vpn config files
IPSEC_CONF_FILE = '/etc/ipsec.conf'
IPSEC_SECRETS_FILE = '/etc/ipsec.secrets'
GRE_CONFIGS_PATH = '/etc/gre/'
IPIP_CONFIGS_PATH = '/etc/ipip/'
VTUND_CONFIGS_PATH = '/etc/vtund/'
VAR_LOCK_VTUND_PATH = '/var/lock/vtund/'

NETWORK_MANAGER_CONFIG_FILE = '/etc/NetworkManager/NetworkManager.conf'
NETWORK_IFACES_CONF_FILE = '/etc/network/interfaces'
RC_LOCAL_FILE = '/etc/rc.local'
# dns
DNSMASQ_CONFIG_FILE = '/etc/dnsmasq.conf'
DNS_UPSTREAM_FILE = '/etc/dns_upstream_list'
DNS_HOST_LIST_FILE = '/etc/host_list'
DNS_LOG_FILE = '/var/log/dns.log'
DNSMASQ_SCRIPT_FILE = '/etc/init.d/dnsmasq'

# dhcp
DHCP_LEASES_FILE = '/var/lib/misc/dnsmasq.leases'

NGINX_CONFIG_FILE = '/etc/nginx/sites-available/narin.conf'

SSH_CONFIG_FILE = '/etc/ssh/sshd_config'
RSYSLOG_CONFIG_FILE = '/etc/rsyslog.conf'
SNMP_V2_CONFIG_FILE = '/etc/snmp/snmpv2.conf'
SNMP_V3_CONFIG_FILE = '/etc/snmp/snmpv3.conf'
SNMP_D_CONFIG_FILE = '/etc/snmp/snmpd.conf'
VAR_LIB_SNMP_CONFIG_FILE = '/var/lib/snmp/snmpd.conf'
NTP_CONFIG_FILE = '/etc/ntp.conf'
FAIL_2_BAN_CONFIG_FILE = '/etc/fail2ban/jail.conf'
ISSUE_FILE = '/etc/issue'
ISSUE_NET_FILE = '/etc/issue.net'
HOSTS_FILE = '/etc/hosts'
RTABLE_FILE = '/etc/iproute2/rt_tables'
SSL_CERT_RSYSLOG_CA_FILE = '/etc/ssl/certs/rsyslog_ca.pem'

# certificates
PKI_DIR = '/var/ngfw/pki'

# RSA VPN
PRIVATE_KEY_FILE = '/etc/ipsec.d/private/'
CERT_VPN_FILE = '/etc/ipsec.d/certs/'
CA_CERT_VPN_FILE = '/etc/ipsec.d/cacerts/'
