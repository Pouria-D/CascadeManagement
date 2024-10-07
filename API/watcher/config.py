import os.path
import re
import subprocess
from threading import Thread
from time import sleep

from brand import BRAND, COMPANY
from config_app.models import StaticRoute, Interface, Setting, Snmp, DHCPServerConfig, DNSConfig, HighAvailability
from config_app.serializers import InterfaceRealSerializer
from config_app.utils import check_static_route_existence, create_static_route_cmd, dnsmasq_basic_config, \
    dns_configuration, dns_record_config, remove_extra_dns_record, set_system_interfaces, config_ntp_server, \
    remove_rsyslog_server, set_rsyslog_server, create_rsyslog_server_config, config_narin_access_ports, \
    generate_ssh_banner, \
    change_or_add_key_to_content, create_snmpv2_config, create_snmpv3_user, remove_snmpv2_config, remove_snmpv3_config, \
    create_snmpv3_config, set_DHCP_configuration, iptables_insert, check_use_bridge, check_use_vlan, ha_read_status, \
    this_system_is_master
from config_app.utils import checkfile_snmpv2, checkfile_snmpv3
from firewall_app.models import Policy
from parser_utils.mod_resource.utils import get_interface_link_status, is_interface_active
from parser_utils.mod_setting.utils import config_network_interface, clear_interfaces_file
from qos_utils.utils import redirect_lan_traffic_to_ifb_filter, mark_for_incoming_interface, \
    check_interface_upload_tree, check_ifb_download_tree, DOWNLOAD_IFB, apply_qos_policy
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner, sudo_file_reader, sudo_file_writer
from utils.config_files import DNSMASQ_CONFIG_FILE, DNS_UPSTREAM_FILE, DNS_HOST_LIST_FILE, DNS_LOG_FILE, \
    NETWORK_MANAGER_CONFIG_FILE, DNSMASQ_SCRIPT_FILE, SSH_CONFIG_FILE, RSYSLOG_CONFIG_FILE, SNMP_V2_CONFIG_FILE, \
    SNMP_V3_CONFIG_FILE, SNMP_D_CONFIG_FILE, NTP_CONFIG_FILE, FAIL_2_BAN_CONFIG_FILE, ISSUE_NET_FILE, ISSUE_FILE
from utils.log import watcher_log
from watcher.base import AbstractWatcher


class SnmpWatcher(AbstractWatcher):

    def run(self, interval, pending_interval=30):
        while True:
            self.check_snmpv2_file()
            self.check_snmpv3_file()
            self.check_snmp_basicconf()
            snmp_config = Snmp.objects.filter(is_enabled=True)
            for snmp_server in snmp_config:
                if snmp_server.snmp_type == "v2":
                    if not checkfile_snmpv2(snmp_server):
                        create_snmpv2_config(snmp_server, "api", "watcher", "watcher", "watcher ADD", is_watcher=True)
                        sudo_runner("service snmpd restart")
                else:
                    if not checkfile_snmpv3(snmp_server):
                        create_snmpv3_user(snmp_server, "api", "watcher", "watcher add", "delete", is_watcher=True)
                        create_snmpv3_config(snmp_server, "api", "watcher", "watcher add","delete", is_watcher=True)
                        sudo_runner("service snmpd restart")
            snmp_config = Snmp.objects.filter(is_enabled=False)
            for snmp_server in snmp_config:
                if snmp_server.snmp_type == "v2":
                    if checkfile_snmpv2(snmp_server):
                        remove_snmpv2_config(snmp_server, "api", "watcher", "watcher Remove", "delete",is_watcher=True)
                else:
                    if checkfile_snmpv3(snmp_server):
                        remove_snmpv3_config(snmp_server, "api", "watcher", "watcher Remove","delete" ,is_watcher=True)

            sleep(interval)

    def check_snmpv2_file(self):
        file_content = ''' ########################SNMP v2  
#com2sec   disksOnly  default   disks
#com2sec   allThings  default   everything

# Map 'disksOnly' to 'diskGroup' for SNMP Version 2c
# Map 'allThings' to 'allGroup' for SNMP Version 2c
#                sec.model sec.name
#group diskGroup   v2c      disksOnly
group allGroup    v2c      allThings

# Define 'diskView', which includes everything under .1.3.6.1.2.1.25.2.3.1
# Define 'allView', which includes everything under .1 (which is everything)
#                  incl/excl   subtree
#view    diskView   included    .1.3.6.1.2.1.25.2.3
view    allView        included    .1

#Access     diskGroup   ""      any     noauth   exact   diskView   none    none
Access                 allGroup    ""      any     noauth   exact   allView    none    none
##########################
'''
        file_conf = SNMP_V2_CONFIG_FILE
        if not os.path.exists(file_conf):
            sudo_file_writer(file_conf, file_content, "w+")

    def check_snmpv3_file(self):
        Default_content = "####SNMPv3 Config\n"
        file_conf = SNMP_V3_CONFIG_FILE
        if not os.path.exists(file_conf):
            sudo_file_writer(file_conf, Default_content, "w+")

    def check_snmp_basicconf(self):
        Default_conf = '''###############################################################################
#
# EXAMPLE.conf:
#   An example configuration file for configuring the Net-SNMP agent ('snmpd')
#   See the 'snmpd.conf(5)' man page for details
#
#  Some entries are deliberately commented out, and will need to be explicitly activated
#
###############################################################################
#
#  AGENT BEHAVIOUR
#

agentAddress  udp:0:161

includeFile	./snmpv2.conf
includeFile	./snmpv3.conf


###############################################################################
#
#  SYSTEM INFORMATION
#

#  Note that setting these values here, results in the corresponding MIB objects being 'read-only'
#  See snmpd.conf(5) for more details
sysLocation    Next Genration Firewall
sysContact     <{}@{}.com>
                                                 # Application + End-to-End layers
sysServices    72


#
#  Process Monitoring
#
                               # At least one  'mountd' process
#proc  mountd
                               # No more than 4 'ntalkd' processes - 0 is OK
#proc  ntalkd    4
                               # At least one 'sendmail' process, but no more than 10
#proc  sendmail 10 1

#  Walk the UCD-SNMP-MIB::prTable to see the resulting output
#  Note that this table will be empty if there are no "proc" entries in the snmpd.conf file


#
#  Disk Monitoring
#
                               # 10MBs required on root disk, 5% free on /var, 10% free on all other disks
disk       /     10000
disk       /var  5%
includeAllDisks  10%

#  Walk the UCD-SNMP-MIB::dskTable to see the resulting output
#  Note that this table will be empty if there are no "disk" entries in the snmpd.conf file


#
#  System Load
#
                               # Unacceptable 1-, 5-, and 15-minute load averages
load   12 10 5

#  Walk the UCD-SNMP-MIB::laTable to see the resulting output
#  Note that this table *will* be populated, even without a "load" entry in the snmpd.conf file



###############################################################################
#
#  ACTIVE MONITORING
#

                                    #   send SNMPv1  traps
#trapsink     localhost public
                                    #   send SNMPv2c traps
#trap2sink    localhost public
                                    #   send SNMPv2c INFORMs
#informsink   localhost public

#  Note that you typically only want *one* of these three lines
#  Uncommenting two (or all three) will result in multiple copies of each notification.


#
#  Event MIB - automatically generate alerts
#
                                   # Remember to activate the 'createUser' lines above
#iquerySecName   internalUser       
#rouser          internalUser
                                   # generate traps on UCD error conditions
#defaultMonitors          yes
                                   # generate traps on linkUp/Down
#linkUpDownNotifications  yes



###############################################################################
#
#  EXTENDING THE AGENT
#

#
#  Arbitrary extension commands
#
#extend    test1   /bin/echo  Hello, world!
# extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
#extend-sh test3   /bin/sh /tmp/shtest

#  Note that this last entry requires the script '/tmp/shtest' to be created first,
#    containing the same three shell commands, before the line is uncommented

#  Walk the NET-SNMP-EXTEND-MIB tables (nsExtendConfigTable, nsExtendOutput1Table
#     and nsExtendOutput2Table) to see the resulting output

#  Note that the "extend" directive supercedes the previous "exec" and "sh" directives
#  However, walking the UCD-SNMP-MIB::extTable should still returns the same output,
#     as well as the fuller results in the above tables.


#
#  "Pass-through" MIB extension command
#
#pass .1.3.6.1.4.1.8072.2.255  /bin/sh       PREFIX/local/passtest
#pass .1.3.6.1.4.1.8072.2.255  /usr/bin/perl PREFIX/local/passtest.pl

# Note that this requires one of the two 'passtest' scripts to be installed first,
#    before the appropriate line is uncommented.
# These scripts can be found in the 'local' directory of the source distribution,
#     and are not installed automatically.
        
#  Walk the NET-SNMP-PASS-MIB::netSnmpPassExamples subtree to see the resulting output
        
        
#
#  AgentX Sub-agents
#
                                                   #  Run as an AgentX master agent
# master          agentx
                                                   #  Listen for network connections (from localhost)
                                                   #    rather than the default named socket /var/agentx/master
'''.format(BRAND, COMPANY)
        file_conf = SNMP_D_CONFIG_FILE
        if not os.path.exists(file_conf):
            sudo_file_writer(file_conf, Default_conf, "w+")


class QOSWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        while True:
            is_ifb_up = False
            if Interface.objects.filter(download_bandwidth__isnull=False).exists():
                check_ifb_download_tree()
                is_ifb_up = True
            for interface in Interface.objects.all():
                interface_num = re.findall(r'\d+', interface.name)[0]
                mark_for_incoming_interface(interface.name, interface_num, 'add')
                if interface.upload_bandwidth:
                    check_interface_upload_tree(interface)
                if is_ifb_up and interface.type == 'LAN':
                    redirect_lan_traffic_to_ifb_filter(interface.name)
                watcher_log('QOS', interface.name)

            qos_policy_list = Policy.objects.filter(qos_id__isnull=False, qos__download_guaranteed_bw__isnull=False)
            if qos_policy_list.exists():
                cmd = 'tc filter show dev {}'.format(DOWNLOAD_IFB)
                status, result = sudo_runner(cmd)
                if not status or not result or 'filter parent 1:' not in result:  # if there is nothing in filter show that means it's boot-up time
                    for policy in qos_policy_list:
                        apply_qos_policy(policy, "add")
                else:
                    for policy in qos_policy_list:
                        if 'flowid 1:{}'.format(policy.qos.class_id) not in result:
                            apply_qos_policy(policy, "add")
            sleep(interval)



class InterfaceWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        clear_interfaces_file()
        set_system_interfaces()
        while True:
            for interface in Interface.objects.all():

                if interface.mode == 'interface' and not check_use_bridge(interface.name) and not check_use_vlan(
                        interface.name):

                    # interface_details = self.get_interface_details(interface.name)
                    # if not self.is_sync(interface, interface_details):
                    config_network_interface(interface, is_watcher=True)
                    watcher_log('Interface', interface.name)

                    dhcp_config = DHCPServerConfig.objects.filter(interface=interface)
                    if dhcp_config and not InterfaceRealSerializer(interface).get_is_link_connected(
                            interface):
                        create_notification(source='interface', item={'id': interface.name, 'name': interface.name},
                                            message=str(
                                                'DHCP can not respond on {} interface, because this interface link is not connected'.format(
                                                    interface.name))
                                            , severity='e', details={}, request_username='')

                    dns_config_list = DNSConfig.objects.filter(interface_list__name__contains=interface.name)
                    if dns_config_list:
                        for dns_interface in dns_config_list[0].interface_list.filter(name=interface.name):
                            if dns_interface == interface and not InterfaceRealSerializer(
                                    interface).get_is_link_connected(
                                interface):
                                create_notification(source='interface',
                                                    item={'id': interface.name, 'name': interface.name},
                                                    message=str(
                                                        'DNS can not respond on {} interface, because this interface link is not connected'.format(
                                                            interface.name))
                                                    , severity='e', details={}, request_username='')

            sleep(interval)

    def get_interface_details(self, interface_name):
        interface_details = dict()

        connection_name = self.get_connection_name(interface_name)
        if not connection_name:
            return ""

        nmcli_connection_details = subprocess.check_output('nmcli conn show "{}"'.format(connection_name), shell=True)
        connection_details_list = str(nmcli_connection_details).replace("b'", '').split('\\n')

        for item in connection_details_list:
            t = item.split(':')
            key = t[0]
            if len(t) > 1:
                value = item.split(':')[1].strip()
            else:
                value = None

            interface_details[key] = value

        nmcli_device_details = subprocess.check_output('nmcli device show {}'.format(interface_name), shell=True)
        device_details_list = str(nmcli_device_details).replace("b'", '').split('\\n')

        for item in device_details_list:
            t = item.split(':')
            key = t[0]
            if len(t) > 1:
                value = item.split(':')[1].strip()
            else:
                value = None

            interface_details[key] = value

        return interface_details

    def get_connection_name(self, interface_name):
        status, nmcli_connections = sudo_runner('nmcli conn show | grep {}'.format(interface_name))
        if status:
            nmcli_connection_name = str(nmcli_connections).split('  ')[0]
            return nmcli_connection_name

    def is_default_gateway(self, interface_name):
        cmd = 'ip route show | grep default'
        route_content = subprocess.check_output(cmd, shell=True).decode()
        if route_content:
            return route_content.split('\n')[0].split(' ')[4] == interface_name

        return False


class NTPWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        from config_app.models import NTPConfig

        while True:
            sleep(interval)
            ntp_config = NTPConfig.objects.filter()
            if not ntp_config:
                continue
            ntp_config = ntp_config[0]
            if not self.is_sync(ntp_config):
                config_ntp_server(ntp_config.id, None, None, is_watcher=True)
                watcher_log('NTP')

    def is_sync(self, ntp_config):
        try:
            status, ntp_file_content = sudo_file_reader(NTP_CONFIG_FILE)
            if status:
                for address in ntp_config.ntp_server_list:
                    if address not in ntp_file_content:
                        return False
        except:
            return False

        return ntp_config.is_enabled == self.is_ntp_service_running()

    def is_ntp_service_running(self):
        cmd = 'service ntp status'
        result = subprocess.check_output(cmd, shell=True).decode()
        if 'Active: active (running)' in result:
            return True
        else:
            return False


class StaticRouteWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        while True:
            static_routes = StaticRoute.objects.filter(is_enabled=True)
            for route in static_routes:
                find = check_static_route_existence(route)
                if not find:
                    cmd = create_static_route_cmd(route)
                    sudo_runner(cmd)
                    watcher_log('Static Route', route.name)

            sleep(interval)


def check_rsysserver_exists(rsyslog_server):
    """
        This function reads /etc/rsyslog.conf file and
        checks that it configured before or not.
        Returns True if configured, else False
    """

    if rsyslog_server.address:
        current_config = create_rsyslog_server_config(rsyslog_server)

        with open(RSYSLOG_CONFIG_FILE) as rsyslog_config_file:
            content = rsyslog_config_file.read()
            if current_config in content:
                return True
            else:
                return False

    with open(RSYSLOG_CONFIG_FILE) as rsyslog_config_file:
        for line in rsyslog_config_file:
            if 'set_by_narin_admin' in line:
                return True

    return False


class RSyslogWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        from config_app.models import LogServer
        while True:
            log_server_list = LogServer.objects.filter(is_enabled=True)
            for item in log_server_list:
                is_check_exists = check_rsysserver_exists(item)
                if not is_check_exists:
                    if not item.is_enabled:
                        remove_rsyslog_server(item, None, None, None, None, is_watcher=True)
                        item.status = 'disabled'
                    else:
                        set_rsyslog_server(item, None, None, None, None, is_watcher=True)
                        item.status = 'succeeded'

                    watcher_log('Log Server')

            sleep(interval)


class DNSWatcher(AbstractWatcher):

    def check_dns_upstream_servers(self, dns_config):
        try:
            with open(DNS_UPSTREAM_FILE, 'r') as dns_upstream_file:
                content = dns_upstream_file.read()
                servers = 'nameserver ' + '\nnameserver '.join(filter(None, [dns_config.primary_dns_server,
                                                                             dns_config.secondary_dns_server,
                                                                             dns_config.tertiary_dns_server]))
                if servers in content:
                    return True
                return False
        except:
            return False

    def check_dns_strict_order_option(self, dns_config):
        try:
            with open(DNSMASQ_CONFIG_FILE, 'r') as dnsmasq_config_file:
                content = dnsmasq_config_file.read()
                is_strict_order = dns_config.is_strict_order
                if is_strict_order:
                    if '\nstrict-order' in content:
                        return True
                    return False
                else:
                    if '\nall-servers' in content:
                        return True
                    return False
        except:
            return False

    def check_dnsmasq_interfaces(self, dns_config):
        import re
        active_interfaces = []
        for interface in dns_config.interface_list.all():
            if is_interface_active(interface) and get_interface_link_status(interface):
                active_interfaces.append(interface.name)
        try:
            with open(DNSMASQ_CONFIG_FILE, 'r') as dnsmasq_config_file:
                content = dnsmasq_config_file.read()
                if active_interfaces:
                    interfaces = ','.join(interface for interface in active_interfaces)
                else:
                    interfaces = 'lo'
                interface_rgx = "\ninterface={}".format(interfaces)
                if re.search(interface_rgx, content):
                    return True
                return False
        except:
            return False

    def check_dnsmasq_local_domain(self, dns_config):
        local_domain = dns_config.local_domain
        try:
            with open(DNSMASQ_CONFIG_FILE, 'r') as dnsmasq_config_file:
                content = dnsmasq_config_file.read()
                if local_domain:
                    if '\ndomain={}'.format(local_domain) not in content or '\nexpand-hosts' not in content:
                        return False
                else:
                    if '\ndomain=' in content or '\nexpand-hosts' in content:
                        return False
                return True
        except:
            return False

    def check_dnsmasq_configuration(self):
        try:
            with open(NETWORK_MANAGER_CONFIG_FILE, 'r') as net_mng_file:
                content = net_mng_file.read()
                if '\ndns=dnsmasq' not in content:
                    dnsmasq_basic_config(None, True, None)
        except:
            return False
        try:
            with open(DNSMASQ_SCRIPT_FILE, 'r') as dns_script_file:
                content = dns_script_file.read()
                if 'RESOLV_CONF={}'.format(DNS_UPSTREAM_FILE) not in content:
                    dnsmasq_basic_config(None, None, True)
        except:
            return False
        try:
            with open(DNSMASQ_CONFIG_FILE, 'r') as dns_config_file:
                content = dns_config_file.read()

                if '\ndomain-needed' not in content:
                    dnsmasq_basic_config('\ndomain-needed', None, None)
                if '\nbogus-priv' not in content:
                    dnsmasq_basic_config('\nbogus-priv', None, None)
                # if '\ndnssec' not in content:
                #     dnsmasq_basic_config('\ndnssec', None, None)
                if '\nresolv-file=' not in content:
                    dnsmasq_basic_config('\nresolv-file={}'.format(DNS_UPSTREAM_FILE), None, None)
                if '\nno-hosts' not in content:
                    dnsmasq_basic_config('\nno-hosts', None, None)
                # if '\nlisten-address=' not in content:
                #     dnsmasq_basic_config('\nlisten-address=127.0.0.1', None, None)
                if '\naddn-hosts=' not in content:
                    dnsmasq_basic_config('\naddn-hosts={}'.format(DNS_HOST_LIST_FILE), None, None)
                if '\nlog-queries' not in content:
                    dnsmasq_basic_config('\nlog-queries', None, None)
                if '\nlog-facility' not in content:
                    dnsmasq_basic_config('\nlog-facility={}'.format(DNS_LOG_FILE), None, None)
                if '\ncache-size' not in content:
                    dnsmasq_basic_config('\ncache-size=1000', None, None)
        except:
            return False

    def check_dns_record(self, dns_record):
        try:
            with open(DNS_HOST_LIST_FILE, 'r') as host_list_file:
                content = host_list_file.read()
                if dns_record.hostname_list:
                    hostname_list = sorted(dns_record.hostname_list)
                    hostnames = "\t".join(hostname for hostname in hostname_list)
                    record = '{host}\n'.format(host=hostnames)
                    if record in content:
                        return True
                    return False
        except:
            return False

    def check_extra_records_existence(self, dns_record_list):
        records = []
        for record in dns_record_list:
            hostname_list = sorted(record.hostname_list)
            records.append(str(record.ip_address) + '\t' + '\t'.join(hostname_list))
        try:
            with open(DNS_HOST_LIST_FILE, 'r') as host_list_file:
                content = host_list_file.read()
                file_record_list = content.splitlines()
                correct_content = None
                for line in file_record_list:
                    if line not in records:
                        correct_content = re.sub(line + '\n', '', content)
                if correct_content:
                    remove_extra_dns_record(correct_content)
        except:
            return False

    def run(self, interval, pending_interval=30):
        from config_app.models import DNSConfig
        from config_app.models import DNSRecord

        self.check_dnsmasq_configuration()

        while True:
            watcher_should_work = False
            if HighAvailability.objects.filter(is_enabled=True, status='succeeded').exists():
                pcs_status = ha_read_status()
                if pcs_status:
                    if this_system_is_master(pcs_status):
                        watcher_should_work = True
            else:
                watcher_should_work = True
            if watcher_should_work:
                dns_config = DNSConfig.objects.filter()
                if dns_config.exists():
                    if not self.check_dns_upstream_servers(dns_config[0]) \
                            or not self.check_dnsmasq_local_domain(dns_config[0]) \
                            or not self.check_dns_strict_order_option(dns_config[0]):
                        dns_configuration(dns_config[0], None, None, None, is_watcher=True)
                        watcher_log('DNS Config')

                for dns_record in DNSRecord.objects.filter():
                    if dns_record:
                        if not self.check_dns_record(dns_record):
                            # The notifications will be removed in dns_record_config (just in this case)
                            dns_record_config(dns_record, 'add', None, None, None, None, None, is_watcher=True)
                            watcher_log('DNS Config')

                self.check_extra_records_existence(DNSRecord.objects.filter())

            sleep(interval)


class SettingWatcher(AbstractWatcher):

    def run(self, interval, pending_interval=30):

        for instance in Setting.objects.all():
            if instance.key in ['ssh-port', 'http-port', 'https-port']:
                config_narin_access_ports(instance, instance, None, None, None, is_watcher=True)

            else:
                if instance.key == 'login-message':

                    ssh_banner_message = generate_ssh_banner(instance.data['value'])

                    t = Thread(target=sudo_file_writer, args=(ISSUE_NET_FILE, ssh_banner_message, 'w'))
                    t.start()

                    t = Thread(target=sudo_file_writer, args=(ISSUE_FILE, ssh_banner_message, 'w'))
                    t.start()

                elif instance.key == 'admin-session-timeout':
                    status, sshd_config_content = sudo_runner('cat {}'.format(SSH_CONFIG_FILE))
                    if status:
                        newcontent = change_or_add_key_to_content("\s*ClientAliveInterval\s*[^\n]*\n",
                                                                  "\nClientAliveInterval {}\n".format(
                                                                      int(instance.data['value']) * 60),
                                                                  sshd_config_content)
                        sudo_file_writer(SSH_CONFIG_FILE, newcontent, 'w')
                        sudo_runner('service ssh restart')

                elif instance.key == 'max-login-attempts':
                    status, fail2ban_config_content = sudo_runner('cat {}'.format(FAIL_2_BAN_CONFIG_FILE))
                    if status:
                        newcontent = change_or_add_key_to_content("\n\s*maxretry\s*=\s*\d+\n",
                                                                  "\nmaxretry = {}\n".format(instance.data['value']),
                                                                  fail2ban_config_content)
                        sudo_file_writer(FAIL_2_BAN_CONFIG_FILE, newcontent, 'w')
                        sudo_runner('service fail2ban restart')

                elif instance.key == 'ssh-ban-time':
                    status, fail2ban_config_content = sudo_runner('cat {}'.format(FAIL_2_BAN_CONFIG_FILE))
                    if status:
                        newcontent = change_or_add_key_to_content("\n\s*bantime\s*=\s*\d+\n",
                                                                  "\nbantime = {}\n".format(instance.data['value']),
                                                                  fail2ban_config_content)
                        sudo_file_writer(FAIL_2_BAN_CONFIG_FILE, newcontent, 'w')
                        sudo_runner('service fail2ban restart')

                # elif instance.key == 'ssl_certificate':
                #     sudo_file_writer('/etc/ssl/certs/nginx-selfsigned.crt', instance.data['public_key'], 'w')
                #     instance.data['public_key'] = 'uploaded by user'
                #
                #     sudo_file_writer('/etc/ssl/private/nginx-selfsigned.key', instance.data['private_key'], 'w')
                #     instance.data['private_key'] = 'uploaded by user'
                #
                #     sudo_runner('service nginx restart')

            watcher_log('Setting')




class DHCPWatcher(AbstractWatcher):
    def check_dhcp_config(self, dhcp_config):
        try:
            flag = True
            with open(DNSMASQ_CONFIG_FILE, 'r') as dnsmasq_config_file:
                content = dnsmasq_config_file.read()
                iptables_insert('INPUT -p udp --dport 67 -j ACCEPT')
                iptables_insert('INPUT -p udp --dport 68 -j ACCEPT')
                if dhcp_config.start_ip and dhcp_config.end_ip:
                    if dhcp_config.subnet_mask:
                        if '\ndhcp-range=interface:{},{},{},{},{}h'.format(dhcp_config.interface.name,
                                                                           dhcp_config.start_ip, dhcp_config.end_ip,
                                                                           dhcp_config.subnet_mask,
                                                                           dhcp_config.lease_time) not in content:
                            flag = False
                    else:
                        if '\ndhcp-range=interface:{},{},{},{}h'.format(dhcp_config.interface.name,
                                                                        dhcp_config.start_ip,
                                                                        dhcp_config.end_ip,
                                                                        dhcp_config.lease_time) not in content:
                            flag = False
                if dhcp_config.gateway:
                    if '\ndhcp-option=interface:{},option:router,{}'.format(dhcp_config.interface.name,
                                                                            dhcp_config.gateway) not in content:
                        flag = False
                if dhcp_config.exclude_ip_list:
                    for ip in dhcp_config.exclude_ip_list:
                        ex_ips = 'dhcp-host=reserve,{}'.format(ip)
                        if '\n{}'.format(ex_ips) not in content:
                            flag = False
                if dhcp_config.dns_server_list:
                    dns_txt = 'dhcp-option=interface:{},6'.format(dhcp_config.interface.name)
                    for dns in dhcp_config.dns_server_list:
                        dns_txt += ',{}'.format(dns)
                    if '\n{}'.format(dns_txt) not in content:
                        flag = False
                if '\ndhcp-option=19,0' not in content:
                    flag = False
                if '\ndhcp-lease-max=200' not in content:
                    flag = False
                return flag
        except:
            return False

    def run(self, interval, pending_interval=30):
        while True:
            watcher_should_work = False
            if HighAvailability.objects.filter(is_enabled=True, status='succeeded').exists():
                pcs_status = ha_read_status()
                if pcs_status:
                    if this_system_is_master(pcs_status):
                        watcher_should_work = True
            else:
                watcher_should_work = True
            if watcher_should_work:
                dhcp_config_list = DHCPServerConfig.objects.filter(is_enabled=True)
                if dhcp_config_list.exists():
                    for config in dhcp_config_list:
                        if not self.check_dhcp_config(config):
                            set_DHCP_configuration(config, old_instance=None, action='add', is_watcher=True)
                            watcher_log('DHCP Config')
                    sudo_runner('service dnsmasq restart')
            sleep(interval)


class HighAvailabilityWatcher(AbstractWatcher):

    def run(self, interval, pending_interval=30):
        while True:
            ha_config = HighAvailability.objects.all()
            if ha_config.exists() and ha_config[0].is_enabled and ha_config[0].status == 'succeeded':
                real_ha_status = ha_read_status()
                try:
                    active_node = real_ha_status['active_node']
                    offline_node = real_ha_status['offline_node']
                except:
                    active_node = ""
                    offline_node = ""
                if not active_node:
                    status, result = sudo_runner(
                        'pcs cluster start')  # sometimes after multiple reboots cluster need to start!
                    if not status:
                        Notification.objects.filter(source='HA',
                                                    message__contains='HighAvailability is out of service').delete()
                        create_notification(source='HA', item={},
                                            message=str(
                                                'Caution! HighAvailability is out of service. check and update your configuration.'),
                                            severity='e',
                                            )
                else:
                    Notification.objects.filter(source='HA',
                                                message__contains='HighAvailability is out of service').delete()
                if offline_node:
                    Notification.objects.filter(source='HA',
                                                message__contains='in HighAvailability configuration is offline').delete()
                    create_notification(source='HA', item={},
                                        message=str(
                                            'Node {} in HighAvailability configuration is offline.'.format(
                                                offline_node)),
                                        severity='e',
                                        )
                else:
                    Notification.objects.filter(source='HA',
                                                message__contains='in HighAvailability configuration is offline').delete()
            sleep(interval)
