import datetime
import json
import logging.handlers
import os
import re
import sys
from time import sleep

from netaddr import IPAddress
from netaddr import IPNetwork
from rest_framework import serializers

from api.settings import IS_TEST, BACKUP_DIR, POLICY_BACK_POSTFIX
from auth_app.utils import get_client_ip
from brand import BRAND
from config_app.models import Interface, NTPConfig, Setting, DNSConfig, DHCPServerConfig, HighAvailability, Hostname
from firewall_input_app.models import InputFirewall, Source
from firewall_input_app.utils import apply_rule
from parser_utils.mod_resource.utils import get_network_interfaces, get_interface_active_connection, \
    get_interface_method, get_interface_ip, get_interface_gateway, get_interface_mac
from parser_utils.mod_setting.utils import convert_to_cidr, get_primary_default_gateway_interface_name, \
    config_network_interface
from parser_utils.mod_setting.views import captive_portal_change_status_view, set_chilli_configs_view
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner, sudo_file_writer, sudo_file_reader, sudo_restart_systemd_service
from root_runner.utils import command_runner, file_reader
from utils.config_files import DNSMASQ_CONFIG_FILE, DNS_UPSTREAM_FILE, DNS_HOST_LIST_FILE, NETWORK_MANAGER_CONFIG_FILE, \
    DNSMASQ_SCRIPT_FILE, NGINX_CONFIG_FILE, SSH_CONFIG_FILE, TEST_PATH, RSYSLOG_CONFIG_FILE, SNMP_V2_CONFIG_FILE, \
    SNMP_V3_CONFIG_FILE, NTP_CONFIG_FILE, VAR_LIB_SNMP_CONFIG_FILE, SSL_CERT_RSYSLOG_CA_FILE, RC_LOCAL_FILE, \
    DHCP_LEASES_FILE, NETWORK_IFACES_CONF_FILE
from utils.log import log
from utils.utils import run_thread, print_if_debug

HA_USER = 'hacluster'
HA_CLUSTER_PASS = 'M13O!+H66seN'
TIMEOUT_DURATION_FOR_SSH = 20
CLUSTER_NAME = 'narincluster'
logger = logging.getLogger('FWMW')


def converttomegabyte(nonBytes):
    if (str(nonBytes) == "0"):
        return 0
    result = re.search("(\d+)([kmg]*)", str(nonBytes).lower())
    if result:
        if result.group(2) == "k":
            return int(result.group(1)) / 1024.0
        if result.group(2) == "m":
            return int(result.group(1))
        if result.group(2) == "g":
            return int(result.group(1)) * 1024
        if not result.group(2):
            return int(result.group(1)) / 1024.0 / 1024.0
            # return int(result.group(1))
    return -1


def findTheRelatedRulesInfo(myPolicyID, iptables_nvL=None, tableName="", chainName="FORWARD"):
    mainLines = []
    chainLines = []
    if tableName:
        tableName = " -t " + tableName

    status, result = sudo_runner('iptables -nvL policy_id_' + str(myPolicyID) + tableName)
    if status:
        regX = r'\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(.+)'
        for line in result.split('\n')[2:]:
            policyInfo = {}
            result = re.search(regX, line, re.M)
            if (result):
                policyInfo['pkts'] = str(result.group(1))
                policyInfo['bytes'] = str(result.group(2))
                policyInfo['content'] = result.group(3)
                chainLines.append(policyInfo)

    if not iptables_nvL:
        status, result = sudo_runner('iptables --line-number -nvL ' + chainName + tableName)
        if status:
            iptables_nvL = result.split("\n")

    # regX = "^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(\d+[KMG]*)\s+policy_id_" + str(myPolicyID) + "\s*(.*)"
    regX = r"^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(\d+[KMG]*)\s+policy_id_" + re.escape(str(myPolicyID)) + r"\s*(.*)"
    # regX = r"\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(\d+[KMG]*)\s+policy_id_1\s*(.*)"

    if iptables_nvL:
        for line in iptables_nvL[2:]:
            policyInfo = {}
            result = re.search(regX, line, re.M)

            if (result):
                policyInfo['line-number'] = str(result.group(1))
                policyInfo['pkts'] = str(result.group(2))
                policyInfo['bytes'] = str(result.group(3))
                policyInfo['content'] = result.group(4)
                mainLines.append(policyInfo)

    return mainLines, chainLines


def getPoliciesInfo(ids):
    idsList = ids
    if type(ids) != type([]):  # To let users call this function with an ID
        idsList = []
        idsList.append(ids)

    iptables_nvL = None
    if not iptables_nvL:
        status, result = sudo_runner('iptables --line-number -nvL FORWARD')
        if status:
            iptables_nvL = result.split("\n")

    result = {}
    for policy in idsList:
        result[str(policy)] = {}
        result[str(policy)]['megapkts'] = 0
        result[str(policy)]['megabytes'] = 0
        result[str(policy)]['mainRules'] = 0
        result[str(policy)]['chainRules'] = 0

        countInfo, policyInfo, chainInfo = getPolicyInfo(policy, iptables_nvL)
        if not countInfo:
            continue
        result[str(policy)]['megapkts'] = countInfo['megapkts']
        result[str(policy)]['megabytes'] = countInfo['megabytes']
        if not policyInfo:
            continue
        mainPolicyes = []
        for pol in policyInfo:
            mainPolicyes.append(pol['content'])

        if not chainInfo:
            continue
        chainPolicyes = []
        for pol in chainInfo:
            chainPolicyes.append(pol['content'])

        result[str(policy)]['mainRules'] = json.dumps(mainPolicyes)
        result[str(policy)]['chainRules'] = json.dumps(chainPolicyes)

    return result


def getPolicyInfo(id, iptables_nvL=None):
    result = {}
    result['megapkts'] = 0
    result['megabytes'] = 0

    policyInfo, chainInfo = findTheRelatedRulesInfo(id, iptables_nvL)

    for PI in chainInfo:
        meg = converttomegabyte(PI['pkts'])
        if meg < 0:
            logger.warning("Can't convert packets ", str(PI['pkts']))
        else:
            result['megapkts'] += meg
            meg = converttomegabyte(PI['bytes'])
            if meg < 0:
                logger.warning("Can't convert bytes", str(PI['bytes']))
            else:
                result['megabytes'] += meg

    # policyPreInfo, chainPreInfo = findTheRelatedRulesInfo(id, iptables_nvL, "nat", "PREROUTING")
    # for PI in chainPreInfo:
    #     meg = convertToMegaByte(PI['pkts'])
    #     if meg < 0:
    #         logger.warning("Can't convert packets ", str(PI['pkts']))
    #     else:
    #         result['megapkts'] += meg
    #         meg = convertToMegaByte(PI['bytes'])
    #         if meg < 0:
    #             logger.warning("Can't convert bytes", str(PI['bytes']))
    #         else:
    #             result['megabytes'] += meg
    #
    # policyPostInfo, chainPostInfo = findTheRelatedRulesInfo(id, iptables_nvL, "nat", "POSTROUTING")
    # for PI in chainPostInfo:
    #     meg = convertToMegaByte(PI['pkts'])
    #     if meg < 0:
    #         logger.warning("Can't convert packets ", str(PI['pkts']))
    #     else:
    #         result['megapkts'] += meg
    #         meg = convertToMegaByte(PI['bytes'])
    #         if meg < 0:
    #             logger.warning("Can't convert bytes", str(PI['bytes']))
    #         else:
    #             result['megabytes'] += meg
    #
    # if (not policyInfo or not chainInfo) and \
    #         (not policyPreInfo or not chainPreInfo) and \
    #         (not policyPostInfo or not chainPostInfo):
    #     return {}, {}, {}

    # return result, policyInfo, chainInfo
    return result


def add_rc_local_ha_commands():
    # most times when system reboot service corosync for some dependincies issue can not up successfully
    # so pacemaker will fail too. for this reason we should restart this services in rc.local.
    restart_cmd = 'service corosync restart\nservice pacemaker restart'
    cmd = 'grep -qxF "{restart_command}" {file} || echo "\n{restart_command}" >> {file}' \
        .format(restart_command=restart_cmd, file=RC_LOCAL_FILE)
    s, o = sudo_runner(cmd)
    if s:
        print_if_debug('HA: add restart pacemaker and corosync in rc.local')
    else:
        print_if_debug("HA: fail to add restart pacemaker and corosync in rc.local")
    return s


def add_rc_local_ha_commands_for_peer2(peer2_address, ssh_port, user='ngfw', password='ngfw'):
    restart_cmd = 'service corosync restart\nservice pacemaker restart'
    cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
          'sudo -S grep -qxF \'{restart_command}\' {file} || sudo -S bash -c \\" echo \'{restart_command}\' >> {file}\\""' \
        .format(user=user, ip=peer2_address, passwd=password,
                ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd, file=RC_LOCAL_FILE)
    s, o = command_runner(cmd)
    if not s:
        print_if_debug("HA: fail to add restart pacemaker and corosync in rc.local for {}".format(peer2_address))
    else:
        print_if_debug("HA: add restart pacemaker and corosync in rc.local for {}".format(peer2_address))
    return s


def remove_rc_local_ha_commands():
    try:
        status, content = sudo_file_reader(RC_LOCAL_FILE)
        cmd = 'service corosync restart\nservice pacemaker restart'
        if cmd in content:
            content = content.replace(cmd, '').strip()
            sudo_file_writer(RC_LOCAL_FILE, content, 'w')
        print_if_debug('HA: remove restart pacemaker and corosync from rc.local')
        return True
    except:
        print_if_debug('HA: fail to remove restart pacemaker and corosync from rc.local')
        return False


def remove_rc_local_ha_commands_for_peer2(peer2_address, ssh_port, user='ngfw', password='ngfw'):
    restart_cmd = 'service \(corosync\|pacemaker\) restart'
    cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
          'sudo -S sed -i \'s/{restart_command}//g\' {file} "' \
        .format(user=user, ip=peer2_address, passwd=password,
                ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, restart_command=restart_cmd, file=RC_LOCAL_FILE)
    s, o = command_runner(cmd)
    if not s:
        print_if_debug("HA: fail to delete restart pacemaker and corosync in rc.local for {}".format(peer2_address))
    else:
        print_if_debug("HA: delete restart pacemaker and corosync in rc.local for {}".format(peer2_address))
    return s


def restart_service_after_ha_remove_for_peer2(peer2_address, ssh_port, service_name, user='ngfw', password='ngfw'):
    restart_cmd = 'service {} restart'.format(service_name)
    cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
          'sudo -S {cmd} "' \
        .format(user=user, ip=peer2_address, passwd=password,
                ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH, cmd=restart_cmd)
    s, o = command_runner(cmd)
    if not s:
        print_if_debug("HA: fail to restart {} for {}".format(service_name, peer2_address))
    else:
        print_if_debug("HA: restart {} for {}".format(service_name, peer2_address))
    return s


def ha_auth_create_cluster_manage_resources(peer1_address, peer2_address, cluster_address_list):
    status = False
    if ha_authentication(peer1_address, peer2_address):
        if ha_cluster_setup_and_start(peer1_address, peer2_address):
            if ha_manage_resources(cluster_address_list):
                status = True
    return status


def systemctl_action_on_service(action, service):
    cmd = 'systemctl {action} {service}.service'.format(action=action, service=service)
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))
    return status


def disable_stop_ha_services(peer2_address, ssh_port, user='ngfw', password='ngfw'):
    # corosync and pacemaker services stop is done by deleting cluster
    systemctl_action_on_service('disable', 'pcsd')
    systemctl_action_on_service('disable', 'pacemaker')
    systemctl_action_on_service('disable', 'corosync')
    cmd = 'service pcsd stop'
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug("HA: {}".format(cmd))
    else:
        print_if_debug("HA: fail to run: {}".format(cmd))
    cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
          'sudo -S systemctl disable pcsd.service; ' \
          'sudo -S systemctl disable pacemaker.service;' \
          'sudo -S systemctl disable corosync.service; ' \
          'sudo -S service pcsd stop;"'.format(user=user, ip=peer2_address, passwd=password,
                                               ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
    s, o = command_runner(cmd)
    if not s:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))


def enable_start_ha_services():
    # corosync and pacemaker services start is done by creating cluster
    if systemctl_action_on_service('enable', 'pcsd'):
        if systemctl_action_on_service('enable', 'pacemaker'):
            if systemctl_action_on_service('enable', 'corosync'):
                cmd = 'service pcsd restart'
                status, result = sudo_runner(cmd)
                if status:
                    print_if_debug("HA: {}".format(cmd))
                    if add_rc_local_ha_commands():
                        return True
                    else:
                        print_if_debug("HA: fail to run: {}".format(cmd))
    return False


def enable_start_ha_services_on_peer2(peer2_address, ssh_port, user='ngfw', password='ngfw'):
    cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
          'sudo -S systemctl enable pcsd.service; ' \
          'sudo -S systemctl enable pacemaker.service;' \
          'sudo -S systemctl enable corosync.service; ' \
          'sudo -S service pcsd restart;"'.format(user=user, ip=peer2_address, passwd=password,
                                                  ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
    status, result = command_runner(cmd)
    if status:
        print_if_debug("HA: {}".format(cmd))
        if add_rc_local_ha_commands_for_peer2(peer2_address, ssh_port):
            return True
        else:
            print_if_debug("HA: fail to run: {}".format(cmd))
    return False


def ha_check_firewall_input(action, peer2_address, interface, ssh_port, https_port, user='ngfw'):
    if IS_TEST:
        return True
    cmd = 'curl -X "{act}" -d \'{{"ssh_port":"{ssh_port}", "interface":"{iface}"}}\' -k ' \
          'https://127.0.0.1:{https_port}/api/input-firewall/inputpolicies/ha_firewall_input'. \
        format(act=action, ssh_port=ssh_port, iface=interface, https_port=https_port)
    status, result = command_runner(cmd)
    if status:
        print_if_debug("HA: {}".format(cmd))
    else:
        print_if_debug("HA: fail to run: {}".format(cmd))
        return False
    cmd2 = 'timeout --foreground {duration} ssh -t {user}@{ip_address} -p {ssh_port} "{cmd}"'.format(
        duration=TIMEOUT_DURATION_FOR_SSH, user=user, ip_address=peer2_address, ssh_port=ssh_port, cmd=cmd)
    status, result = command_runner(cmd2)
    if status:
        print_if_debug("HA: {}".format(cmd2))
    else:
        print_if_debug("HA: fail to run: {}".format(cmd2))
        return False
    return True


def set_HA_configuration(instance, action, old_instance, request_username=None, request=None, details=None):
    ssh_port = Setting.objects.get(key='ssh-port').data['value']
    https_port = Setting.objects.get(key='https-port').data['value']
    try:
        configured_successfully = False
        if old_instance:
            old_instance_obj = HighAvailability()
            for key in old_instance:
                setattr(old_instance_obj, key, old_instance[key])
            setattr(instance, 'old', old_instance_obj)

            if instance.old.is_enabled and instance.is_enabled:
                ha_check_firewall_input('POST', instance.peer2_address,
                                        instance.configured_peer_interface_mac.split('#')[0], ssh_port, https_port)
                ha_destroy_cluster()
                if enable_start_ha_services():
                    if enable_start_ha_services_on_peer2(instance.peer2_address, ssh_port):
                        sleep(1)
                        if ha_auth_create_cluster_manage_resources(instance.peer1_address, instance.peer2_address,
                                                                   instance.cluster_address_list):
                            configured_successfully = True

            elif instance.old.is_enabled and not instance.is_enabled:
                remove_ha_config_on_peers(instance.peer1_address, instance.peer2_address,
                                          instance.configured_peer_interface_mac.split('#')[0],
                                          instance.id, ssh_port, https_port,
                                          action='disable')
                configured_successfully = True
            elif not instance.old.is_enabled and instance.is_enabled:
                if ha_check_firewall_input('POST', instance.peer2_address,
                                           instance.configured_peer_interface_mac.split('#')[0], ssh_port, https_port):
                    if enable_start_ha_services():
                        if enable_start_ha_services_on_peer2(instance.peer2_address, ssh_port):
                            sleep(1)
                            if ha_auth_create_cluster_manage_resources(instance.peer1_address, instance.peer2_address,
                                                                       instance.cluster_address_list):
                                configured_successfully = True
            else:
                configured_successfully = True
        else:
            if instance.is_enabled:
                if ha_check_firewall_input('POST', instance.peer2_address,
                                           instance.configured_peer_interface_mac.split('#')[0], ssh_port, https_port):
                    if enable_start_ha_services():
                        if enable_start_ha_services_on_peer2(instance.peer2_address, ssh_port):
                            sleep(1)
                            if ha_auth_create_cluster_manage_resources(instance.peer1_address, instance.peer2_address,
                                                                       instance.cluster_address_list):
                                configured_successfully = True
            else:
                configured_successfully = True
        if configured_successfully:
            from ha_syncer.config import sync_db_ha
            # databases should sync right after ha config, unless we maybe have some troubles in sync

            if sync_db_ha(instance.peer2_address, ssh_port, https_port):  # pending ha instance
                if sync_files_and_restart_related_services_on_peer2(instance.peer2_address, ssh_port):
                    instance.status = 'succeeded'
                    instance.save()
                    if sync_db_ha(instance.peer2_address, ssh_port, https_port):  # succeeded ha instance
                        log('config', 'ha_config', action, 'success',
                            username=request_username, ip=get_client_ip(request), details=details)
                        if not instance.is_enabled:
                            ha_check_firewall_input('DELETE', instance.peer2_address,
                                                    instance.configured_peer_interface_mac.split('#')[0], ssh_port,
                                                    https_port)
                        return True
        raise Exception

    except Exception as e:
        remove_ha_config_on_peers(instance.peer1_address, instance.peer2_address,
                                  instance.configured_peer_interface_mac.split('#')[0],
                                  instance.id, ssh_port, https_port, 'delete')
        instance.status = 'failed'
        instance.save()
        create_notification(source='HA', item={},
                            message=str('Error in {}ing HighAvailability'.format(action)), severity='e',
                            request_username=request_username)
        log('config', 'ha_config', action, 'fail',
            username=request_username, ip=get_client_ip(request), details=details)


def sync_files_and_restart_related_services_on_peer2(peer2_address, ssh_port, user='ngfw', password='ngfw'):
    from ha_syncer.config import sync_files

    if sync_files(peer2_address, ssh_port):
        cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
              'sudo -S systemctl daemon-reload;' \
              'sudo -S service nginx restart;' \
              '"'.format(user=user, ip=peer2_address, passwd=password,
                         ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
        status, result = command_runner(cmd)
        if status:
            print_if_debug("HA: {}".format(cmd))
            cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                  'sudo -S service ssh restart;' \
                  '"'.format(user=user, ip=peer2_address, passwd=password,
                             ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
            s, o = command_runner(cmd)
            if s:
                print_if_debug("HA: {}".format(cmd))
                cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "echo {passwd} | ' \
                      'sudo -S service fail2ban restart;' \
                      '"'.format(user=user, ip=peer2_address, passwd=password,
                                 ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
                command_runner(cmd)
                return True
            else:
                print_if_debug("HA: fail to run : {}".format(cmd))
                create_notification(source='HA', item={},
                                    message=str(
                                        'Caution! CLI pannel is out of service on Node2({}). '
                                        'update admin CLI ssh port on this system'.format(peer2_address)),
                                    severity='e', )
        else:
            print_if_debug("HA: fail to run : {}".format(cmd))
            create_notification(source='HA', item={},
                                message=str(
                                    'Caution! web engine is out of service on Node2({}). '
                                    'update admin UI ports on this system using CLI pannel'.format(peer2_address)),
                                severity='e', )
    return False


def ha_authentication(peer1_address, peer2_address):
    cmd = 'pcs cluster auth {peer1} {peer2} -u {user} -p {password}'.format(peer1=peer1_address, peer2=peer2_address,
                                                                            user=HA_USER, password=HA_CLUSTER_PASS)
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))
    return status


def set_cluster_config():
    # it's a 2-node configuration, and quorum as a concept makes no sense in this scenario
    #  you only have it when more than half the nodes are available
    cmd = 'pcs property set no-quorum-policy=ignore'
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
        return False
    print_if_debug("HA: {}".format(cmd))

    cmd = "pcs property set stonith-enabled=false"
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
        return False
    print_if_debug("HA: {}".format(cmd))
    return True


def ha_cluster_setup_and_start(peer1_address, peer2_address):
    cmd = "pcs cluster setup --name {cluster_name} {peer1_address} {peer2_address} --start --force --enable". \
        format(cluster_name=CLUSTER_NAME, peer1_address=peer1_address, peer2_address=peer2_address)
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
        return False
    print_if_debug("HA: {}".format(cmd))
    return set_cluster_config()


def destroy_ha_peer_cluster(peer1_address, peer2_address, ha_instance_id, ssh_port, https_port, user='ngfw'):
    list_of_ip_list = list(Interface.objects.filter().values_list('ip_list', flat=True))
    ip_list = [item['ip'] for ip_list in list_of_ip_list for item in ip_list]
    if peer1_address in ip_list:
        peer_address = peer2_address
    else:
        peer_address = peer1_address
    cmd = 'timeout --foreground {duration} ssh -t {user}@{ip_address} -p {ssh_port} "curl -X "DELETE" -k https://127.0.0.1:{https_port}/api/config/highavailability/{id}"'.format(
        user=user, https_port=https_port,
        ip_address=peer_address, id=ha_instance_id, ssh_port=ssh_port, duration=TIMEOUT_DURATION_FOR_SSH)
    status, result = command_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))
    return status


def ha_destroy_cluster():
    cmd = "pcs cluster stop"
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))
    cmd = "pcs cluster destroy --all"
    status, result = sudo_runner(cmd)
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))
    status, result = sudo_runner('rm /var/lib/pcsd/tokens')  # remove authenticated nodes
    if not status:
        print_if_debug("HA: fail to run: {}".format(cmd))
    else:
        print_if_debug("HA: {}".format(cmd))
    return status


def remove_ha_config_on_peers(peer1_address, peer2_address, interface, ha_instance_id, ssh_port, https_port, action):
    ha_destroy_cluster()
    remove_rc_local_ha_commands()
    if action == 'delete':
        destroy_ha_peer_cluster(peer1_address, peer2_address, ha_instance_id, ssh_port, https_port)
    disable_stop_ha_services(peer2_address, ssh_port)
    remove_rc_local_ha_commands_for_peer2(peer2_address, ssh_port)
    ha_check_firewall_input('DELETE', peer2_address, interface, ssh_port, https_port)
    sudo_runner('service ipsec restart')
    sudo_runner('service dnsmasq restart')
    sudo_runner('service ha_syncer restart')
    restart_service_after_ha_remove_for_peer2(peer2_address, ssh_port, 'ipsec')
    restart_service_after_ha_remove_for_peer2(peer2_address, ssh_port, 'dnsmasq')
    restart_service_after_ha_remove_for_peer2(peer2_address, ssh_port, 'ha_syncer')


def create_ip_resource_name(cidr):
    match_obj = re.search(r'(.*?)/(.*)', cidr)
    cluster_ip = match_obj.group(1)
    cluster_mask = match_obj.group(2)
    return "ClusterIP_{}_{}".format(cluster_ip, cluster_mask)


def ha_set_clusterip_resource(cluster_address_list):
    # cluster_address_list is like [{"nic":"ETH9", "cidr":"192.168.5.5/32"}, ...]
    for item in cluster_address_list:
        nic = item.get("nic")
        cidr = item.get("cidr")
        match_obj = re.search(r'(.*?)/(.*)', cidr)
        cluster_ip = match_obj.group(1)
        cluster_mask = match_obj.group(2)
        clusterip_name = create_ip_resource_name(cidr)
        sudo_runner('pcs resource delete {}'.format(clusterip_name))
        sleep(1)
        cmd = "pcs resource create {} ocf:heartbeat:IPaddr2 ip={} cidr_netmask={} nic={} op monitor interval=30s".format(
            clusterip_name, cluster_ip, cluster_mask, nic
        )
        status, result = sudo_runner(cmd)
        if not status:
            print_if_debug("HA: fail to run: {}".format(cmd))
            return False
        print_if_debug("HA: {}".format(cmd))
    return True


def ha_set_services_resource(service_list):
    for service in service_list:
        sudo_runner('pcs resource delete {service_name}'.format(service_name=service['name']))
        sleep(1)  # we need a gep time between delete and add resource
        cmd = 'pcs resource create {service_name} {service_type}:{service_name} op monitor interval=30s timeout=60s on-fail=ignore'.format(
            service_name=service['name'], service_type=service['type'])
        status, result = sudo_runner(cmd)
        if not status:
            print_if_debug("HA: fail to run: {}".format(cmd))
            return False
        print_if_debug("HA: {}".format(cmd))
    return True


def create_resources_colocation(cluster_address_list, service_list):
    try:
        main_resource = create_ip_resource_name(cluster_address_list[0].get("cidr"))
        rest_of_cluster_address_list = cluster_address_list.copy()
        rest_of_cluster_address_list.remove(cluster_address_list[0])
        ip_resource_list = []
        for item in rest_of_cluster_address_list:
            ip_resource_list.append(create_ip_resource_name(item.get("cidr")))
        service_name_list = []
        for service in service_list:
            service_name_list.append(service['name'])
        resource_list = list(set(ip_resource_list + service_name_list))
        for resource in resource_list:
            cmd = 'pcs constraint colocation add {} with {} INFINITY'.format(resource, main_resource)
            status, result = sudo_runner(cmd)
            if not status:
                print_if_debug("HA: fail to run: {}".format(cmd))
                return False
            print_if_debug("HA: {}".format(cmd))
        return True
    except Exception as e:
        print_if_debug("HA : fail to create colocation : {}".format(e))
        return False


def ha_manage_resources(cluster_address_list):
    if ha_set_clusterip_resource(cluster_address_list):
        service_list = [{'name': 'dnsmasq', 'type': 'lsb'},
                        {'name': 'ipsec', 'type': 'lsb'},
                        {'name': 'ha_syncer', 'type': 'systemd'}]
        if ha_set_services_resource(service_list):
            if create_resources_colocation(cluster_address_list, service_list):
                return True
    return False


def ha_remove_clusterip_config(cluster_address_list):
    for cidr in cluster_address_list:
        clusterip_name = create_ip_resource_name(cidr)
        cmd = "pcs resource delete {}".format(clusterip_name)
        status, result = sudo_runner(cmd)
        if not status:
            print_if_debug("HA: fail to run: {}".format(cmd))
            return False
        print_if_debug("HA: {}".format(cmd))
    return True


def get_nodes_info():
    ssh_port = Setting.objects.get(key='ssh-port').data['value']
    https_port = Setting.objects.get(key='https-port').data['value']
    if HighAvailability.objects.all():
        ha_config = HighAvailability.objects.all().get()
        peer1_hostname = get_peer_hostname(ha_config.peer1_address, ssh_port, https_port)
        peer2_hostname = get_peer_hostname(ha_config.peer2_address, ssh_port, https_port)
        return [{'hostname': peer1_hostname, 'ip': ha_config.peer1_address},
                {'hostname': peer2_hostname, 'ip': ha_config.peer2_address}]
    return None


def ha_read_status():
    node_info_list = get_nodes_info()
    active_node_dict = ""
    offline_node = ""
    alive_node_list = ""
    pcs_status = ""
    if node_info_list:
        cmd = 'pcs status resources'
        status, result = sudo_runner(cmd)
        if status:
            if re.search(r'\s*\(ocf::heartbeat:IPaddr2\):\s*Stopped\s*', result):
                pcs_status = 'pending'
            else:
                pcs_status = 'succeeded'

            try:
                active_node_hostname = re.search(r'\s*Started\s*(\S*)', result).group(1).strip()
                active_node_ip = ""
                for item in node_info_list:
                    if item['hostname'] == active_node_hostname:
                        active_node_ip = item['ip']
                active_node_dict = {'hostname': active_node_hostname, 'ip': active_node_ip}
            except AttributeError:
                active_node_dict = ""
        cmd = 'pcs status nodes'
        status, result = sudo_runner(cmd)
        if status:
            try:
                alive_node_list = re.search(r'\s*Pacemaker Nodes:\s*Online:\s(.*)', result).group(1).strip(" ").split(
                    " ")
            except AttributeError:
                alive_node_list = ""
            try:
                res = re.sub('Pacemaker\s*Remote\s*Nodes:(\s*\S*)*', '', result)
                offline_node = re.search(r'Pacemaker\s*Nodes:(\s*\S*)*\s*Offline:\s*(\S*)', res).group(2)
            except AttributeError:
                offline_node = ""
    return ({"active_node": active_node_dict,
             "offline_node": offline_node,
             "alive_node_list": alive_node_list,
             "node_info_list": node_info_list,
             "pcs_status": pcs_status})


def ha_configured_on_this_system():
    try:
        HA_config = HighAvailability.objects.get(is_enabled=True)
        ha_interface_info = re.findall(r'(\S*)#(\S*)', HA_config.configured_peer_interface_mac, re.M)
        ha_interface_name = ha_interface_info[0]
        ha_interface_mac = ha_interface_info[1]
        if Interface.objects.filter(name=ha_interface_name, mac=ha_interface_mac):
            return True
        return False
    except Exception:
        return False


def this_system_is_master(pcs_status):
    try:
        active_node = pcs_status['active_node']
        hostname_obj = Hostname.objects.get(key='host-name')
        if active_node['hostname'] == hostname_obj.data['value']:
            return True
    except:
        pass
    return False


def get_peer_hostname(ip_address, ssh_port, https_port, user='ngfw'):
    status, result = command_runner(
        'timeout --foreground {duration} ssh -t {user}@{ip_address} -p {ssh_port} "curl -k '
        'https://127.0.0.1:{https_port}/api/config/settings/host-name"'.format(
            user=user, https_port=https_port,
            ip_address=ip_address, duration=int(TIMEOUT_DURATION_FOR_SSH - 15), ssh_port=ssh_port))
    if status:
        try:
            hostname = re.findall('"data":{"value":"(\S*?)"', result, re.M)
            return hostname[0]
        except:
            return False
    return False


def get_peer2_version(ip_address, ssh_port, https_port, user='ngfw'):
    status, result = command_runner(
        'timeout --foreground {duration} ssh -t {user}@{ip_address}  -p {ssh_port} "curl -k '
        'https://127.0.0.1:{https_port}/api/version"'.format(
            user=user, https_port=https_port,
            ip_address=ip_address, duration=TIMEOUT_DURATION_FOR_SSH, ssh_port=ssh_port))
    if status:
        if "version" in result:
            try:
                version = re.findall('"version":\s*"(\S*?)"', result, re.M)
                return version[0]
            except Exception as e:
                print_if_debug('cannot get version of slave!')
                return None
        else:
            print_if_debug('slave doesn\'t reply to api request!')
            return None
    else:
        print_if_debug('slave is not in touch!')
        return None


def get_peer1_interface_name_list():
    interface_list = Interface.objects.all().order_by('name')
    interface_name_list = []
    for interface in interface_list:
        interface_name_list.append(interface.name)
    return sorted(interface_name_list)


def peer2_is_slave_static_ip(peer2_address, interfaces):
    if peer2_address in interfaces:
        return True
    return False


def get_peer2_interface_list(ip_address, ssh_port, https_port, user='ngfw'):
    status, result = command_runner(
        'timeout --foreground {duration} ssh -t {user}@{ip_address} -p {ssh_port} "curl -k '
        'https://127.0.0.1:{https_port}/api/config/interfaces?limit=99"'.format(
            user=user, https_port=https_port,
            ip_address=ip_address, duration=TIMEOUT_DURATION_FOR_SSH, ssh_port=ssh_port))
    if status:
        if 'results' in result:
            try:
                results = re.findall('{\s*\S*,"results":\[(\s*\S*)\]\s*\S*}', result, re.M)
                return results[0]
            except Exception as e:
                return []
        else:
            print_if_debug('slave doesn\'t reply to api request!')
            return []
    else:
        print_if_debug('slave is not in touch!')
        return []


def get_related_interface_name_of_peer2(peer2_address, interfaces):
    interface_list = interfaces.split('},{')
    for interface in interface_list:
        if peer2_address in interface:
            name = re.findall('"name":"([^"]+?)",', interface, re.M)
            return name[0]
    return False


def get_sorted_interface_name_list(interfaces):
    try:
        interface_name_list = re.findall('"name":"([^"]+?)",', interfaces, re.M)
        return sorted(list(set(interface_name_list)))
    except Exception as e:
        return []


def get_slave_ip_address(pcs_status):
    try:
        alive_node_list = pcs_status['alive_node_list']
        active_node = pcs_status['active_node']['hostname']
        node_info_list = pcs_status['node_info_list']
        if active_node in alive_node_list:
            alive_node_list.remove(active_node)
            slave_hostname = alive_node_list[0]
            for item in node_info_list:
                if item['hostname'] == slave_hostname:
                    slave_ip = item['ip']
                    return slave_ip
    except:
        pass
    return False


def change_or_add_key_to_content(regx, newvalue, content):
    (new_content, count) = re.subn(regx, newvalue, content)
    if not count:
        new_content = content + "\n" + newvalue
    return new_content


def static_route_error_message(result):
    error_message = result
    errors = {'Network is unreachable': 'Network is unreachable',
              'File exists': 'This static route exists'}
    for key in errors.keys():
        if key in result:
            error_message = errors[key]
    return error_message


def convert_chilli_config_to_json(instance):
    interface_config = Interface.objects.get(name=instance.lan_interface.name)
    data = {
        'wan': [(lambda item: item.name)(item) for item in instance.wan_interfaces.all()],
        'lan': instance.lan_interface.name,
        'network_mask': interface_config.ip_list[0]['mask'],
        'ip': interface_config.ip_list[0]['ip']
    }
    return data


def send_chilli_config_to_parser(instance, data, query):
    if query == "change_status":
        data = {'status': False}
        response = captive_portal_change_status_view(data)
    else:
        response = set_chilli_configs_view(data, "POST")


def create_static_route_options(route):
    device_interface = ""
    metric = ""

    if not route.destination_mask:
        route.destination_mask = 32

    if isinstance(route.destination_mask, str) and '.' in route.destination_mask:
        destination_cidr = convert_to_cidr(route.destination_ip, route.destination_mask)
    else:
        destination_cidr = '{}/{}'.format(route.destination_ip, route.destination_mask)

    try:
        network_cidr = str(IPNetwork('{}/{}'.format(route.destination_ip, route.destination_mask)).cidr)
    except Exception as err:
        raise serializers.ValidationError(str(err))

    if destination_cidr == network_cidr:
        dst = destination_cidr
    else:
        dst = route.destination_ip

    dst = dst.replace("/32", "")

    if route.interface:
        device_interface = 'dev {}'.format(route.interface.name)

    if route.metric:
        metric = 'metric {}'.format(route.metric)

    options = '{dst} via {gw} {interface} {metric}'.format(
        dst=dst, gw=route.gateway, interface=device_interface, metric=metric)
    return options


def create_static_route_cmd(route):
    options = create_static_route_options(route)
    cmd = 'ip route add {}'.format(options)
    return cmd


def delete_static_route_cmd(route):
    options = create_static_route_options(route)
    cmd = 'ip route del {}'.format(options)
    return cmd


def check_static_route_existence(route):
    cmd = "ip route"
    result_status, result = sudo_runner(cmd)
    if 'test' in sys.argv:
        s, result = command_runner('cat {}/route.txt'.format(TEST_PATH))

    exist = False
    for static_route in str(result).strip().split('\n'):
        if route.destination_ip in static_route and route.gateway in static_route:
            exist = True

            if route.destination_mask:
                if route.destination_mask != '32' and route.destination_mask != '255.255.255.255':
                    if "/{}".format(route.destination_mask) not in static_route:
                        exist = False

            if route.metric:
                if "metric {}".format(route.metric) not in static_route:
                    exist = False

            if route.interface:
                if "dev {}".format(route.interface) not in static_route:
                    exist = False

            if exist:
                break
    return True if exist else False

    # find = str(result).strip().replace(" ", "").find(static_route_line.replace(" ", ""))
    # return False if find == -1 else True


def dns_record_config(instance, action, old_ip_address, old_hostname_list,
                      request_username, request, changes, is_watcher=False):
    from report_app.models import Notification
    from report_app.utils import create_notification

    if is_watcher:  # Remove old notification when it was called by watcher. In other cases the remove will handled
        # in their related positions (for example delete or update)
        Notification.objects.filter(source='dns_record', item__id=instance.id).delete()

    ip_address = instance.ip_address
    if instance.hostname_list:
        hostname_list = sorted(instance.hostname_list)
        hostnames = "\t".join(hostname for hostname in hostname_list)

        if action == 'add':
            new_record = '{ip}\t{host}\n'.format(ip=ip_address, host=hostnames)
            status, result = sudo_runner('cat ' + DNS_HOST_LIST_FILE)
            if status:
                content = result + '\n' + new_record
                sudo_file_writer(DNS_HOST_LIST_FILE, content, 'r+')
            else:
                sudo_file_writer(DNS_HOST_LIST_FILE, new_record, 'a+')

            if not is_watcher:
                log('config', 'dns_record', action, 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)

        elif action == 'update':
            status, result = sudo_runner('cat ' + DNS_HOST_LIST_FILE)
            if status:
                old_hostname_list = sorted(old_hostname_list)
                old_hostnames = "\t".join(hostname for hostname in old_hostname_list)
                old_record = '{}\t{}'.format(old_ip_address, old_hostnames)
                if old_hostname_list:
                    content = ''
                    for line in result.split('\n'):
                        if old_record != line:
                            content += line + '\n'

                    new_record = '{ip}\t{host}\n'.format(ip=str(ip_address), host=str(hostnames))
                    content += new_record
                    sudo_file_writer(DNS_HOST_LIST_FILE, content, 'r+')

                    if not is_watcher:
                        log('config', 'dns_record', action, 'success',
                            username=request_username, ip=get_client_ip(request), details=changes)

        elif action == 'delete':
            record = '{ip}\t{host}'.format(ip=str(instance.ip_address), host=str(hostnames))
            status, result = sudo_runner('cat ' + DNS_HOST_LIST_FILE)
            if status:
                content = ''
                for line in result.split('\n'):
                    if record != line:
                        content += line + '\n'

                sudo_file_writer(DNS_HOST_LIST_FILE, content, 'r+')
                if not is_watcher:
                    log('config', 'dns_record', action, 'success',
                        username=request_username, ip=get_client_ip(request), details=changes)

        cmd = 'service dnsmasq reload'
        status, result = sudo_runner(cmd)
        if action != 'delete':
            if not status:
                instance.status = 'failed'
                instance.save()
                create_notification(source='dns_record', item={'id': instance.id},
                                    message=str('Error in config of DNS record'), severity='e',
                                    details={'command': cmd, 'error': str(result)},
                                    request_username=request_username)
                if not is_watcher:
                    log('config', 'dns_record', action, 'fail',
                        username=request_username, ip=get_client_ip(request), details=changes)
            else:
                instance.status = 'succeeded'
                instance.save()
                Notification.objects.filter(source='dns_record', item__id=instance.id).delete()
                if not is_watcher:
                    log('config', 'dns_record', action, 'success',
                        username=request_username, ip=get_client_ip(request), details=changes)


def dns_configuration(instance, request_username, request, changes, is_watcher=False):
    from report_app.models import Notification
    from report_app.utils import create_notification
    from parser_utils.mod_resource.utils import is_interface_active, get_interface_link_status

    primary_dns = instance.primary_dns_server
    secondary_dns = instance.secondary_dns_server
    tertiary_dns = instance.tertiary_dns_server
    local_domain = instance.local_domain
    is_strict_order = instance.is_strict_order
    interface_list = instance.interface_list.all()
    active_interfaces = []
    for interface in interface_list:
        if IS_TEST:
            active_interfaces.append(interface)
        elif is_interface_active(interface) and get_interface_link_status(interface):
            active_interfaces.append(interface)

    if primary_dns or secondary_dns or tertiary_dns:
        servers = 'nameserver ' + '\nnameserver '.join(filter(None, [primary_dns, secondary_dns, tertiary_dns]))
        sudo_file_writer(DNS_UPSTREAM_FILE, servers, 'w+')

    status, content = sudo_file_reader(DNSMASQ_CONFIG_FILE)
    if status:
        if local_domain:
            if '\nexpand-hosts' not in content:
                content += '\nexpand-hosts'
            if '\ndomain=' not in content:
                content += '\ndomain={}'.format(local_domain)
            else:
                content = re.sub(r'\ndomain=\S*', '\ndomain={}'.format(local_domain), content)
        else:
            if '\nexpand-hosts' in content:
                content = re.sub(r'\nexpand-hosts', '', content)
            if '\ndomain=' in content:
                content = re.sub('\ndomain=\S*', '', content)

        # if '\ninterface=' in content:
        #     content = re.sub(r'\ninterface=\s*\S*\n', '\ninterface={}\n'.format(interfaces),
        #                      content)
        # else:
        #     content += '\ninterface={}\n'.format(interfaces)

        if is_strict_order and '\nstrict-order' not in content:
            if '\nall-servers' in content:
                content = re.sub('\nall-servers', '', content)
            content += '\nstrict-order\n'
        if not is_strict_order and '\nall-servers' not in content:
            if '\nstrict-order' in content:
                content = re.sub('\nstrict-order', '', content)
            content += '\nall-servers\n'
        content = update_interface_dnsmasq(content)
        sudo_file_writer(DNSMASQ_CONFIG_FILE, content, 'r+')

    else:
        instance.status = 'failed'
        instance.save()
        if not is_watcher:
            log('config', 'dns_config', 'update', 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(content)})
        raise serializers.ValidationError({'non_field_errors': 'Can\'t find dns config files'})

    cmd = 'service dnsmasq restart'
    status, result = sudo_runner(cmd)
    if not status:
        instance.status = 'failed'
        instance.save()
        if not is_watcher:
            create_notification(source='dns_config', item={'id': instance.id},
                                message=str('Error in config of DNS server'), severity='e',
                                details={'command': cmd, 'error': str(result)},
                                request_username=request_username)
            log('config', 'dns_config', 'update', 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(result)})
    else:
        instance.status = 'succeeded'
        instance.save()
        if not is_watcher:
            log('config', 'dns_config', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)
        Notification.objects.filter(source='dns_config', item__id=instance.id).delete()


def remove_extra_dns_record(correct_content):
    sudo_file_writer(DNS_HOST_LIST_FILE, correct_content, 'r+')
    cmd = 'service dnsmasq reload'
    sudo_runner(cmd)


def dnsmasq_basic_config(dnsmasq_config, net_mng_config, dnsmasq_script_config):
    if dnsmasq_config:
        status, result = sudo_runner('cat ' + DNSMASQ_CONFIG_FILE)
        if status:
            content = result + dnsmasq_config
            sudo_file_writer(DNSMASQ_CONFIG_FILE, content, 'r+')
            cmd = 'service dnsmasq restart'
            sudo_runner(cmd)
    if net_mng_config:
        status, result = sudo_runner('cat ' + NETWORK_MANAGER_CONFIG_FILE)
        if status:
            content = re.sub(r'#dns=\s*\S*\n', 'dns=dnsmasq', result)
            sudo_file_writer(NETWORK_MANAGER_CONFIG_FILE, content, 'r+')
            cmd = 'service network-manager restart'
            sudo_runner(cmd)
    if dnsmasq_script_config:
        status, result = sudo_runner('cat ' + DNSMASQ_SCRIPT_FILE)
        if status:
            content = re.sub(r'RESOLV_CONF=\s*\S*', 'RESOLV_CONF={}\n'.format(DNS_UPSTREAM_FILE), result)
            sudo_file_writer(DNSMASQ_SCRIPT_FILE, content, 'r+')
            cmd = 'service dnsmasq restart'
            sudo_runner(cmd)


def generate_ssh_banner(message):
    """
    This method get a string and add # around it.
    It also add brand logo before message.
    :return: str
    """

    login_message_lines = message.split('\n')
    longest_line_length = len(max(login_message_lines, key=len))

    for i in range(len(login_message_lines)):
        l = int((longest_line_length - len(login_message_lines[i].strip())) / 2) + 1
        login_message_lines[i] = '#{0}{1}{0}#'.format(' ' * l, login_message_lines[i].strip())

    longest_line_length_after_padding = len(max(login_message_lines, key=len))
    for i in range(len(login_message_lines)):
        if len(login_message_lines[i]) < longest_line_length_after_padding:
            login_message_lines[i] = login_message_lines[i][:-1] + ' #'
    logo = None
    if BRAND == 'narin':
        logo = """
                 _   _               _        
                | \ | |  __ _  _ __ (_) _ __  
                |  \| | / _` || '__|| || '_ \ 
                | |\  || (_| || |   | || | | |
                |_| \_| \__,_||_|   |_||_| |_|                              
"""[1:] + '\n\n'
    elif BRAND == 'alamin':
        logo = """
                _    _                 _       
               / \  | | __ _ _ __ ___ (_)_ __  
              / _ \ | |/ _` | '_ ` _ \| | '_ \ 
             / ___ \| | (_| | | | | | | | | | |
            /_/   \_\_|\__,_|_| |_| |_|_|_| |_|       
"""[1:] + '\n\n'

    if message:
        result = '{1}{0}\n{2}\n{0}\n\n'.format('#' * (longest_line_length + 4), logo,
                                               '\n'.join(login_message_lines))

    else:
        result = logo

    return result


def config_narin_access_ports(new_setting, old_setting, request_username, request, changes, is_watcher=False):
    from report_app.models import Notification
    from report_app.utils import create_notification
    firewall_input_flag = False
    if old_setting.key == 'ssh-port':
        # if new_setting.data['value'] == old_setting.data['value']:
        #     return

        ssh_config_file = SSH_CONFIG_FILE
        status, result = sudo_runner('cat ' + ssh_config_file)
        if status:
            try:
                content = re.sub(r'Port\s*\S*', 'Port {}\n'.format(new_setting.data['value']), result)
                sudo_file_writer(ssh_config_file, content, 'r+')
                sudo_runner("systemctl daemon-reload")
                cmd = 'service sshd restart'
                status, result = sudo_runner(cmd)
                if not status:
                    new_setting.status = 'failed'
                    new_setting.save()
                    create_notification(source='access_ports', item={'id': new_setting.key},
                                        message=str('Error in config of ssh port'), severity='e',
                                        details={'command': cmd, 'error': str(result)},
                                        request_username=request_username)
                    if not is_watcher:
                        log('config', 'ssh-port', 'update', 'fail',
                            username=request_username, ip=get_client_ip(request), details={'error': str(result)})
                else:
                    firewall_input_flag = True

                    new_setting.status = 'succeeded'
                    new_setting.save()

                    if not is_watcher:
                        log('config', 'ssh-port', 'update', 'success',
                            username=request_username, ip=get_client_ip(request), details=changes)
                    Notification.objects.filter(source='access_ports_config',
                                                item__id=new_setting.key).delete()
            except Exception as e:
                if not is_watcher:
                    log('config', 'ssh-port', 'update', 'fail',
                        username=request_username, ip=get_client_ip(request), details={'error': str(e)})
                raise e

    elif old_setting.key == 'http-port':
        # if new_setting.data['value'] == old_setting.data['value']:
        #     return

        http_config_file = NGINX_CONFIG_FILE
        status, result = sudo_runner('cat ' + http_config_file)
        if status:
            try:
                content = re.sub(r'listen\s*\d*\s*default_server;\s*listen\s*\[::]:\d*\s*default_server;\n',
                                 'listen {port} default_server;\n    listen [::]:{port} default_server;\n'. \
                                 format(port=new_setting.data['value']), result)
                sudo_file_writer(http_config_file, content, 'r+')
                sudo_runner("systemctl daemon-reload")
                cmd = 'service nginx restart'
                status, result = sudo_runner(cmd)
                if not status:
                    new_setting.status = 'failed'
                    new_setting.save()
                    create_notification(source='access_ports', item={'id': new_setting.key},
                                        message=str('Error in config of http port'), severity='e',
                                        details={'command': cmd, 'error': str(result)},
                                        request_username=request_username)
                    if not is_watcher:
                        log('config', 'http-port', 'update', 'fail',
                            username=request_username, ip=get_client_ip(request), details={'error': str(result)})
                else:
                    firewall_input_flag = True
                    new_setting.status = 'succeeded'
                    new_setting.save()

                    if not is_watcher:
                        log('config', 'http-port', 'update', 'success',
                            username=request_username, ip=get_client_ip(request), details=changes)
                    Notification.objects.filter(source='access_port',
                                                item__id=new_setting.key).delete()

            except Exception as e:
                if not is_watcher:
                    log('config', 'http-port', 'update', 'fail',
                        username=request_username, ip=get_client_ip(request), details={'error': str(e)})
                raise e

    elif old_setting.key == 'https-port':
        # if new_setting.data['value'] == old_setting.data['value']:
        #     return

        http_config_file = NGINX_CONFIG_FILE
        status, result = sudo_runner('cat ' + http_config_file)
        if status:
            try:
                content = re.sub(
                    r'listen\s*\d*\s*ssl\s*http2\s*default_server;\s*listen\s*\[::]:\d*\s*ssl\s*http2\s*default_server;\n',
                    'listen {port} ssl http2 default_server;\n    listen [::]:{port} ssl http2 default_server;\n'. \
                        format(port=new_setting.data['value']), result)
                sudo_file_writer(http_config_file, content, 'r+')
                sudo_runner("systemctl daemon-reload")
                cmd = 'service nginx restart'
                status, result = sudo_runner(cmd)
                if not status:
                    new_setting.status = 'failed'
                    new_setting.save()
                    create_notification(source='ports_config', item={'id': new_setting.key},
                                        message=str('Error in config of https port'), severity='e',
                                        details={'command': cmd, 'error': str(result)},
                                        request_username=request_username)
                    if not is_watcher:
                        log('config', 'https-port', 'update', 'fail',
                            username=request_username, ip=get_client_ip(request), details={'error': str(result)})
                else:
                    firewall_input_flag = True
                    new_setting.status = 'succeeded'
                    new_setting.save()

                    if not is_watcher:
                        log('config', 'https-port', 'update', 'success',
                            username=request_username, ip=get_client_ip(request), details=changes)
                    Notification.objects.filter(source='access_ports_config',
                                                item__id=new_setting.key).delete()

            except Exception as e:
                if not is_watcher:
                    log('config', 'https-port', 'update', 'fail',
                        username=request_username, ip=get_client_ip(request), details={'error': str(e)})
                raise e
    if firewall_input_flag:
        check_and_ignore_our_ports_from_nat()
        apply_rule(None, None)


def iptables_append(cmd):
    check_cmd = 'iptables -w -C {}'.format(cmd)
    status, result = sudo_runner(check_cmd)

    if not status:
        sudo_runner('iptables -w -A {}'.format(cmd))


def iptables_insert(cmd):
    check_cmd = 'iptables -w -C {}'.format(cmd)
    status, result = sudo_runner(check_cmd)
    if not status:
        return sudo_runner('iptables -w -I {}'.format(cmd))

    return True, ""


def check_and_ignore_our_ports_from_nat():
    chain = "head_rules"

    cmd = "iptables -w -t nat -N {}".format(chain)
    s, o = sudo_runner(cmd)
    if not s:
        sudo_runner("iptables -w -t nat -F {}".format(chain))

    iptables_insert("PREROUTING -t nat -j {}".format(chain))

    narin_ports = '{0},{1},{2}'.format(Setting.objects.get(key='ssh-port').data['value'],
                                       Setting.objects.get(key='http-port').data['value'],
                                       Setting.objects.get(key='https-port').data['value'])

    iptables_insert("{} -t nat -p tcp -mmultiport --dports {} -j ACCEPT".format(chain, narin_ports))


def open_port_in_iptables(new_port=None, old_port=None, direction='dport'):
    if old_port:
        cmd = 'iptables -w -D INPUT -p tcp --{} {} -j ACCEPT '.format(direction, old_port)
        sudo_runner(cmd)

    insert_status = True
    if new_port:
        cmd = 'INPUT -p tcp --{} {}  -j ACCEPT'.format(direction, new_port)
        s, o = iptables_insert(cmd)
        insert_status = s

    sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
    cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
    sudo_runner(cmd)

    if not insert_status:
        raise serializers.ValidationError({'non_field_errors': 'Can\'t open required port(s) in firewall'})


def set_system_interfaces():
    interfaces = get_network_interfaces()
    current_system_mac_list = []
    current_system_interface_name_list = []
    Notification.objects.filter(source='auto_fix_inter').delete()
    for idx, item in enumerate(interfaces):
        mac = get_interface_mac(item, False)
        current_system_mac_list.append(mac)
        current_system_interface_name_list.append(item)

        try:
            found_interfaces = Interface.objects.filter(name__exact=item).order_by('name')
            if found_interfaces:
                found_interfaces[0].alias = item
                found_interfaces[0].mac = mac
                found_interfaces[0].save()
                # config_network_interface(found_interfaces[0])
                if found_interfaces.count() > 1:
                    for i in range(1, found_interfaces.count()):
                        sudo_runner('nmcli con del {}'.format(found_interfaces[i].name))
                        sudo_runner('nmcli con del {}_con'.format(found_interfaces[i].name))
                        found_interfaces[i].delete()
                continue

            found_interfaces = Interface.objects.filter(name__iexact=item).order_by('name')
            if found_interfaces:
                found_interfaces[0].name = item
                found_interfaces[0].alias = item
                found_interfaces[0].mac = mac
                found_interfaces[0].save()
                config_network_interface(found_interfaces[0])

                if found_interfaces.count() > 1:
                    for i in range(1, found_interfaces.count()):
                        sudo_runner('nmcli con del {}'.format(found_interfaces[i].name))
                        sudo_runner('nmcli con del {}_con'.format(found_interfaces[i].name))
                        found_interfaces[i].delete()
                continue

            # found_interfaces = Interface.objects.filter(mac__iexact=mac).order_by('name')
            # if found_interfaces:
            #     found_once = False
            #     for inter in found_interfaces:
            #         if inter.name != item or found_once:  # Remove all items that have same mac with different name
            #             sudo_runner('nmcli con del {}'.format(inter.name))
            #             sudo_runner('nmcli con del {}_con'.format(inter.name))
            #             inter.delete()
            #         else:
            #             found_once = True
            #             inter.alias = item
            #             inter.save()
            #             config_network_interface(inter)
            #     if found_once:
            #         continue
        except Interface.DoesNotExist:
            pass

        use_nmcli = False

        # Check if this interface has a related connection name in nmcli
        # NOTE: the return of get_interface_connection doesn't indicate whether or not the interface is
        # related to Network-manager connections
        connection_name = get_interface_active_connection(item)

        if connection_name:
            if not connection_name == "{}_con".format(item):
                rename_cmd = "nmcli connection modify '{}' connection.id {}_con".format(connection_name, item)
                sudo_runner(rename_cmd)
            use_nmcli = True

        is_enabled = True  # Always add new interfaces with enabled mode
        is_default_gateway = False
        ip_list = []
        gateway = None
        is_dhcp_enabled = True if get_interface_method(connection_name, item,
                                                       use_nmcli) == 'auto' else False
        if get_primary_default_gateway_interface_name() == item:
            is_default_gateway = True

        if not is_dhcp_enabled:
            ip_list = get_interface_ip(item, use_nmcli)
            gateway = get_interface_gateway(item, use_nmcli)
            if not ip_list:
                count = 0
                num = 0
                for i in range(len(item) - 1, -1, -1):
                    if item[i].isdigit():
                        num += (pow(10, count) * int(item[i]))
                    else:
                        break
                    count += 1

                ip_list = [{"ip": "192.168.{}.200".format(num), "mask": "255.255.255.0"}]

        interface = Interface.objects.filter(name=item)
        if interface:
            interface = interface[0]  # Use the first founded interface as interface, it will be used later
            interface[0].mac = mac
            interface[0].save()
        else:
            interface = Interface.objects.create(name=item,
                                                 mac=mac,
                                                 gateway=gateway,
                                                 is_enabled=is_enabled,
                                                 ip_list=ip_list,
                                                 is_dhcp_enabled=is_dhcp_enabled,
                                                 alias=item,
                                                 is_default_gateway=is_default_gateway)

        cmd = 'nmcli dev set {} managed yes'.format(item)
        sudo_runner(cmd)

        config_network_interface(interface)
        # TODO
        # qos_configs = models.qos_and_traffic_shaping.objects.filter(wan_interface__name = item)
        # if not qos_configs:
        #     models.qos_and_traffic_shaping.objects.create(wan_interface=interface,enabled=False,guaranteed_bandwidth_d=100,guaranteed_bandwidth_u=100,status=0,guaranteed_bandwidth_type_d='Mbitps',guaranteed_bandwidth_type_u='Mbitps')

    # Create a new udev file and make sure that anything is ok on it!
    new_udev_content = ""
    interface_count = 0
    current_system_mac_list.sort()
    for mac in current_system_mac_list:
        new_udev_content += 'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{{address}}=="{}", ' \
                            'ATTR{{type}}=="1", NAME="ETH{}"\n'.format(mac.lower(), interface_count)
        interface_count += 1

    status, current_udev_content = sudo_file_reader("/etc/udev/rules.d/70-persistent-net.rules")
    if status and current_udev_content != new_udev_content:
        sudo_file_writer("/etc/udev/rules.d/70-persistent-net.rules", new_udev_content, 'w')
        create_notification(source='auto_fix_inter', item='',
                            message=str('We have made changes to this version that need rebooting the system, '
                                        'please restart the system (use CLI to do this)'), severity='e',
                            details={'error': str('The udev file is not related to this system')},
                            request_username="system")
    else:
        # Remove all interfaces that are not exists in the system. This section will useful when the installed version
        # of the product on a system moved to another system with different interfaces list!
        all_not_existed_interfaces = Interface.objects.exclude(mac__in=current_system_mac_list,
                                                               name__in=current_system_interface_name_list)
        for inter in all_not_existed_interfaces:
            if inter.mode == 'interface':
                sudo_runner('nmcli con del {}'.format(inter.name))
                sudo_runner('nmcli con del {}_con'.format(inter.name))
                inter.delete()
        # TODO remove all Wired... connections


def set_ntp_server(ntp_config, request_username):
    """
        This function takes a parameter (ntp server) and clears every line that
        starts with "server" or "pool" (/etc/ntp.conf), then adds a line at
        the end of file and call ntpdate to apply it.
    """
    sudo_runner('service ntp stop')
    status, content = sudo_file_reader(NTP_CONFIG_FILE)
    if status:
        new_content = re.sub(r'\npool.+', '', content)
        new_content = re.sub(r'\nserver.+\n', '', new_content)
        set_date = False
        for addr in ntp_config.ntp_server_list:
            new_content += '\nserver %s \n' % addr
            if not set_date:
                result, output = sudo_runner("ntpdate {}".format(addr))
                if result:
                    set_date = True
                else:
                    create_notification(source='ntp', item={'id': ntp_config.id},
                                        message=str('Error in setting NTP servers'), severity='e',
                                        details={'error': str('Can not set NTP server address for {}'.format(addr))},
                                        request_username=request_username)
        sudo_file_writer(NTP_CONFIG_FILE, new_content, 'w+')
        sudo_runner('service ntp start')
        return True
    else:
        ntp_config.status = 'failed'
        ntp_config.save()
        create_notification(source='ntp', item={'id': ntp_config.id},
                            message=str('Error in setting NTP servers'), severity='e',
                            details={'error': str('Can not set NTP server address')},
                            request_username=request_username)
        sudo_runner('service ntp start')
        return False


def config_ntp_server(instance_id, request_username, request, is_watcher=False):
    ntp_config = NTPConfig.objects.get(id=instance_id)
    request_username = request_username
    Notification.objects.filter(source='ntp', item__id=instance_id).delete()
    if ntp_config.is_enabled:
        run_thread(target=set_ntp_server, name='ntp', args=(ntp_config, request_username))
        status = True
        result = ""
    else:
        status, result = sudo_runner('service ntp stop')

    if status:
        ntp_config.status = 'succeeded'
        ntp_config.save()
    else:
        ntp_config.status = 'failed'
        ntp_config.save()
        create_notification(source='ntp', item={'id': ntp_config.id, 'name': "NTPConfig"},
                            message=str('Error in setting NTP servers'), severity='e',
                            details={'command': "service ntp stop", 'error': str(result)},
                            request_username=request_username)
        if not is_watcher:
            log('config', 'ntp-setting', 'update', 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(result)})


def create_snmp_agent(snmp_instance):
    ''' This Function is not used yet, because of some Reason is decided, this Configuration which use for Interface
    Configuration ,should be deactivated '''
    for ip_entity in snmp_instance.interface.ip_list:
        ip = convert_to_cidr(ip_entity['ip'], ip_entity['mask'])
        if ip:
            config_agent += "\nagentAddress\t" + "udp:" + ip + ":161\n"
        else:
            config_agent = "agentAddress\t" + "udp:" + "0.0.0.0" + ":161\n"
        sudo_file_writer("etc/snmp/agent.conf", config_agent, "w+")


def checkfile_snmpv2(snmp_instance):
    ip = snmp_instance.allow_network
    with open(SNMP_V2_CONFIG_FILE) as snmpv2_configfile:
        content = "\n".join(snmpv2_configfile.readlines())
        if ip in content:
            return True

    return False


def checkfile_snmpv3(snmp_instance):
    username = snmp_instance.user_name
    with open(SNMP_V3_CONFIG_FILE) as snmpv3_configfile:
        content = "\n".join(snmpv3_configfile.readlines())
    if username in content:
        return True

    return False


def create_snmpv3_user(snmp_instance, request_username, request, details, operation, is_watcher=False):
    '''This Function Provides Creation of User on SNMPv3 Service.the Result of this Function is so
    # createUser “username”  Hashalgorithm  “password” EncryptionAlgorithm  “password”   '''

    config = "\ncreateUser " + snmp_instance.user_name + "\t"
    if snmp_instance.security_level == "priv":
        config += snmp_instance.authentication_algorithm.upper() + "\t" + \
                  snmp_instance.authentication_password + "\t" + snmp_instance.private_algorithm.upper() + "\t" + \
                  snmp_instance.private_password + "\n"

    elif snmp_instance.security_level == "auth":
        config += snmp_instance.authentication_algorithm.upper() + "\t" + \
                  snmp_instance.authentication_password + "\n"

    status, output = sudo_file_writer(VAR_LIB_SNMP_CONFIG_FILE, config, "a+")
    if not status:
        if is_watcher:
            log('config', 'log-servers', operation, 'fail',
                username="api", ip="127.0.0.1", details={'error': str(output)})
        else:
            log('config', 'log-servers', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
        return False
    else:
        return True


def create_snmpv3_config(snmp_instance, request_username, request, details, operation, is_watcher=False):
    config_snmpv3 = "\nrouser " + snmp_instance.user_name + " " + snmp_instance.security_level + " .1" + "\n"
    status, output = sudo_file_writer(SNMP_V3_CONFIG_FILE, config_snmpv3, "a+")
    if not status:
        if is_watcher:
            log('config', 'log-servers', operation, 'fail',
                username="api", ip="127.0.0.1", details={'error': str(output)})
        else:
            log('config', 'log-servers', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
        return False
    else:
        return True


def create_snmpv2_config(snmp_instance, request_username, request, details, operation, is_watcher=False):
    '''This Function Provides Configuration of SNMPv2 Service.the Result of this Function is so: com2sec allThings
        allowed IP Community Name'''

    snmpv2_config = ''
    allowed_ip = snmp_instance.allow_network
    if allowed_ip:
        snmpv2_config += "\ncom2sec\t" + "allThings\t" + allowed_ip + "\t" + snmp_instance.community_name + "\n"
    else:
        snmpv2_config = "\ncom2sec\t" + "allThings\t" + "default" + "\t" + snmp_instance.community_name + "\n"
    status, output = sudo_file_writer(SNMP_V2_CONFIG_FILE, snmpv2_config, "a+")
    if not status:
        if is_watcher:
            log('config', 'log-servers', operation, 'fail',
                username="api", ip="127.0.0.1", details={'error': str(output)})
        else:
            log('config', 'log-servers', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
        return False
    else:
        return True


def set_snmpv2(snmp_instance, request_username, request, details, operation):
    snmp_restart = "service snmpd restart "
    function_status = create_snmpv2_config(snmp_instance, request_username, request, details, operation)
    if not function_status:
        return False
    else:
        status, output = sudo_runner(snmp_restart)
        if not status:
            log('config', 'snmp', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
            create_notification(source='snmp', item={'id': snmp_instance.id},
                                message=str('Error in setting SNMP'), severity='e',
                                details={'error': str(output), 'command': output},
                                request_username=request_username)
            return False
        else:
            log('config', 'snmp', operation, 'success', username=request_username, ip=get_client_ip(request),
                details=details)
            return True


def set_snmpv3(snmp_instance, request_username, request, details, operation):
    snmp_stop = "service snmpd stop"
    snmp_start = "service snmpd start"
    status, output = sudo_runner(snmp_stop)
    if not status:
        sudo_runner("killall snmpd")

    status_output1 = create_snmpv3_user(snmp_instance, request_username, request, details, operation)
    status_output2 = create_snmpv3_config(snmp_instance, request_username, request, details, operation)
    if not (status_output1 and status_output2):
        return False
    else:
        status, output = sudo_runner(snmp_start)
        if not status:
            log('config', 'snmp', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
            create_notification(source='snmp', item={'id': snmp_instance.id},
                                message=str('Error in setting SNMP'), severity='e',
                                details={'error': str(output), 'command': output},
                                request_username=request_username)
            return False
        else:
            log('config', 'snmp', operation, 'success', username=request_username, ip=get_client_ip(request), \
                details=details)
            return True


def create_rsyslog_server_config(rsyslog_server):
    return create_rsyslog_server_config_for_ip_address(rsyslog_server.address, rsyslog_server.port,
                                                       rsyslog_server.protocol, rsyslog_server.is_secure,
                                                       rsyslog_server.service_list)


def create_rsyslog_server_config_for_ip_address(address, port, protocol, is_secure, service_list):
    config = ''
    l3_sign = ''

    # format filename for unique : 'address-tcp-port'

    filename = '-'.join([address.replace('.', '-'), protocol, str(port)])

    if protocol == 'tcp' and is_secure:
        l3_sign = 'action(type="omfwd" target = "{0}" port = "{1}" protocol = "{2}" ' \
                  ' TCP_Framing="octet-counted" StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/certvalid"' \
                  ' rebindinterval = "10000"  queue.filename = "{3}" queue.type = "fixedarray" queue.size = "100")'.format(
            address, port, protocol, filename)

    else:

        l3_sign = 'action(type="omfwd" target = "{0}" port = "{1}" protocol = "{2}"' \
                  '  rebindinterval = "10000" queue.filename = "{3}" queue.type = "fixedarray" queue.size = "100")'.format(
            address, port, protocol, filename)

    if 'admin-log' in service_list:
        config += "$msg contains\', \"operation\": ' "

    if 'firewall' in service_list:
        if config:
            config += " or $msg contains \"[f:\" "
        else:
            config += "$msg contains \"[f:\" "

    if 'ssh' in service_list:
        if config:
            config += "or $msg contains \"sshd\" "
        else:
            config += "$msg contains \"sshd\" "

    if 'vpn' in service_list:
        if config:
            config += "or $msg contains \"[NET] \" or "
        else:
            config += "$msg contains \"[NET] \" or "

        config += "$msg contains \"[MGR] \" or "

        config += "$msg contains \"[IKE] \" or "

        config += "$msg contains \"[JOB] \" or "

        config += "$msg contains \"[ENC] \" or "

        config += "$msg contains \"[CFG] \" or "

        config += "$msg contains \"[LIB] \" or "

        config += "$msg contains \"[KNL] \" "

    config = 'if ' + config + " then " + l3_sign + "  #set_by_narin_admin\n"
    return config


def set_rsyslog_server(rsyslog_server, request_username, request, details, operation, is_watcher=False):
    config = create_rsyslog_server_config(rsyslog_server)
    s, o = sudo_file_writer(RSYSLOG_CONFIG_FILE, config, 'a')
    if not s:
        log('config', 'log-servers', operation, 'fail',
            username=request_username, ip=get_client_ip(request), details={'error': str(o)})
        return False

    s, o = sudo_restart_systemd_service('rsyslog')

    if not s:
        log('config', 'log-servers', operation, 'fail',
            username=request_username, ip=get_client_ip(request), details={'error': str(o)})
        create_notification(source='rsyslog', item={'id': rsyslog_server.id},
                            message=str('Error in setting syslog servers'), severity='e',
                            details={'error': str(o), 'command': o},
                            request_username=request_username)
        return False

    if not is_watcher:
        log('config', 'log-servers', operation, 'success',
            username=request_username, ip=get_client_ip(request), details=details)

    return True


def remove_rsyslog_server(rsyslog_server, request_username, request, details, operation, is_watcher=False):
    s, o = sudo_file_reader(RSYSLOG_CONFIG_FILE)
    if not s:
        if not is_watcher:
            log('config', 'log-servers', operation, 'success',
                username=request_username, ip=get_client_ip(request), details=rsyslog_server)

        rsyslog_server.status = 'failed'
        rsyslog_server.save()
        raise serializers.ValidationError({'non_field_errors': 'Can\'t read syslog configs'})

    current_config = create_rsyslog_server_config(rsyslog_server)
    new_content = o.replace(current_config, '')

    s, o = sudo_file_writer(RSYSLOG_CONFIG_FILE, new_content, 'w')
    if not s:
        if not is_watcher:
            log('config', 'log-servers', operation, 'success',
                username=request_username, ip=get_client_ip(request), details=rsyslog_server)
        rsyslog_server.status = 'failed'
        rsyslog_server.save()
        raise serializers.ValidationError({'non_field_errors': 'Can\'t read syslog configs'})
    sudo_restart_systemd_service('rsyslog')


def remove_snmpv2_config(snmp_instance, request_username, request, details, operation, is_watcher=False):
    status, output = sudo_file_reader(SNMP_V2_CONFIG_FILE)
    if not status:
        if is_watcher:
            log('config', 'snmp', operation, 'fail',
                username="api", ip="127.0.0.1", details={'error': str(output)})
        else:
            log('config', 'snmp', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
            create_notification(source='snmp', item={'id': snmp_instance.id},
                                message=str('Cant read snmp config files during removing snmpv2 configs'), severity='e',
                                details={'error': str(output), 'command': output},
                                request_username=request_username)
        return False
    else:
        ipadd = snmp_instance.allow_network
        new_content = re.sub(r'\n.+%s' % ipadd + ".+\n", '', output)
        status, output = sudo_file_writer(SNMP_V2_CONFIG_FILE, new_content, "w")
        if not status:
            if is_watcher:
                log('config', 'snmp', operation, 'fail',
                    username="api", ip="127.0.0.1", details={'error': str(output)})
            else:
                log('config', 'snmp', operation, 'fail',
                    username=request_username, ip=get_client_ip(request), details={'error': str(output)})
                create_notification(source='snmp', item={'id': snmp_instance.id},
                                    message=str('Cant write snmp config files during snmpv2 configurations change'),
                                    severity='e',
                                    details={'error': str(output), 'command': output},
                                    request_username=request_username)
            return False
        else:
            status, output = sudo_restart_systemd_service("snmpd")
            if not status:
                if is_watcher:
                    log('config', 'snmp', operation, 'fail',
                        username="api", ip="127.0.0.1", details={'error': str(output)})
                else:
                    log('config', 'snmp', operation, 'fail',
                        username=request_username, ip=get_client_ip(request), details={'error': str(output)})
                    create_notification(source='snmp', item={'id': snmp_instance.id},
                                        message=str(' Error in setting SNMPV2'), severity='e',
                                        details={'error': str(output), 'command': output},
                                        request_username=request_username)
                return False
            else:
                log('config', 'snmp', operation, 'success', username=request_username, ip=get_client_ip(request), \
                    details=details)
                return True


def remove_snmpv3_config(snmp_instance, request_username, request, details, operation, is_watcher=False):
    status, output = sudo_file_reader(SNMP_V3_CONFIG_FILE)
    username = snmp_instance.user_name
    if not status:
        if is_watcher:
            log('config', 'snmp', operation, 'fail',
                username="api", ip="127.0.0.1", details={'error': str(output)})
        else:
            log('config', 'snmp', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
            create_notification(source='snmp', item={'id': snmp_instance.id},
                                message=str('Cant read snmp config files during removing snmpv3 configs'), severity='e',
                                details={'error': str(output), 'command': output},
                                request_username=request_username)
        return False
    else:
        new_content = re.sub(r'\n.+%s' % ("\\b" + username) + "\\b.+\n", '', output)
        status, output = sudo_file_writer(SNMP_V3_CONFIG_FILE, new_content, "w")
        if not status:
            if is_watcher:
                log('config', 'snmp', operation, 'fail',
                    username="api", ip="127.0.0.1", details={'error': str(output)})
            else:
                log('config', 'snmp', operation, 'fail',
                    username=request_username, ip=get_client_ip(request), details={'error': str(output)})
                create_notification(source='snmp', item={'id': snmp_instance.id},
                                    message=str("Cant write snmp config files during snmpv3 configurations change"),
                                    severity='e',
                                    details={'error': str(output), 'command': output},
                                    request_username=request_username)

            return False
        else:
            status, output = sudo_file_reader(VAR_LIB_SNMP_CONFIG_FILE)
            if not status:
                if is_watcher:
                    log('config', 'snmp', operation, 'fail',
                        username="api", ip="127.0.0.1", details={'error': str(output)})
                else:
                    log('config', 'snmp', operation, 'fail',
                        username=request_username, ip=get_client_ip(request), details={'error': str(output)})
                    create_notification(source='snmp', item={'id': snmp_instance.id},
                                        message=str('Cant read snmp config files during removing snmpv3 configs '),
                                        severity='e',
                                        details={'error': str(output), 'command': output},
                                        request_username=request_username)
                return False
            else:
                # new_content = re.sub(r'\n.+%s\"' % username + "\"" + ".+\n", '', output)
                new_content = re.sub(r'\n.+%s\"' % username + "\".+\n", '', output)
                status, output = sudo_runner("service snmpd stop")
                if not status:
                    if is_watcher:
                        log('config', 'snmp', operation, 'fail',
                            username="api", ip="127.0.0.1", details={'error': str(output)})
                    else:
                        log('config', 'snmp', operation, 'fail',
                            username=request_username, ip=get_client_ip(request), details={'error': str(output)})
                        create_notification(source='snmp', item={'id': snmp_instance.id},
                                            message=str('Cant change SNMP configuration'), severity='e',
                                            details={'error': str(output), 'command': output},
                                            request_username=request_username)
                    return False
                else:
                    status, output = sudo_file_writer(VAR_LIB_SNMP_CONFIG_FILE, new_content, "w")
                    if not status:
                        if is_watcher:
                            log('config', 'snmp', operation, 'fail',
                                username="api", ip="127.0.0.1", details={'error': str(output)})
                        else:
                            log('config', 'snmp', operation, 'fail',
                                username=request_username, ip=get_client_ip(request), details={'error': str(output)})
                            create_notification(source='snmp', item={'id': snmp_instance.id},
                                                message=str(
                                                    "Cant write snmp config files during Configuration's Change"),
                                                severity='e',
                                                details={'error': str(output), 'command': output},
                                                request_username=request_username)
                        return False
                    else:
                        status, output = sudo_runner("service snmpd start")
                        if not status:
                            snmp_instance.status = 'fail'
                            snmp_instance.save()
                            if is_watcher:
                                log('config', 'snmp', operation, 'fail',
                                    username="api", ip="127.0.0.1", details={'error': str(output)})
                            else:
                                log('config', 'snmp', operation, 'fail',
                                    username=request_username, ip=get_client_ip(request),
                                    details={'error': str(output)})
                                create_notification(source='snmp', item={'id': snmp_instance.id},
                                                    message=str('Error in setting SNMP'),
                                                    severity='e',
                                                    details={'error': str(output), 'command': output},
                                                    request_username=request_username)
                            return False
                        else:
                            log('config', 'snmp', operation, 'success', username=request_username,
                                ip=get_client_ip(request), details=details)
                            return True


def replace_or_insert_in_content(content, key, whole_text):
    if '\n{}'.format(key) not in content:
        content += '\n{}'.format(whole_text)
    else:
        content = re.sub(r'\n{}\s*\S*\n'.format(key), '\n', content)
        content += '\n{}\n'.format(whole_text)
    return content


def update_interafce_list_in_content(content):
    dhcp_interface_list = []
    sleep(0.1)
    DHCP_config_list = DHCPServerConfig.objects.filter(is_enabled=True)
    for config in DHCP_config_list:
        if config.last_operation != 'delete':
            dhcp_interface_list.append(config.interface.name)
    interface_list = Interface.objects.filter()
    no_dhcp_interface_config = 'no-dhcp-interface='
    for interface in interface_list:
        if interface.name not in dhcp_interface_list:
            no_dhcp_interface_config += '{},'.format(interface.name)
    no_dhcp_interface_config = no_dhcp_interface_config.strip(',')
    no_dhcp_interface_config += '\n'
    content = replace_or_insert_in_content(content, 'no-dhcp-interface=', no_dhcp_interface_config)
    content = update_interface_dnsmasq(content)
    return content


def dnsmasq_interfaces():
    interfaces = ""
    dns_config = DNSConfig.objects.all()
    if dns_config:
        dns_interface_list = dns_config[0].interface_list.all()
        for interface in dns_interface_list:
            interfaces += '{},'.format(interface.name)
    sleep(0.1)
    dhcp_config_list = DHCPServerConfig.objects.filter(is_enabled=True)
    for config in dhcp_config_list:
        if config.last_operation != 'delete':
            if config.interface.name not in interfaces:
                interfaces += '{},'.format(config.interface.name)
    # dhcp_config = DHCPServerConfig.objects.all()
    # if dhcp_config:
    #     if dhcp_config[0].last_operation != 'delete' and dhcp_config[0].is_enabled:
    #         if dhcp_config and dhcp_config[0].interface and dhcp_config[0].interface.name not in interfaces:
    #             interfaces += dhcp_config[0].interface.name
    return interfaces


def update_interface_dnsmasq(content):
    interfaces = dnsmasq_interfaces()
    if interfaces == "":
        new_content = replace_or_insert_in_content(content, 'interface=', 'interface=lo\n')
    else:
        new_content = replace_or_insert_in_content(content, 'interface=',
                                                   'interface={}\n'.format(interfaces.strip(',')))
    return new_content


def set_DHCP_configuration(instance, old_instance, action, request_username=None, request=None, details=None,
                           is_watcher=False):
    import socket
    import struct
    try:
        Notification.objects.filter(source='dhcp', item__id=instance.id).delete()
        if old_instance:
            old_instance_obj = DHCPServerConfig()
            for key in old_instance:
                setattr(old_instance_obj, key, old_instance[key])
            setattr(instance, 'old', old_instance_obj)

        if instance.is_enabled:
            status, content = sudo_file_reader(DNSMASQ_CONFIG_FILE)
            if status:
                content = update_interafce_list_in_content(content)
                content = replace_or_insert_in_content(content, "dhcp-option=interface:{},option:router,".format(
                    instance.interface.name),
                                                       "dhcp-option=interface:{},option:router,{}\n".format(
                                                           instance.interface.name, instance.gateway))
                if instance.dns_server_list:
                    dns_txt = 'dhcp-option=interface:{},6'.format(instance.interface.name)
                    for dns in instance.dns_server_list:
                        dns_txt += ',{}'.format(dns)
                    dns_txt += '\n'
                    content = replace_or_insert_in_content(content,
                                                           "dhcp-option=interface:{},6".format(instance.interface.name),
                                                           dns_txt)
                else:
                    content = clear_key_in_content("dhcp-option=interface:{},6".format(instance.interface.name),
                                                   content)
                if old_instance and instance.old:
                    if instance.old.exclude_ip_list:
                        for ip in instance.old.exclude_ip_list:
                            content = replace_or_insert_in_content(content, "dhcp-host=reserve,{}".format(ip), '')

                if instance.exclude_ip_list:
                    for ip in instance.exclude_ip_list:
                        content = replace_or_insert_in_content(content, "dhcp-host=reserve,{}".format(ip),
                                                               "dhcp-host=reserve,{}".format(ip))
                else:
                    pass

                content = replace_or_insert_in_content(content, "dhcp-option=19,0", "dhcp-option=19,0")
                content = replace_or_insert_in_content(content, "dhcp-lease-max=200", "dhcp-lease-max=200\n")
                if instance.subnet_mask:
                    mask = socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - instance.subnet_mask)) & 0xffffffff))
                    content = replace_or_insert_in_content(content,
                                                           "dhcp-range=interface:{},".format(instance.interface.name),
                                                           "dhcp-range=interface:{},{},{},{},{}h\n".format(
                                                               instance.interface.name, instance.start_ip,
                                                               instance.end_ip, mask, instance.lease_time))
                else:
                    content = replace_or_insert_in_content(content,
                                                           "dhcp-range=interface:{},".format(instance.interface.name),
                                                           "dhcp-range=interface:{},{},{},{}h\n".format(
                                                               instance.interface.name,
                                                               instance.start_ip,
                                                               instance.end_ip, instance.lease_time))

                content = content.replace('\n\n', '\n')
                status, result = sudo_file_writer(DNSMASQ_CONFIG_FILE, content, 'r+')
                if not status:
                    raise Exception
                if not is_watcher:
                    status, result = sudo_runner('service dnsmasq restart')
                    if not status:
                        raise Exception
                # iptables_insert('INPUT -p udp --dport 67 -j ACCEPT')
                # iptables_insert('INPUT -p udp --dport 68 -j ACCEPT')

                if not InputFirewall.objects.filter(port__exact='67') and not InputFirewall.objects.filter(
                        port__exact='68'):

                    try:
                        source = Source.objects.create()
                        InputFirewall.objects.create(
                            name='dhcp1',
                            is_log_enabled='False',
                            is_enabled='True',
                            permission='system',
                            protocol='udp',
                            port='67',
                            service_list='{dhcp}',
                            source=source
                        )
                    except:
                        pass

                    try:
                        source = Source.objects.create()
                        InputFirewall.objects.create(
                            name='dhcp2',
                            is_log_enabled='False',
                            is_enabled='True',
                            permission='system',
                            protocol='udp',
                            port='68',
                            service_list='{dhcp}',
                            source=source
                        )
                    except:
                        pass
                    apply_rule(None, None)

        if action == 'update' and not instance.is_enabled:
            clear_DHCP_configuration(instance)
            # sudo_runner('iptables -D INPUT -p udp --dport 67 -j ACCEPT')
            # sudo_runner('iptables -D INPUT -p udp --dport 68 -j ACCEPT')
            if not DHCPServerConfig.objects.filter(is_enabled=True):
                InputFirewall.objects.filter(port__exact='67').delete()
                InputFirewall.objects.filter(port__exact='68').delete()
                apply_rule(None, None)

        if not is_watcher:
            log('config', 'dhcp-server-setting', action, 'success',
                username=request_username, ip=get_client_ip(request), details=details)
        instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        instance.status = 'failed'
        instance.save()
        if not is_watcher:
            create_notification(source='dhcp', item={'id': instance.id, 'name': instance.name},
                                message=str('Error in {}ing DHCP, check interface {} configuration'.format(action,
                                                                                                           instance.interface.name)),
                                severity='e',
                                details={},
                                request_username=request_username)
            log('config', 'dhcp-server-setting', action, 'fail',
                username=request_username, ip=get_client_ip(request), details=details)


def clear_key_in_content(key, content):
    if key in content:
        content = re.sub(r'{}\s*\S*\n'.format(key), '', content)
    return content


def clear_DHCP_configuration(instance):
    status, content = sudo_file_reader(DNSMASQ_CONFIG_FILE)
    if status:
        try:
            content = clear_key_in_content("dhcp-range=interface:{}".format(instance.interface.name), content)
            content = clear_key_in_content("dhcp-option=interface:{},option:router,".format(instance.interface.name),
                                           content)
            content = clear_key_in_content("dhcp-option=interface:{},6".format(instance.interface.name), content)
            if instance.exclude_ip_list:
                for ip in instance.exclude_ip_list:
                    content = clear_key_in_content("dhcp-host=reserve,{}".format(ip), content)
            sleep(0.1)
            if not DHCPServerConfig.objects.filter(is_enabled=True).exists():
                content = clear_key_in_content("dhcp-option=19,0", content)
                content = clear_key_in_content("dhcp-lease-max=200", content)
            content = update_interafce_list_in_content(content)
            status, result = sudo_file_writer(DNSMASQ_CONFIG_FILE, content, 'r+')
            if not status:
                return False
            status, result = sudo_runner('service dnsmasq restart')
            if not status:
                return False
            return True
        except Exception:
            return False
    return False


def convert_ipv4(ip):
    return tuple(int(n) for n in ip.split('.'))


def check_ipv4_in(addr, start, end):
    if addr == start or addr == end:
        return True
    return convert_ipv4(start) < convert_ipv4(addr) < convert_ipv4(end)


def dhcp_lease_information():
    content = file_reader(DHCP_LEASES_FILE)
    lease_info_list = []
    try:
        if content:
            dhcp_instance_list = DHCPServerConfig.objects.filter(is_enabled=True)
            for dhcp_instance in dhcp_instance_list:
                interface = dhcp_instance.interface
                for line in content.split('\n'):
                    if line:
                        match = re.search(r'(\d*)\s*(\S*)\s*(\S*)\s*(\S*)\s*(\S*)', line)
                        lease_time = match.group(1)  # Expiry time, in epoch format (seconds since start of 1970)
                        mac_address = match.group(2)
                        ip_address = match.group(3)
                        client_name = match.group(4)  # Computer name, if known.
                        client_id = match.group(5)  # Client-ID, if known.
                        if check_ipv4_in(ip_address, dhcp_instance.start_ip, dhcp_instance.end_ip):
                            lease_info_list.append({'interface': interface.name,
                                                    'lease_time': datetime.datetime.fromtimestamp(int(lease_time)),
                                                    'mac_address': mac_address,
                                                    'ip_address': ip_address})
    except Exception as e:
        lease_info_list = []
    return lease_info_list


def set_Bridge_configuration(instance, action, request_username=None, request=None, details=None, is_watcher=False):
    config = " \n"
    config += "auto {}  \n".format(instance.name)
    config += "iface {} inet static  \n".format(instance.name)
    config += "  address {}  \n".format(instance.ip_list[0]['ip'])
    config += "  netmask {} \n".format(instance.ip_list[0]['mask'])
    if instance.gateway:
        config += "  gateway {} \n".format(instance.gateway)
    config += "  bridge_ports "

    for interface in instance.data[0]['interface']:
        sudo_runner('ip addr flush dev {0}'.format(interface))

    s, o = sudo_runner('brctl addbr {0}'.format(instance.name))
    if not s and not is_watcher:
        instance.status = 'failed'
        instance.save()
        print_if_debug(o)

    for interface in instance.data[0]['interface']:
        s, o = sudo_runner('brctl addif {0} {1}'.format(instance.name, interface))
        config += "{} ".format(interface)
        if not s and not is_watcher:
            instance.status = 'failed'
            instance.save()
            print_if_debug(o)

    if instance.mtu:

        s, o = sudo_runner('sudo ifconfig {0} mtu {1}'.format(instance.name, str(instance.mtu)))
        if not s and not is_watcher:
            instance.status = 'failed'
            instance.save()
            print_if_debug(o)

    is_stp_enabled = instance.data[0]["is_stp_enabled"]

    config += '\n'
    if is_stp_enabled:

        s, o = sudo_runner('brctl stp {} on'.format(instance.name))
        config += "  bridge_stp on \n"
        if not s and not is_watcher:
            instance.status = 'failed'
            instance.save()
            print_if_debug(o)


    else:
        s, o = sudo_runner('brctl stp {} off'.format(instance.name))
        config += "  bridge_stp off \n"
        if not s and not is_watcher:
            instance.status = 'failed'
            instance.save()
    netmask = instance.ip_list[0]['mask']
    netmask = IPAddress(netmask).netmask_bits()
    sudo_runner(
        'ip addr add dev {0} {1}/{2}'.format(instance.name, instance.ip_list[0]['ip'], netmask))

    if instance.is_enabled:

        config += "\n"
        s, o = sudo_runner('ip link set dev {0} up'.format(instance.name))

        sudo_runner('touch {}'.format(NETWORK_IFACES_CONF_FILE))
        status, contact = sudo_file_reader(NETWORK_IFACES_CONF_FILE)
        if not config in contact:
            contact += config

            s, o = sudo_file_writer(NETWORK_IFACES_CONF_FILE, contact, 'w')

        if not s and not is_watcher:
            instance.status = 'failed'
            instance.save()
            log('config', 'interface', action, 'fail',
                username=request_username, ip=get_client_ip(request), details=details)
            print_if_debug(o)


        elif not is_watcher:
            instance.status = 'succeeded'
            instance.save()
            log('config', 'interface', action, 'success',
                username=request_username, ip=get_client_ip(request), details=details)

    elif not instance.is_enabled:
        s, o = sudo_runner('ip link set {0} down'.format(instance.name))  # 192.168.66.66/24
        instance.status = 'disabled'
        instance.save()

        if not s:
            instance.status = 'failed'
            instance.save()

    if instance.gateway and instance.is_enabled:
        s, o = sudo_runner('ip route add {0} dev {1}'.format(instance.gateway, instance.name))
        if not s and not is_watcher:
            instance.status = 'failed'
            instance.save()
            print_if_debug(o)


def remove_bridge_interface(instance, request_username, request, details, operation, is_watcher=False):
    file_address = '/etc/network/interfaces'
    status, contact = sudo_file_reader(file_address)
    config = '\n'
    lines = contact.splitlines()
    i = 0
    while i < (len(lines)):
        if re.match('auto {}'.format(instance.name), lines[i]):
            i += 7
        if i < (len(lines)):
            config += (lines[i] + '\n')
            i += 1

    s, o = sudo_file_writer(file_address, config, 'w')

    # s, o = sudo_runner('/etc/init.d/networking restart')

    s, o = sudo_runner('ip link set dev {0} down'.format(instance.name))
    if not s:
        instance.status = 'failed'
        instance.save()
        # raise serializers.ValidationError({'non_field_errors': 'Bridge interface Can\'t be down '})

    s, o = sudo_runner('brctl delbr {}'.format(instance.name))
    if not s:
        instance.status = 'failed'
        instance.save()
        # raise serializers.ValidationError({'non_field_errors': 'Can\'t remove bridge interface'})


def set_Vlan_configuration(instance, action, request_username=None, request=None, details=None, is_watcher=False):
    # cmd = 'nmcli con add type vlan con-name {0}.{1} dev {0} id {1}'.format(
    #     instance.data[0]['interface'][0],
    #     instance.data[0]['vlan_id'])
    # s, o = sudo_runner(cmd)
    # print_if_debug(o)

    netmask = IPAddress(instance.ip_list[0]['mask']).netmask_bits()
    # sudo_runner('nmcli con up  {}.{} up'.format(instance.data[0]['interface'][0], instance.data[0]['vlan_id']))

    s, o = sudo_runner(
        'nmcli con show | grep {0}.{1}'.format(instance.data[0]['interface'][0], instance.data[0]['vlan_id']))
    if not s:

        cmd = 'nmcli con add type vlan con-name {0}.{1} dev {0} id {1} ip4 {2}/{3}'.format(
            instance.data[0]['interface'][0],
            instance.data[0]['vlan_id'],
            instance.ip_list[0]['ip'],
            netmask)
        s, o = sudo_runner(cmd)
        print_if_debug(o)

    else:

        s, o = sudo_runner('nmcli con mod {0}.{1} ipv4.addresses {2}/{3}'.format(instance.data[0]['interface'][0],
                                                                                 instance.data[0]['vlan_id'],
                                                                                 instance.ip_list[0]['ip'],
                                                                                 netmask))

        s, o = sudo_runner('nmcli con up  {}'.format(instance.name))

    if not is_watcher and not s:
        instance.status = 'failed'
        instance.save()
        log('config', 'interface', action, 'fail',
            username=request_username, ip=get_client_ip(request), details=details)
        print_if_debug(o)
        raise serializers.ValidationError({'non_field_errors': 'Can\'t add vlan interface'})

    sleep(4)

    cmd = 'ifconfig {0}.{1} mtu {2}'.format(instance.data[0]['interface'][0],
                                            instance.data[0]['vlan_id'], str(instance.mtu))
    s, o = sudo_runner(cmd)
    if not s:
        instance.status = 'failed'
        instance.save()
        print_if_debug(o)
        raise serializers.ValidationError({'non_field_errors': 'Can\'t set MTU on interface'})

    instance.status = 'succeeded'
    instance.save()

    if not instance.is_enabled:

        s, o = sudo_runner('ifconfig {0}.{1} down'.format(instance.data[0]['interface'][0],
                                                          instance.data[0]['vlan_id']))
        instance.status = 'disabled'
        instance.save()

        if not s:
            instance.status = 'failed'
            instance.save()
            print_if_debug(o)


def remove_Vlan_interface(instance, request_username, request, details, operation, is_watcher=False):
    # sudo_runner('ip link set {0}.{1} down'.format(instance.data[0]['interface'][0], instance.data[0]['vlan_id']))

    s, o = sudo_runner(
        "  nmcli con delete `nmcli -f NAME,UUID -p c | grep -i {}.{} ` ".format(instance.data[0]['interface'][0],

                                                                                instance.data[0]['vlan_id']))

    s, o = sudo_runner(
        "  nmcli con delete {}.{} ` ".format(instance.data[0]['interface'][0],

                                             instance.data[0]['vlan_id']))

    s, o = sudo_runner('vconfig rem {}.{}'.format(instance.data[0]['interface'][0],

                                                  instance.data[0]['vlan_id']))


def valdtion_offline_update(instance):
    s, o = sudo_runner('mv /var/ngfw/{} /var/ngfw/update_offline.tar.xz.enc.gpg'.format(instance.name))

    s, o = command_runner(
        'gpg --yes /var/ngfw/update_offline.tar.xz.enc.gpg')

    if not s:
        # update.status = 'failed'
        # update.save()
        raise serializers.ValidationError(
            {
                'update_error': 'Looks like the server is taking too long to respond, please try again after sometime (0xBB) '})

    try:
        with open('/var/ngfw/{brand}.v{ver}.tar.xz.key') as temp:
            key = temp.read()
    except:
        raise serializers.ValidationError({
            'update_error': 'something went wrong (0x2)'})

    # todo find ver and brand
    s, o = command_runner(
        'openssl enc -d -aes-256-cbc -in /var/ngfw/{brand}.v{ver}.tar.xz.enc -out /var/ngfw/{brand}.v{ver}.tar.xz -k {key}'.format(
            key=key))
    if not s:
        raise serializers.ValidationError(
            {
                'update_error': 'Looks like the server is taking too long to respond, please try again after sometime (0x5)'})


def check_bridge_interface(instance):
    cmd = 'brctl show {}'.format(instance.name)

    status, result = sudo_runner(cmd)

    if not status:
        return False
    for interface in instance.data[0]['interface']:
        if str(interface) not in str(result):
            return False

    return True


def check_use_bridge(interface_name):
    instance = Interface.objects.all()

    for interface in instance:
        if interface.mode == 'bridge':

            for x in interface.data[0]['interface']:
                if x == interface_name:
                    return True

    return False


def check_use_vlan(interface_name):
    instance = Interface.objects.all()

    for interface in instance:
        if interface.mode == 'vlan':

            if interface.data[0]['interface'][0] == interface_name:
                return True

    return False
