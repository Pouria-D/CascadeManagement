import array
import fcntl
import os
import re
import socket
import struct
import subprocess as sub

from django.db import transaction

from api.settings import IS_TEST, BACKUP_DIR, POLICY_BACK_POSTFIX
from auth_app.utils import get_client_ip
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner, sudo_check_path_exists, sudo_remove_directory, sudo_file_reader, \
    sudo_file_writer, sudo_mkdir
from utils.config_files import IPSEC_CONF_FILE, IPSEC_SECRETS_FILE, TEST_PATH, VTUND_CONFIGS_PATH, VAR_LOCK_VTUND_PATH, \
    PKI_DIR, PRIVATE_KEY_FILE, CERT_VPN_FILE
from utils.log import log
from utils.utils import run_thread, print_if_debug
from vpn_app.models import Tunnel, VPN


def chack_and_create_ipsec_config_file():
    init_str = '''config setup
        uniqueids="yes"
        strictcrlpolicy="no"

conn %default
        keyingtries="%forever"
        leftsendcert="always"
###############################
'''
    status, result = sudo_check_path_exists(IPSEC_CONF_FILE)
    if status:
        if result == 'False':
            sudo_file_writer(IPSEC_CONF_FILE, init_str, 'w+')
        else:
            s, r = sudo_file_reader(IPSEC_CONF_FILE)
            if s:
                if init_str not in r:
                    sudo_file_writer(IPSEC_CONF_FILE, '{}\n'.format(init_str), 'w+')
            else:
                sudo_file_writer(IPSEC_CONF_FILE, '{}\n'.format(init_str), 'w+')


def write_vpn_tunnel_config(config_txt):
    chack_and_create_ipsec_config_file()
    sudo_file_writer(IPSEC_CONF_FILE, config_txt, 'a+')


def create_vpn_tunnel_config_txt(vpn):
    Local_pub_key_path = ""
    Peer_pub_key = ""
    auth_by = "psk"
    if vpn.authentication_method == "RSA":
        auth_by = "rsasig"
    dhg_trans = {
        '1': 'modp768',
        '2': 'modp1024',
        '5': 'modp1536',
        '14': 'modp2048',
        '15': 'modp3072',
        '16': 'modp4096'
    }
    phase2Algorithm = vpn.phase2_encryption_algorithm
    # if phase2Algorithm == 'paya256':
    #     phase2Algorithm = 'camellia256'
    ike = vpn.phase1_encryption_algorithm + "-" + vpn.phase1_authentication_algorithm + "-" + dhg_trans[
        vpn.phase1_diffie_hellman_group] + "!"
    esp = phase2Algorithm + "-" + vpn.phase2_authentication_algorithm + "-" + dhg_trans[
        vpn.phase2_diffie_hellman_group] + "!"
    localNetworkList = []
    for localN in vpn.local_network.all():
        for value in localN.value_list:
            localNetworkList.append(value)
    remoteNetworkList = []
    for remoteN in vpn.remote_network.all():
        for value in remoteN.value_list:
            remoteNetworkList.append(value)

    local_endpoint = vpn.local_endpoint.value_list[0].split("/")[0]
    remote_endpoint = vpn.remote_endpoint.value_list[0].split("/")[0]

    auto = 'start'
    if vpn.is_on_demand:
        auto = "route"

    tunnel_conf_text = "\n\nconn " + vpn.name + " \n"
    tunnel_conf_text += "\tauthby=\"" + auth_by + "\"\n"
    tunnel_conf_text += "\tauto=\"" + auto + "\"\n"
    tunnel_conf_text += "\ttype=\"tunnel\"\n"
    tunnel_conf_text += "\tcompress=\"no\"\n"
    tunnel_conf_text += "\trekeymargin=\"540s\"\n"
    tunnel_conf_text += "\tleft=\"" + local_endpoint + "\"\n"
    tunnel_conf_text += "\tleftsubnet=\"" + ",".join(localNetworkList) + "\"\n"
    tunnel_conf_text += "\tright=\"" + remote_endpoint + "\"\n"
    tunnel_conf_text += "\trightsubnet=\"" + ",".join(remoteNetworkList) + "\"\n"
    tunnel_conf_text += "\tike=\"" + ike + "\"\n"
    tunnel_conf_text += "\tesp=\"" + esp + "\"\n"
    tunnel_conf_text += "\tikelifetime=\"" + str(int(vpn.phase1_lifetime) * 3600) + "\"\n"
    tunnel_conf_text += "\tkeylife=\"" + str(int(vpn.phase2_lifetime) * 3600) + "\"\n"
    if vpn.authentication_method == 'preshared':
        tunnel_conf_text += "\tleftid=\"" + vpn.local_id + "\"\n"
        tunnel_conf_text += "\trightid=\"" + vpn.peer_id + "\"\n"

    if vpn.authentication_method == "RSA":
        tunnel_conf_text += "\tleftcert=" + 'cert_' + vpn.certificate.name + '.crt' + "\n"

        tunnel_conf_text += "\tleftid=\"" + vpn.local_id + "\"\n"
        tunnel_conf_text += "\trightid=\"" + vpn.peer_id + "\"\n"

    tunnel_conf_text += "\tkeyexchange=\"ikev2\"\n"
    if vpn.dpd:
        dpd_timeout = "900"
        tunnel_conf_text += "\tdpdaction = \"restart\"\n"
        tunnel_conf_text += "\tdpddelay = \"30s\"\n"
        tunnel_conf_text += "\tdpdtimeout = \"" + dpd_timeout + "s\"\n"

    if vpn.is_backup_enabled:

        local_endpoint = vpn.local_endpoint_backup.value_list[0].split("/")[0]
        remote_endpoint = vpn.remote_endpoint_backup.value_list[0].split("/")[0]

        tunnel_conf_text += "\n\nconn " + vpn.name + '_backup_' + " \n"
        tunnel_conf_text += "\tauthby=\"" + auth_by + "\"\n"
        tunnel_conf_text += "\tauto=\"" + auto + "\"\n"
        tunnel_conf_text += "\ttype=\"tunnel\"\n"
        tunnel_conf_text += "\tcompress=\"no\"\n"
        tunnel_conf_text += "\trekeymargin=\"540s\"\n"
        tunnel_conf_text += "\tleft=\"" + local_endpoint + "\"\n"
        tunnel_conf_text += "\tleftsubnet=\"" + ",".join(localNetworkList) + "\"\n"
        tunnel_conf_text += "\tright=\"" + remote_endpoint + "\"\n"
        tunnel_conf_text += "\trightsubnet=\"" + ",".join(remoteNetworkList) + "\"\n"
        tunnel_conf_text += "\tike=\"" + ike + "\"\n"
        tunnel_conf_text += "\tesp=\"" + esp + "\"\n"
        tunnel_conf_text += "\tikelifetime=\"" + str(int(vpn.phase1_lifetime) * 3600) + "\"\n"
        tunnel_conf_text += "\tkeylife=\"" + str(int(vpn.phase2_lifetime) * 3600) + "\"\n"

        if vpn.authentication_method == "Preshared":
            tunnel_conf_text += "\tleftid=\"" + vpn.local_id + '_backup_' + "\"\n"
            tunnel_conf_text += "\trightid=\"" + vpn.peer_id + '_backup_' + "\"\n"

        if vpn.authentication_method == "RSA":
            tunnel_conf_text += "\tleftcert=" + 'cert_' + vpn.certificate.name + '.crt' + "\n"
            tunnel_conf_text += "\tleftid=\"" + vpn.local_id + "\"\n"
            tunnel_conf_text += "\trightid=\"" + vpn.peer_id + "\"\n"
        tunnel_conf_text += "\tkeyexchange=\"ikev2\"\n"
        if vpn.dpd:
            dpd_timeout = "900"
            tunnel_conf_text += "\tdpdaction = \"restart\"\n"
            tunnel_conf_text += "\tdpddelay = \"30s\"\n"
            tunnel_conf_text += "\tdpdtimeout = \"" + dpd_timeout + "s\"\n"
    return tunnel_conf_text


def check_path_exist(path):
    if IS_TEST:
        path = '{}{}'.format(TEST_PATH, path)
    return os.path.exists(path)


def set_vpn_tunnel_secret(vpn):
    if vpn.authentication_method == 'preshared':
        vpn_tunnel_secret = "\n" + vpn.local_id + " " + vpn.peer_id + "  : PSK \"" + vpn.preshared_key + "\"" + "   #" + vpn.name + "\n"
        sudo_file_writer(IPSEC_SECRETS_FILE, vpn_tunnel_secret, 'a')
        if vpn.is_backup_enabled:
            vpn_tunnel_secret = "\n" + vpn.local_id + '_backup_' + " " + vpn.peer_id + '_backup_' + "  : PSK \"" + vpn.preshared_key + "\"" + "   #" + vpn.name + '_backup_' + "\n"
            sudo_file_writer(IPSEC_SECRETS_FILE, vpn_tunnel_secret, 'a')

    elif vpn.authentication_method == 'RSA':

        vpn_tunnel_secret = "\n" + vpn.local_id + " " + vpn.peer_id + "  : RSA \"" + "cert_private_" + vpn.certificate.name + ".key" + "\"" + "   #" + vpn.name + "\n"
        sudo_file_writer(IPSEC_SECRETS_FILE, vpn_tunnel_secret, 'a')
        # if vpn.is_backup_enabled:
        #     vpn_tunnel_secret = "\n" + vpn.local_id + '_backup_' + " " + vpn.peer_id + '_backup_' + "  : RSA \"" + "cert_private_" + vpn.certificate.name + ".key" + "\"" + "   #" + vpn.name + '_backup_' + "\n"
        #     sudo_file_writer(IPSEC_SECRETS_FILE, vpn_tunnel_secret, 'a')


def up_vpn_tunnel(vpn_name):
    output = sub.Popen(["ps -aux | grep ipsec"], shell=True, stdout=sub.PIPE, universal_newlines=True)
    ipsec_is_up = output.stdout.read()
    match = re.search("/usr/lib/ipsec/starter", ipsec_is_up, flags=0)
    if not match:
        cmd = "ipsec start"
        sudo_runner(cmd)
    else:
        cmd = "ipsec update"
        sudo_runner(cmd)
        cmd = "ipsec rereadsecrets"
        sudo_runner(cmd)

        t = run_thread(target=ipsec_up, name='vpn_ipsec_up', args=(vpn_name,))
        if not IS_TEST:
            t.join(5)


def ipsec_up(vpn_name):
    """
        this command takes time very much when we want the result of the cmd so I use subprocess.
        run instead of checkoutput.
    """
    cmd = 'ipsec up {} &'.format(vpn_name)
    sudo_runner(cmd, wait_for_output=False)


def set_vpn_tunnel_configuration(vpn):
    if vpn.authentication_method == 'RSA':
        manage_certificate('copy', vpn)
        manage_private_key('copy', vpn)

    tunnel_conf_text = create_vpn_tunnel_config_txt(vpn)

    if not check_path_exist(VAR_LOCK_VTUND_PATH):
        sudo_mkdir(VAR_LOCK_VTUND_PATH)
        sudo_runner('chown ngfw:ngfw {} -R'.format(VAR_LOCK_VTUND_PATH))

    write_vpn_tunnel_config(tunnel_conf_text)

    status_last, whole_line = get_ipsec_vpn_status(vpn.name)
    if status_last == "down":
        up_vpn_tunnel(vpn.name)


def check_chain_existence(chain_name):
    cmd = 'iptables -nvL | grep {}'.format(chain_name)
    status, result = sudo_runner(cmd)
    if not status:
        cmd = 'iptables -w -N {}'.format(chain_name)
        sudo_runner(cmd)

        cmd = 'iptables -w -I INPUT -j {}'.format(chain_name)
        sudo_runner(cmd)

        sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
        cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
        sudo_runner(cmd)


def check_policy(vpn):
    check_input_chain = 'iptables -S INPUT'
    status, result = sudo_runner(check_input_chain)
    if status:
        if vpn.tunnel.type not in result:
            return False
    tunnel_chain = '{}_chain'.format(vpn.tunnel.type)
    check_chain = 'iptables -S {}'.format(tunnel_chain)
    real_remote_endpoint = vpn.tunnel.real_remote_endpoint.value_list[0].split("/")[0]
    status, result = sudo_runner(check_chain)
    if status:
        if vpn.tunnel.type == 'ipip' or vpn.tunnel.type == 'gre':
            match = re.search('-A {chain} -s {real_remote_endpoint}/32 -m comment --comment {vpn_name} -j ACCEPT'. \
                              format(chain=tunnel_chain, real_remote_endpoint=real_remote_endpoint,
                                     vpn_name=vpn.name), result)
            return match
        elif vpn.tunnel.type == 'vtun':
            tcp_match_vtun = re.search('-A vtun_chain -p tcp -m tcp --dport ' + str(
                vpn.tunnel.service_port) + ' -m comment --comment ' + vpn.name + ' -j ACCEPT', result)
            udp_match_vtun = re.search('-A vtun_chain -p udp -m udp --dport ' + str(
                vpn.tunnel.service_port) + ' -m comment --comment ' + vpn.name + ' -j ACCEPT', result)
            if not tcp_match_vtun or not udp_match_vtun:
                return False
            else:
                return True


def check_policy_rule_existence(vpn):
    tunnel_chain = '{}_chain'.format(vpn.tunnel.type)
    check_chain = 'iptables -S {}'.format(tunnel_chain)

    status, result = sudo_runner(check_chain)
    if status:
        if vpn.tunnel.type == 'ipip' or vpn.tunnel.type == 'gre':
            real_remote_endpoint = vpn.tunnel.real_remote_endpoint.value_list[0].split("/")[0]
            if not re.search('-A {chain} -s {real_remote_endpoint}/32 -m comment --comment {vpn_name} -j ACCEPT'. \
                                     format(chain=tunnel_chain, real_remote_endpoint=real_remote_endpoint,
                                            vpn_name=vpn.name), result):
                cmd = 'iptables -A {chain} -s {real_remote_endpoint} -m comment --comment {vpn_name} -j ACCEPT'. \
                    format(chain=tunnel_chain, real_remote_endpoint=real_remote_endpoint, vpn_name=vpn.name)
                sudo_runner(cmd)
        elif vpn.tunnel.type == 'vtun':
            tcp_match_vtun = re.search('-A vtun_chain -p tcp -m tcp --dport ' + str(
                vpn.tunnel.service_port) + ' -m comment --comment ' + vpn.name + ' -j ACCEPT', result)
            udp_match_vtun = re.search('-A vtun_chain -p udp -m udp --dport ' + str(
                vpn.tunnel.service_port) + ' -m comment --comment ' + vpn.name + ' -j ACCEPT', result)
            insert_tcp_rule = 'iptables -I vtun_chain -p tcp --dport ' + str(
                vpn.tunnel.service_port) + ' -j ACCEPT' + ' -m comment --comment ' + vpn.name
            insert_udp_rule = 'iptables -I vtun_chain -p udp --dport ' + str(
                vpn.tunnel.service_port) + ' -j ACCEPT' + ' -m comment --comment ' + vpn.name
            if vpn.tunnel.service_protocol == 'udp':
                if not tcp_match_vtun:
                    sudo_runner(insert_tcp_rule)
                if not udp_match_vtun:
                    sudo_runner(insert_udp_rule)
            if vpn.tunnel.service_protocol == 'tcp':
                if not tcp_match_vtun:
                    sudo_runner(insert_tcp_rule)
        else:
            return None

        sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
        cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
        sudo_runner(cmd)


def add_tunnel_iptables_rule(vpn):
    chain_name = '{}_chain'.format(vpn.tunnel.type)
    check_chain_existence(chain_name)
    check_policy_rule_existence(vpn)


def create_tunnel_config_script(vpn):
    real_remote_endpoint = vpn.tunnel.real_remote_endpoint.value_list[0].split("/")[0]
    real_local_endpoint = vpn.tunnel.real_local_endpoint.value_list[0].split("/")[0]
    virtual_local_endpoint = vpn.tunnel.virtual_local_endpoint.value_list[0].split("/")[0]
    if vpn.tunnel.type == 'ipip':
        config_text = "#!/bin/bash\n"
        config_text += "modprobe ip_gre \n"
        config_text += "ip tunnel add " + vpn.name + " mode ipip remote " + \
                       str(real_remote_endpoint) + " local " + str(real_local_endpoint) + " ttl 255\n"
        config_text += "ip link set " + vpn.name + " up" + "\n"
        config_text += "ip addr add " + str(virtual_local_endpoint) + "/24 dev " + vpn.name + "\n"
        config_text += "ifconfig " + vpn.name + " mtu " + str(vpn.tunnel.mtu) + " up\n"
    elif vpn.tunnel.type == 'gre':
        config_text = '#!/bin/bash\n'
        config_text += 'modprobe ip_gre \n'
        config_text += "INF=': ' read -r -a result <<< `ip tunnel show | grep 'remote {}[ ]\+local {}'`\n". \
            format(real_remote_endpoint, real_local_endpoint)
        config_text += 'if [ "X${result[0]::-1}" != "X" ]; then sudo ip tunnel del ${result[0]::-1}; fi\n'
        config_text += 'ip tunnel add ' + vpn.name + ' mode gre remote ' + \
                       str(real_remote_endpoint) + ' local ' + str(real_local_endpoint) + ' ttl 255\n'
        config_text += 'ip link set ' + vpn.name + ' up' + '\n'
        config_text += 'ip addr add ' + str(virtual_local_endpoint) + '/24 dev ' + vpn.name + '\n'
        config_text += 'ifconfig ' + vpn.name + ' mtu ' + str(vpn.tunnel.mtu) + ' up\n'
    else:
        return None
    script_file = '/etc/{tunnel_type}/{vpn_name}/{tunnel_type}_tun.conf'.format(tunnel_type=vpn.tunnel.type,
                                                                                vpn_name=vpn.name)
    sudo_file_writer(script_file, config_text, 'w')
    sudo_runner('chown ngfw:ngfw {} -R'.format(script_file))
    sudo_runner('chmod +r {}'.format(script_file))
    return script_file


def create_ipip_or_gre_tunnel(vpn):
    cmd = 'mkdir -p /etc/{tunnel_type}/{vpn_name}'.format(tunnel_type=vpn.tunnel.type, vpn_name=vpn.name)
    status, result = sudo_runner(cmd)
    if not status:
        vpn.status = 'failed'
        vpn.save()
        create_notification(source='vpn', item={'id': vpn.id, 'name': vpn.name},
                            message=str('Error in VPN tunnel configuration'), severity='e',
                            details={'command': cmd, 'error': str(result)},
                            request_username=vpn.request_username)
        log('vpn', 'vpn', 'add', 'fail', vpn.request_username)
        raise Exception(str(result))
    sudo_runner(
        'chown ngfw:ngfw /etc/{tunnel_type}/{vpn_name} -R'.format(tunnel_type=vpn.tunnel.type, vpn_name=vpn.name))
    script = create_tunnel_config_script(vpn)
    cmd = 'bash {}'.format(script)
    status, result = sudo_runner(cmd)
    if not status:
        vpn.status = 'failed'
        vpn.save()
        create_notification(source='vpn', item={'id': vpn.id, 'name': vpn.name},
                            message=str('Error in VPN tunnel configuration'), severity='e',
                            details={'command': cmd, 'error': str(result)},
                            request_username=vpn.request_username)
        log('vpn', 'vpn', 'add', 'fail', vpn.request_username)
        raise Exception(str(result))


def create_vtun_config_txt(vpn):
    virtual_local_endpoint = vpn.tunnel.virtual_local_endpoint.value_list[0].split("/")[0]
    virtual_remote_endpoint = vpn.tunnel.virtual_remote_endpoint.value_list[0].split("/")[0]
    vtun_conf_text = "options {" + "\n"
    vtun_conf_text += "port " + str(vpn.tunnel.service_port) + "; # Listen on this port\n"
    vtun_conf_text += "#bindaddr { iface lo; };\n"
    vtun_conf_text += "#syslog  local4;\n"
    vtun_conf_text += "#bindaddr { iface lo; };\n"
    vtun_conf_text += "# Path to various programs\n"
    vtun_conf_text += "#ppp         /usr/sbin/pppd;\n"
    vtun_conf_text += "ifconfig         /sbin/ifconfig;\n"
    vtun_conf_text += "#firewall         /sbin/ipchains;\n"
    vtun_conf_text += "#ip         /usr/sbin/ip;\n}\n"
    vtun_conf_text += "# virtual tunnel definition.\n"
    vtun_conf_text += vpn.name + "  {\n"
    vtun_conf_text += "passwd  Secure_G@tEw@y!2O!7;\n"
    vtun_conf_text += "#ppp         /usr/sbin/pppd;\n"
    vtun_conf_text += "type tun;\n"
    vtun_conf_text += "proto " + vpn.tunnel.service_protocol + ";\n"
    vtun_conf_text += "compress no;\t# Compression is off by default\n"
    vtun_conf_text += "encrypt no;\t# Max Speed by default, No Shaping \n"
    vtun_conf_text += "keepalive yes;\n"
    vtun_conf_text += "speed 0;\n"
    vtun_conf_text += "stat yes;\n"
    vtun_conf_text += "persist yes;\n"
    vtun_conf_text += "multi no;\n"
    vtun_conf_text += "up {\n"
    vtun_conf_text += "\tifconfig " + '"%% ' + \
                      virtual_local_endpoint \
                      + " pointopoint " + virtual_remote_endpoint \
                      + " mtu " + str(vpn.tunnel.mtu) + '"' + ";\n"
    vtun_conf_text += "};\n"
    vtun_conf_text += "down {\n"
    vtun_conf_text += "ifconfig " + '"%% ' + 'down ";\n'
    vtun_conf_text += "};\n}"
    return vtun_conf_text


def create_path_if_not_exist(path):
    status, result = sudo_check_path_exists(path)
    if result == 'False':
        sudo_mkdir(path)


def create_vtun_tunnel(vpn):
    server_endpoint = ""
    if vpn.tunnel.mode == "client":
        server_endpoint = str(vpn.tunnel.server_endpoint.value_list[0].split("/")[0])

    vtun_conf_text = create_vtun_config_txt(vpn)

    create_path_if_not_exist('{}{}/'.format(VAR_LOCK_VTUND_PATH, vpn.tunnel.mode))
    sudo_runner('chown ngfw:ngfw {}{} -R'.format(VAR_LOCK_VTUND_PATH, vpn.tunnel.mode))
    create_path_if_not_exist(
        '{vtun_path}{tunnel_mode}/{vpn_name}'.format(vtun_path=VTUND_CONFIGS_PATH, tunnel_mode=vpn.tunnel.mode,
                                                     vpn_name=vpn.name))
    sudo_runner('chown ngfw:ngfw {} -R'.format(VTUND_CONFIGS_PATH))

    if vpn.tunnel.mode == "server":
        sudo_file_writer('{}server/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, vpn.name), vtun_conf_text, 'w')
        sudo_runner('chmod +r {}server/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, vpn.name))
        cmd = "vtund -s -f {}server/{}/vtund.conf".format(VTUND_CONFIGS_PATH, vpn.name)
    else:
        sudo_file_writer('{}client/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, vpn.name),
                         "#" + str(server_endpoint) + "\n" + vtun_conf_text, 'w+')
        sudo_runner('chmod +r {}client/{}/vtund.conf'.format(VTUND_CONFIGS_PATH, vpn.name))
        cmd = 'vtund -f {vtun_path}client/{vpn_name}/vtund.conf {vpn_name} {server_endpoint}'. \
            format(vtun_path=VTUND_CONFIGS_PATH, vpn_name=vpn.name, server_endpoint=server_endpoint)
    status, result = sudo_runner(cmd)
    if not status:
        vpn.status = 'failed'
        vpn.save()
        create_notification(source='vpn', item={'id': vpn.id, 'name': vpn.name},
                            message=str('Error in VPN tunnel configuration'), severity='e',
                            details={'command': cmd, 'error': str(result)},
                            request_username=vpn.request_username)
        log('vpn', 'vpn', 'add', 'fail', vpn.request_username)
        raise Exception(str(result))


def tear_down_gre_or_ipip_tunnel(vpn):
    cmd = 'ip link set {} down'.format(vpn.old.name)
    sudo_runner(cmd)

    cmd = 'ip tunnel del {}'.format(vpn.old.name)
    sudo_runner(cmd)


def delete_ipip_gre_tunnel(vpn):
    tear_down_gre_or_ipip_tunnel(vpn)
    dir = '/etc/{tunnel_type}/{old_vpn_name}'.format(tunnel_type=vpn.old.tunnel.type, old_vpn_name=vpn.old.name)
    status, result = sudo_check_path_exists(dir)
    if status:
        if result == 'True':
            sudo_remove_directory(dir)


def delete_tunnel_iptables_rules(vpn):
    chain_name = '{}_chain'.format(vpn.old.tunnel.type)
    cmd = "iptables -nvL {chain_name} --line-numbers".format(chain_name=chain_name)
    status, result = sudo_runner(cmd)
    if IS_TEST:
        sudo_runner('iptables -D {chain}'.format(chain=chain_name))
        sudo_runner('iptables -D INPUT -j {}'.format(chain_name))
        sudo_runner('iptables -X {}'.format(chain_name))
    else:
        if status and str(result):
            for line in reversed(result.splitlines()):
                if '/* {} */'.format(vpn.old.name) in line:
                    line_number = re.compile('\s*').split(line)[0]
                    sudo_runner('iptables -D {chain} {line} '.format(chain=chain_name, line=line_number))

            s, r = sudo_runner('iptables -nvL {chain_name}'.format(chain_name=chain_name))
            if s and str(r):
                if '/*' not in r:
                    delete_input_rule = 'iptables -D INPUT -j {}'.format(chain_name)
                    sudo_runner(delete_input_rule)
                    delete_chain = 'iptables -X {}'.format(chain_name)
                    sudo_runner(delete_chain)

    sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
    cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
    sudo_runner(cmd)


def remove_vpn_ipsec_configraion(name):
    status, result = sudo_file_reader(IPSEC_CONF_FILE)
    if status:
        vpn_config = [item for item in result.split('\n\n') if 'conn {} \n'.format(name) not in item]
        sudo_file_writer(IPSEC_CONF_FILE, '\n\n'.join(vpn_config), 'w')


def remove_vpn_ipsec_secrets(name=None, local_id=None, peer_id=None, preshared_key=None):
    searchExp = local_id + " " + peer_id + "  : PSK \"" + preshared_key + "\"" + "   #" + name
    status, result = sudo_file_reader(IPSEC_SECRETS_FILE)
    if status:
        vpn_secrets = [item for item in result.splitlines() if searchExp not in item]
        sudo_file_writer(IPSEC_SECRETS_FILE, '\n'.join(vpn_secrets), 'w')


def remove_vpn_tunnel_configuration(name):
    cmd = 'ipsec down {}'.format(name)
    sudo_runner(cmd)
    remove_vpn_ipsec_configraion(name)
    cmd = "ipsec update"
    sudo_runner(cmd)
    cmd = "ipsec rereadsecrets"
    sudo_runner(cmd)
    cmd = 'rm -rf /var/log/ipsec/{}'.format(name)
    sudo_runner(cmd)


def tear_down_vtun_tunnel(vpn):
    pid = None
    if vpn.old.tunnel.mode == "server":
        cmd = "ps -aux | grep -u vtund | grep -w {} | grep -vE color | awk '{{print$2}}'".format(
            str(vpn.old.tunnel.service_port))
        status, result = sudo_runner(cmd)
        if status:
            pid = result.split('\n')[0]
    else:
        cmd = "ps -aux | grep -u vtund | grep -w '{} tun' | grep -vE color | awk '{{print$2}}'".format(vpn.old.name)
        status, result = sudo_runner(cmd)
        if status:
            pid = result.split('\n')[0]

    if pid:
        cmd = "kill -9 " + pid
        status, result = sudo_runner(cmd)
        if not status:
            vpn.status = 'failed'
            vpn.save()
            create_notification(source='vpn', item={'id': vpn.id, 'name': vpn.name},
                                message=str('Error in VPN tunnel configuration'), severity='e',
                                details={'command': cmd, 'error': str(result)},
                                request_username=vpn.request_username)
            raise Exception(str(result))


def all_interfaces():
    max_possible = 128  # arbitrary. raise if needed.
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', b'\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, 40):
        name = namestr[i:i + 16].split(b'\0', 1)[0]
        ip = namestr[i + 20:i + 24]
        lst.append((name, ip))
    return lst


def check_vtun_tunnel_is_up(virtual_local_ip, virtual_remote_ip):
    ifs = all_interfaces()
    for i in ifs:
        interface = i[0].decode("utf-8")
        if interface.startswith("tun"):
            output_status, output = sudo_runner("ifconfig " + interface)

            match1 = re.search("inet addr:" + virtual_local_ip + "\s+P-t-P:" +
                               virtual_remote_ip, output, flags=0)

            if match1:
                output_status, output = sudo_runner("ping -w 1 " + virtual_remote_ip)
                match2 = re.search("bytes from " + virtual_remote_ip, output, flags=0)
                if match2:
                    return "up"
            else:
                return "down"

    return "down"


def get_vtun_interface(virtual_local_ip, virtual_remote_ip, vtun_name):
    ifs = all_interfaces()
    for i in ifs:
        interface = str(i[0])
        if interface.startswith("tun"):
            output_status, output = sudo_runner("ifconfig " + interface)
            match = re.search("inet addr:" + virtual_local_ip + "\s+P-t-P:" +
                              virtual_remote_ip, output, flags=0)
            if match:
                return interface
    return None


def remove_vtun_tunnel(vpn):
    virtual_remote_ip = vpn.old.tunnel.virtual_remote_endpoint.value_list[0].split("/")[0]
    virtual_local_ip = vpn.old.tunnel.virtual_local_endpoint.value_list[0].split("/")[0]

    status_last = check_vtun_tunnel_is_up(virtual_local_ip, virtual_remote_ip)
    iface = get_vtun_interface(virtual_local_ip, virtual_remote_ip, vpn.old.name)
    if iface:
        if status_last == "up":
            cmd = 'ifconfig {} down'.format(iface)
            sudo_runner(cmd)

    dir = '{vtun_path}{type}/{name}'.format(vtun_path=VTUND_CONFIGS_PATH, type=vpn.old.tunnel.mode, name=vpn.old.name)
    status, result = sudo_check_path_exists(dir)
    if result == 'True':
        sudo_remove_directory(dir)


def create_vpn(vpn, request_username, request=None, changes=None, is_update=False, is_watcher=False):
    try:
        if vpn.is_enabled:
            set_vpn_tunnel_secret(vpn)
            set_vpn_tunnel_configuration(vpn)
            if vpn.tunnel:
                if vpn.tunnel.type == "vtun":
                    create_vtun_tunnel(vpn)
                else:
                    if vpn.tunnel.type == 'ipip' or vpn.tunnel.type == 'gre':
                        create_ipip_or_gre_tunnel(vpn)
                add_tunnel_iptables_rule(vpn)
        if not is_update:
            if not is_watcher:
                log('vpn', 'vpn', 'add', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)

    except Exception as e:
        vpn.status = 'failed'
        vpn.save()
        if not is_update:
            if not is_watcher:
                log('vpn', 'vpn', 'add', 'fail',
                    username=request_username, ip=get_client_ip(request), details={'error': str(e)})
        raise e

    with transaction.atomic():
        Notification.objects.filter(source='vpn', item__id=vpn.id).delete()
        vpn.status = 'succeeded'
        vpn.save()


def update_vpn(vpn, old_vpn, old_tunnel, request_username=None, request=None, changes=None, is_watcher=False):
    try:
        if old_vpn:
            old_vpn_obj = VPN()
            for key in old_vpn:
                setattr(old_vpn_obj, key, old_vpn[key])
            if old_tunnel:
                old_tunnel_obj = Tunnel()
                for key in old_tunnel:
                    setattr(old_tunnel_obj, key, old_tunnel[key])
                setattr(old_vpn_obj, 'tunnel', old_tunnel_obj)
            setattr(vpn, 'old', old_vpn_obj)
        setattr(vpn, 'request_username', request_username)

        # remove old vpn
        remove_enable_vpn(vpn)

        create_vpn(vpn, request_username, is_update=True, is_watcher=is_watcher)

        if not is_watcher:
            log('vpn', 'vpn', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)

    except Exception as e:
        vpn.status = 'failed'
        vpn.save()
        if not is_watcher:
            log('vpn', 'vpn', 'update', 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(e)})
        raise e

    with transaction.atomic():
        Notification.objects.filter(source='vpn', item__id=vpn.id).delete()
        vpn.status = 'succeeded'
        vpn.save()


def delete_vpn(vpn, request_username):
    setattr(vpn, 'old', vpn)
    setattr(vpn, 'request_username', request_username)

    remove_enable_vpn(vpn)
    if vpn.tunnel:
        vpn.tunnel.name = vpn.name
        rmmod(vpn)


def restart_vpn(vpn, request_username):
    from report_app.models import Notification
    from django.db import transaction
    setattr(vpn, 'old', vpn)
    setattr(vpn, 'request_username', request_username)

    if vpn.tunnel:
        tunnel_restart(vpn)
    vpn_restart(vpn)

    with transaction.atomic():
        Notification.objects.filter(source='vpn', item__id=vpn.id).delete()
        vpn.status = 'succeeded'
        vpn.save()


def tunnel_restart(vpn):
    cmd = None
    if vpn.tunnel.type == 'vtun':
        tear_down_vtun_tunnel(vpn)
        create_path_if_not_exist(VAR_LOCK_VTUND_PATH)
        if vpn.tunnel.mode == "server":
            cmd = "vtund -s -f {}server/{}/vtund.conf".format(VTUND_CONFIGS_PATH, vpn.name)
        elif vpn.tunnel.mode == "client":
            cmd = 'vtund -f {vtun_path}client/{vpn_name}/vtund.conf {vpn_name} {server_endpoint}'. \
                format(vtun_path=VTUND_CONFIGS_PATH, vpn_name=vpn.name,
                       server_endpoint=vpn.tunnel.server_endpoint.value_list[0].split("/")[0])
    elif vpn.tunnel.type == 'gre' or vpn.tunnel.type == 'ipip':
        tear_down_gre_or_ipip_tunnel(vpn)
        cmd = 'bash /etc/{type}/{vpn_name}/{type}_tun.conf'.format(type=vpn.tunnel.type, vpn_name=vpn.name)

    status, result = sudo_runner(cmd)
    if not status:
        vpn.status = 'failed'
        vpn.save()
        create_notification(source='vpn', item={'id': vpn.id, 'name': vpn.name},
                            message=str('Error in VPN tunnel configuration'), severity='e',
                            details={'command': cmd, 'error': str(result)},
                            request_username=vpn.request_username)
        raise Exception(str(result))


def vpn_restart(vpn):
    down_vpn_tunnel(vpn.name)
    up_vpn_tunnel(vpn.name)


def down_vpn_tunnel(vpn_name):
    cmd = 'ipsec down {}'.format(vpn_name)
    status, result = sudo_runner(cmd)
    return status


def get_vpn_traffic(vpn_name):
    vtun_traffic = {"traffic_in": 0, "traffic_out": 0, "tunnel_uptime": 0}

    status, whole_line = get_ipsec_vpn_status(vpn_name)
    if status == 'up':
        byte_inbound = re.compile(r",(.*)\sbytes_i", 0).findall(whole_line)[-1]
        if byte_inbound:
            converted_size = format(float(int(byte_inbound)) / (1024 * 1024), '.2f')
            if converted_size != "undefined":
                vtun_traffic["traffic_in"] = converted_size

        byte_outbound = re.compile(r",\s(\w*)\sbytes_o", 0).findall(whole_line)[-1]
        if byte_outbound:
            converted_size = format(float(int(byte_outbound)) / (1024 * 1024), '.2f')
            if converted_size != "undefined":
                vtun_traffic["traffic_out"] = converted_size
        if whole_line:
            if 'ago' in whole_line:
                tunnel_uptime = re.search(r'{}\[\S*\s*ESTABLISHED\s*(\d+\s*\S*)\s*ago'.format(vpn_name), whole_line,
                                          re.M)
                if tunnel_uptime:
                    vtun_traffic["tunnel_uptime"] = tunnel_uptime.group(1)

    return vtun_traffic


def get_vpn_status(request, vpn_name, tunnel_type, virtual_remote_ip, virtual_local_ip):
    status = None

    if request == 'vpn':
        status, whole_line = get_ipsec_vpn_status(vpn_name)
    elif request == 'tunnel':
        if tunnel_type == "vtun":
            status = check_vtun_tunnel_is_up(virtual_local_ip, virtual_remote_ip)
            return True if status == 'up' else False

        elif tunnel_type in ["ipip", "gre"]:
            status = check_ipip_gre_is_up(virtual_remote_ip)
            return True if status == 'up' else False
    return status


def get_ipsec_vpn_status(vpn_name=None):
    all_vpn_info = {}
    cmd = 'ipsec statusall'
    status, output = sudo_runner(cmd)
    if status:
        for line in output.splitlines():
            if 'CONNECTING' in line:
                result = re.search('\s*(\S*?)[\[\(\{]?\d*[\]\)\}]?:\s*CONNECTING', line, re.M)
                if result:
                    all_vpn_info['{}_real_data'.format(result.group(1))] = 'down'
                    all_vpn_info['{}_whole_line'.format(result.group(1))] = ''
                else:
                    print_if_debug("Something went wrong in vpn check status with this line: {}".format(line))
            elif 'INSTALLED' in line:
                result = re.search('\s*(\S*?)[\[\(\{]?\d*[\]\)\}]?:\s*INSTALLED', line, re.M)
                if result:
                    all_vpn_info['{}_real_data'.format(result.group(1))] = 'up'
                    all_line_with_this_vpn_name = ''.join(re.findall('\s*{}.*'.format(result.group(1)), output))
                    all_vpn_info['{}_whole_line'.format(result.group(1))] = all_line_with_this_vpn_name
                else:
                    print_if_debug("Something went wrong in vpn check status with this line: {}".format(line))

    if not vpn_name:
        return all_vpn_info, None
    elif '{}_real_data'.format(vpn_name) in all_vpn_info:
        return all_vpn_info['{}_real_data'.format(vpn_name)], all_vpn_info['{}_whole_line'.format(vpn_name)]
    else:
        return "down", None


def check_ipip_gre_is_up(virtual_remote_endpoint):
    output_status, output = sudo_runner("ping -w 1 " + virtual_remote_endpoint)
    match = re.search("bytes from " + virtual_remote_endpoint, output, flags=0)
    if match:
        return "up"
    return "down"


def rmmod(vpn):
    if vpn.tunnel.type == "gre":
        filter_profiles_gre = VPN.objects.filter(tunnel__type="gre")
        if len(filter_profiles_gre) == 1:
            cmd = "rmmod -f -s ip_gre"
            sudo_runner(cmd)

    elif vpn.tunnel.type == "ipip":
        filter_profiles_ipip = VPN.objects.filter(tunnel__type="ipip")
        if len(filter_profiles_ipip) == 1:
            cmd = "rmmod -f -s ipip"
            sudo_runner(cmd)


def remove_enable_vpn(vpn):
    if vpn.old.is_enabled:
        if vpn.old.tunnel:
            if vpn.old.tunnel.type == "vtun":
                tear_down_vtun_tunnel(vpn)
                remove_vtun_tunnel(vpn)
            elif vpn.old.tunnel.type in ["ipip", "gre"]:
                delete_ipip_gre_tunnel(vpn)
            delete_tunnel_iptables_rules(vpn)

        if vpn.old.authentication_method == 'RSA':
            manage_certificate('del', vpn)
            manage_private_key('del', vpn)
            remove_vpn_tunnel_configuration(vpn.old.name)
            remove_vpn_ipsec_secrets_rsa(vpn.old)
            if vpn.old.is_backup_enabled:
                remove_vpn_tunnel_configuration(vpn.old.name + '_backup_')





        elif vpn.old.authentication_method == 'preshared':
            remove_vpn_tunnel_configuration(vpn.old.name)
            remove_vpn_ipsec_secrets(vpn.old.name, vpn.old.local_id, vpn.old.peer_id, vpn.old.preshared_key)

            if vpn.old.is_backup_enabled:
                remove_vpn_tunnel_configuration(vpn.old.name + '_backup_')
                remove_vpn_ipsec_secrets(vpn.old.name + '_backup_', vpn.old.local_id + '_backup_',
                                         vpn.old.peer_id + '_backup_', vpn.old.preshared_key)

    return True


def manage_private_key(mode, vpn):
    if mode == 'copy':
        private_key_path = '{}/{}/cert_private_{}.key'.format(PKI_DIR, vpn.certificate.type, vpn.certificate.name)
        sudo_runner('cp {0}  {1}'.format(private_key_path, PRIVATE_KEY_FILE))

    if mode == 'del':
        sudo_runner('rm {}cert_private_{}.key'.format(PRIVATE_KEY_FILE, vpn.certificate.name))


def manage_certificate(mode, vpn):
    if mode == 'copy':
        cert_path = '{}/{}/cert_{}.crt'.format(PKI_DIR, vpn.certificate.type, vpn.certificate.name)

        sudo_runner('cp {0}  {1}'.format(cert_path, CERT_VPN_FILE))

    if mode == 'del':
        sudo_runner('rm {}cert_{}.crt'.format(CERT_VPN_FILE, vpn.certificate.name))


def remove_vpn_ipsec_secrets_rsa(vpn):
    searchExp = vpn.local_id + " " + vpn.peer_id + "  : RSA \"" + "cert_private_" + vpn.certificate.name + ".key" + "\"" + "   #" + vpn.name

    status, result = sudo_file_reader(IPSEC_SECRETS_FILE)
    if status:
        vpn_secrets = [item for item in result.splitlines() if searchExp not in item]
        sudo_file_writer(IPSEC_SECRETS_FILE, '\n'.join(vpn_secrets), 'w')
