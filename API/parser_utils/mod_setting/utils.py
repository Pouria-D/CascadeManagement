import json
import os
import re
import socket
import struct
import subprocess
import sys
from shutil import copyfile
from time import sleep

import requests
from netaddr import IPAddress
from psycopg2.extensions import AsIs
from psycopg2.extras import DictCursor

import parser_utils
from auth_app.utils import get_client_ip
from config_app.models import Interface, HighAvailability
from parser_utils import logger, redis_connection, connect_to_db
from parser_utils.config import config
from parser_utils.mod_resource.utils import get_service_status, get_interface_gateway, \
    get_pppoe_interfaces_map, get_map_tun_interfaces, get_interface_link_status, \
    get_interface_real_data
from parser_utils.mod_setting import check_gateway, add_default_route_table, add_default_rule
from parser_utils.mod_util.utils import logout_user
from qos_utils.utils import config_ifb_module, up_ifb_link, DOWNLOAD_IFB, \
    config_ifb_bandwidth, config_interface_upload_bandwidth, delete_interface_qdisc, \
    config_root_interface_class, redirect_lan_traffic_to_ifb_filter
from root_runner.sudo_utils import sudo_runner, sudo_file_writer
from utils.config_files import NETWORK_IFACES_CONF_FILE
from utils.log import log
from utils.utils import print_if_debug, run_thread

sys.path.append(config['MWLINK_ADDR'])


def set_shared_key(key, just_check_key=False):
    """
        This function sets shared key in
        /etc/chilli/config and /etc/freeradius/clients.conf

        If just_return_key = True then
        this function just read the key and returns it.
    """

    chilli_regex = r'\s*HS_RADSECRET\s*=\s*[\"|\'](.*)[\"|\']\s*'
    radius_regex = r'\s*secret\s*=\s*[\"|\'](.*)[\"|\']\s*'

    try:
        with open("/etc/chilli/config", 'r+') as chilli_configs:
            content = chilli_configs.read()
            if not just_check_key:
                new_content = re.sub(chilli_regex, "\nHS_RADSECRET='%s'\n" % key, content)
                chilli_configs.seek(0)
                chilli_configs.write(new_content)
                chilli_configs.truncate()
            else:
                chilli_key = re.search(chilli_regex, content)
                if chilli_key:
                    chilli_key = chilli_key.group(1)

                else:
                    return False

        with open('/etc/freeradius/clients.conf', 'r+') as radius_configs:
            content = radius_configs.read()
            if not just_check_key:
                new_content = re.sub(radius_regex, "\n\tsecret \t= '%s'\n" % key, content, flags=re.M)
                radius_configs.seek(0)
                radius_configs.write(new_content)
                radius_configs.truncate()
                return True
            else:
                radius_key = re.search(radius_regex, content)
                if radius_key:
                    radius_key = radius_key.group(1)
                    if radius_key == chilli_key:
                        if radius_key == key:
                            return True
                        else:
                            return False
                    else:
                        logger.warning("Radius secret key is not same as Chilli key.")
                        return False
                else:
                    return False

    except PermissionError:
        print('Permission Error!')
        return False
    except:
        return False


def set_database_connection_details(username, password, port, just_check_key=False):
    """
        This function changes /etc/freeradius/mods-available/sql file
    """
    username_regex = r'^\s*login\s*=\s*[\"|\'](.*)[\"|\']'
    password_regex = r'^\s*password\s*=\s*[\"|\'](.*)[\"|\']'
    port_regex = r'^\s*port\s*=\s*(\d+)'
    try:
        # change database, login, password, host and server attributes
        with open('/etc/freeradius/mods-available/sql', 'r+') as sql_conf_file:
            content = sql_conf_file.read()

            if not just_check_key:
                new_content = re.sub(username_regex, \
                                     '\tlogin = "%s"' % username, content, flags=re.M)

                new_content = re.sub(password_regex, \
                                     '\tpassword = "%s"' % password, new_content, flags=re.M)

                # new_content = re.sub(r'^\s*server\s*=\s*[\"|\'].*[\"|\']', \
                #   '\tserver = "%s"' % host, new_content, flags=re.M)

                new_content = re.sub(port_regex, \
                                     '\tport = %s' % port, new_content, flags=re.M)

                sql_conf_file.seek(0)
                sql_conf_file.write(new_content)
                sql_conf_file.truncate()

                return True

            else:
                status = True

                re_username = re.search(username_regex, content, re.M)
                re_password = re.search(password_regex, content, re.M)
                re_port = re.search(port_regex, content, re.M)

                if not re_username:
                    logger.error("I can't read username.")
                    status = False
                elif re_username and re_username.group(1) != username:
                    logger.warning("Usernames are not sync.")
                    status = False

                if not re_password:
                    logger.error("I can't read password.")
                    status = False
                elif re_password and re_password.group(1) != password:
                    logger.warning("Passwords are not sync.")
                    status = False

                if not re_port:
                    logger.error("I can't read port.")
                    status = False
                elif re_port and int(re_port.group(1)) != port:
                    logger.warning("Ports are not sync.")
                    status = False

            return status

    except Exception as e:
        logger.error(str(e))
        return False


def get_database_connection_details():
    try:

        # change database, login, password, host and server attributes
        with open('/etc/freeradius/mods-available/sql', 'r+') as sql_conf_file:
            content = sql_conf_file.read()
            data = {}

            username = re.search(r'^\s*login\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
            password = re.search(r'^\s*password\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
            port = re.search(r'^\s*port\s*=\s*(\d+)', content, re.M)
            db_name = re.search(r'^\s*radius_db\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)

            if username:
                data['username'] = username.group(1)
            if password:
                data['password'] = password.group(1)
            if port:
                data['port'] = port.group(1)
            if db_name:
                data['db_name'] = db_name.group(1)

        return data

    except Exception as e:
        logger.error(str(e))
        return None


def reapply_cp_lan_policies(interface, opration, do_qos):
    if do_qos:
        from parser_utils.mod_qos.utils import reapply_qos_policies_of_interface
        reapply_qos_policies_of_interface(interface, opration)


def change_chilli_status(status):
    from parser_utils.mod_qos.utils import get_interface_status
    try:
        lan_interface = get_chilli_interfaces()['LAN']
        if lan_interface:
            qos_interface_status = get_interface_status(lan_interface)  # QoS general config status
        else:
            qos_interface_status = False
        reapply_cp_lan_policies(lan_interface, 'DELETE', qos_interface_status)

        if status:
            with open('/etc/default/chilli', 'r+') as chilli_file:
                content = chilli_file.read()
                new_content = re.sub(r'START_CHILLI\s*=.*',
                                     "START_CHILLI=1", content)
                chilli_file.seek(0)
                chilli_file.write(new_content)
                chilli_file.truncate()

            subprocess.Popen("touch /etc/default/chilli_active", shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True).communicate()[0]

            sudo_runner("systemctl daemon-reload")

            sudo_runner("service chilli restart")

            tries = 0
            while tries < 3:
                tun = get_map_tun_interfaces().get(lan_interface, None)
                if tun:
                    break
                else:
                    sleep(2)
                    tries += 1

        else:
            tun = get_map_tun_interfaces().get(lan_interface, None)
            sudo_runner("service chilli stop")

            with open('/etc/default/chilli', 'r+') as chilli_file:
                content = chilli_file.read()
                new_content = re.sub(r'START_CHILLI\s*=.*',
                                     "START_CHILLI=0", content)
                chilli_file.seek(0)
                chilli_file.write(new_content)
                chilli_file.truncate()

            subprocess.Popen("rm /etc/default/chilli_active", shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]

        reapply_cp_lan_policies(lan_interface, 'ADD', qos_interface_status)
    except Exception as e:
        logger.error(str(e))
        return False

    return True


def flush_ipset():
    cmd = 'ipset flush'
    status, result = sudo_runner(cmd)
    if not status:
        return False
    else:
        return True


def write_chilli_old_config(wan, lan, hotspot_network, hotspot_netmask, listen_ip,
                            dhcp_start, dhcp_mask, port, ui_port, dhcp_start_ip, dhcp_end_ip):
    """
        This function gets chilli configs and writes it in old config file.
    """

    content = {
        'wan': wan,
        'lan': lan,
        'hotspot_network': hotspot_network,
        'hotspot_netmask': hotspot_netmask,
        'listen_ip': listen_ip,
        'dhcp_start': dhcp_start,
        'dhcp_mask': dhcp_mask,
        'port': port,
        'ui_port': ui_port,
        'dhcp_start_ip': dhcp_start_ip,
        'dhcp_end_ip': dhcp_end_ip,
    }

    with open(parser_utils.config['CHILLI_OLD_CONFIG'], 'w') as old_config_file:
        old_config_file.write(json.dumps(content))


def check_chilli_config(wan, lan, hotspot_network, hotspot_netmask, listen_ip,
                        dhcp_start, dhcp_mask, port, ui_port, dhcp_start_ip, dhcp_end_ip):
    """
        This function gets chilli config and checks it with old data,
        return True if they ware equale, False or None at other states.
    """

    if os.path.isfile(parser_utils.config['CHILLI_OLD_CONFIG']):
        with open(parser_utils.config['CHILLI_OLD_CONFIG']) as old_config_file:
            try:
                content = json.loads(old_config_file.read())
            except ValueError as e:
                return None
            try:
                if wan != content['wan']:                           return False
                if lan != content['lan']:                           return False
                if hotspot_network != content['hotspot_network']:   return False
                if hotspot_netmask != content['hotspot_netmask']:   return False
                if listen_ip != content['listen_ip']:               return False
                if dhcp_start != content['dhcp_start']:             return False
                if dhcp_mask != content['dhcp_mask']:               return False
                if port != content['port']:                         return False
                if ui_port != content['ui_port']:                   return False
                if dhcp_start_ip != content['dhcp_start_ip']:       return False
                if dhcp_end_ip != content['dhcp_end_ip']:           return False
            except KeyError as e:
                logger.warning(str(e))
                return False
        return True
    else:
        return None


def create_ip_pool(ip, mask, exceptions_ip=list()):
    """
        This generator takes an IP and a mask and yields all IPs of that CIDR.
    """

    convert_to_cidr_result = convert_to_cidr(ip, mask)
    (ip, mask_bits) = convert_to_cidr_result.split('/')
    mask_bits = int(mask_bits)
    host_bits = 32 - mask_bits
    i = struct.unpack('>I', socket.inet_aton(ip))[0]  # note the endianness
    start = (i >> host_bits) << host_bits  # clear the host bits
    end = i | ((1 << host_bits) - 1)

    for i in range(start, end):
        result = socket.inet_ntoa(struct.pack('>I', i))
        if result in exceptions_ip:
            continue
        yield result


def save_ip_pool_db(ippool):
    """
        This function takes the generator of IP pool and saves that in database.
    """

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    try:
        cursor.execute("truncate table %s", (AsIs(parser_utils.config['IPPOLL_TABLE']),))
        for index, ip in enumerate(ippool):
            cursor.execute("INSERT INTO %s (id, pool_name, framedipaddress) \
                VALUES (%s, 'main_pool', %s)",
                           (AsIs(parser_utils.config['IPPOLL_TABLE']), index + 1, ip))
        con.commit()
    except Exception as e:
        con.rollback()
        return False

    return True


def set_chilli_configs(wan=None, lan=None, hotspot_network=None,
                       hotspot_netmask=None, listen_ip=None, dhcp_start=None,
                       dhcp_mask=None, port=3990, ui_port=4990, dhcp_start_ip=1, dhcp_end_ip=254):
    """
        This function sets chilli configs in /etc/chilli/config.
        If entered config is equale to old config (exactly),
        it will check chilli status and enable chilli and returns
        it's status if it was not enable.
    """

    if check_chilli_config(wan, lan, hotspot_network, hotspot_netmask,
                           listen_ip, dhcp_start, dhcp_mask, port, ui_port, dhcp_start_ip,
                           dhcp_end_ip):
        if not get_service_status('chilli'):
            if change_chilli_status(True):
                return True
            else:
                return False
        else:
            return True

    copyfile('/etc/chilli/config', '/etc/chilli/config.backup')

    try:
        # Stop chilli to remove old wan interface from nat!
        # and do what should happen in stopping process
        sudo_runner("service chilli stop")

        with open('/etc/chilli/config', 'r+') as chilli_file:
            content = chilli_file.read()

            new_content = re.sub(r'HS_WANIF\s*=.*', "HS_WANIF=%s" % wan, content)

            new_content = re.sub(r'HS_LANIF\s*=\s*[A-Za-z0-9]+', "HS_LANIF=%s" % lan, new_content)

            new_content = re.sub(r'HS_NETWORK\s*=\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                 "HS_NETWORK=%s" % hotspot_network, new_content)

            new_content = re.sub(r'HS_NETMASK\s*=\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                 "HS_NETMASK=%s" % hotspot_netmask, new_content)

            new_content = re.sub(r'HS_UAMLISTEN\s*=\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                 "HS_UAMLISTEN=%s" % listen_ip, new_content)

            new_content = re.sub(r'HS_UAMPORT\s*=\s*\d+', "HS_UAMPORT=%s" % port, new_content)

            new_content = re.sub(r'HS_DYNIP\s*=\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                 "HS_DYNIP=%s" % dhcp_start, new_content)

            new_content = re.sub(r'HS_DYNIP_MASK\s*=\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                 "HS_DYNIP_MASK=%s" % dhcp_mask, new_content)

            new_content = re.sub(r'HS_UAMUIPORT\s*=\s*\d+',
                                 "HS_UAMUIPORT=%s" % ui_port, new_content)

            chilli_file.seek(0)
            chilli_file.write(new_content)
            chilli_file.truncate()

        with open('/etc/chilli.conf', 'r+') as chilli_file:
            content = chilli_file.read()
            new_content = re.sub(r'dhcpstart\s*=.*', "dhcpstart=%s" % dhcp_start_ip, content)

            new_content = re.sub(r'dhcpend\s*=.*', "dhcpend=%s" % dhcp_end_ip, new_content)

            chilli_file.seek(0)
            chilli_file.write(new_content)
            chilli_file.truncate()

        write_chilli_old_config(wan, lan, hotspot_network, hotspot_netmask,
                                listen_ip, dhcp_start, dhcp_mask, port, ui_port, dhcp_start_ip,
                                dhcp_end_ip)

        redis_connection.flushdb()
        flush_ipset()
        if change_chilli_status(True) and save_ip_pool_db(
                create_ip_pool(hotspot_network, hotspot_netmask,
                               [hotspot_network, listen_ip])):
            return True
        else:
            return False

    except KeyError as e:
        copyfile('/etc/chilli/config.backup', '/etc/chilli/config')
        raise e
    except Exception as e:
        logger.error(str(e))
        copyfile('/etc/chilli/config.backup', '/etc/chilli/config')
        return False


def clear_interfaces_file():
    """
        cleans /etc/network/interfaces and just writes lo data in that.
    """

    sudo_file_writer(NETWORK_IFACES_CONF_FILE, 'auto lo\niface lo inet loopback', 'w')


def convert_to_cidr(ip, mask):
    return "{}/{}".format(ip, str(IPAddress(mask).netmask_bits()))


def convert_from_cidr(cidr):
    if '/' not in cidr:
        logger.error("wrong CIDR")
        return None, None

    ip = cidr.split('/')[0]
    mask_bits = int(cidr.split('/')[1])
    mask = socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - mask_bits)) & 0xffffffff))
    return ip, mask


def apply_network_command(cmd, interface=None, request_username=None, should_notify=False):
    from report_app.utils import create_notification

    print_if_debug("Trying to run...{}".format(cmd))
    status, output = sudo_runner(cmd)
    if not status:
        if should_notify and interface:
            create_notification(source='interface', item={'id': interface.name, 'name': interface.name},
                                message='Error in running network commands',
                                details=output,
                                severity='e', request_username=request_username)
            log('config', 'interface', 'update', 'fail', username=request_username, details="")
        print_if_debug("failed to run:{} because:{}".format(cmd, output))

        return False, None

    return True, output


def is_network_setting_changed(interface_name, method, ip_addresses, gateway, pppoe_user=None, pppoe_pass=None):
    # {'is_link_connected': True,
    #  'real_ip_list': [{'ip': '1.1.1.1', 'mask': '255.255.255.0'}, {'ip': '2.2.2.3', 'mask': '255.255.255.0'}],
    #  'real_gateway': '82.3.3.3', 'real_is_enabled': True}
    real_data = get_interface_real_data(interface_name, True)
    real_ip_set = set([convert_to_cidr(item['ip'], item['mask']) for item in real_data['real_ip_list'] if item])
    ip_set = set(ip_addresses.split(','))
    if real_ip_set == ip_set and real_data['real_gateway'] == gateway:
        # and (not pppoe_user or "pppoe.username:{}".format(pppoe_user) in output) and \
        # (not pppoe_pass or "pppoe.password:{}".format(pppoe_pass) in output):
        return False, real_data['real_connection_name']

    diff_ip = real_ip_set.symmetric_difference(ip_set)
    is_any_diff_ip_exist_in_ha_cluster_ip_list = True
    for ip in diff_ip:
        if not HighAvailability.objects.filter(is_enabled=True, cluster_address_list__contains=ip):
            is_any_diff_ip_exist_in_ha_cluster_ip_list = False
            break
    if is_any_diff_ip_exist_in_ha_cluster_ip_list:
        return False, real_data['real_connection_name']

    return True, real_data['real_connection_name']


def config_network_interface(interface, request_username=None,
                             old_default_gw_interface=None, should_up_ifb_link=False,
                             interface_already_has_qdisc=False, request=None, changes=None, is_watcher=False):
    from report_app.models import Notification
    import time

    new_default_gw_interface = None
    res = True
    should_apply_changes = True
    # TODO check what is the speed problem!
    # TODO return current state correctly with different meaningful code
    start_time = time.time()
    try:
        if interface.is_default_gateway:
            new_default_gw_interface = interface.name

        Notification.objects.filter(source='interface', item__name=interface.name).delete()

        con_type_nmcli = None
        username = None
        password = None
        nmcli_pppoe_cmd = None
        gateway = ''
        cidr = ''
        cidr2 = ''

        qos_res = True
        if not is_watcher:
            if interface.is_enabled:
                if interface.upload_bandwidth:
                    if not config_interface_upload_bandwidth(interface, interface_already_has_qdisc):
                        qos_res = False
                elif interface_already_has_qdisc:
                    if not config_root_interface_class(interface.name, None, 'delete'):
                        qos_res = False

                # configuring ifb if it doesn't configed before, ifb is configured with first wan which has
                # download bandwidth
                if should_up_ifb_link:
                    if not (config_ifb_module() and up_ifb_link(DOWNLOAD_IFB) and config_ifb_bandwidth()):
                        qos_res = False
                    else:
                        lan_interface_list = Interface.objects.filter(type='LAN')
                        for lan_int in lan_interface_list:
                            if not redirect_lan_traffic_to_ifb_filter(lan_int.name):
                                qos_res = False

            if not Interface.objects.filter(download_bandwidth__isnull=False).exists():
                if not delete_interface_qdisc(DOWNLOAD_IFB):
                    qos_res = False
            if interface.qos_status == 'pending':
                if qos_res:
                    interface.qos_status = 'succeeded'
                else:
                    interface.qos_status = 'failed'
                interface.save()
        if interface.link_type == 'Ethernet':
            con_type_nmcli = '802-3-ethernet'
        elif interface.link_type == 'PPPOE':
            username = interface.pppoe_username
            password = interface.pppoe_password
            con_type_nmcli = 'pppoe'

        method = 'manual'
        if interface.is_dhcp_enabled:
            method = 'auto'

        print_if_debug("method is: " + method)

        if interface.gateway and not interface.is_dhcp_enabled:
            gateway = interface.gateway

        if interface.ip_list and not interface.is_dhcp_enabled:
            cidr = ",".join(convert_to_cidr(address['ip'], address['mask']) for address in interface.ip_list)
            cidr2 = " ".join(
                "ip4 %s" % convert_to_cidr(address['ip'], address['mask']) for address in interface.ip_list)

        # Get current active connection and rename if it is not equal to our standard form <interface>_con
        connection_name = "{}_con".format(interface.name)
        is_connection_changed, real_connection_name = is_network_setting_changed(
            interface_name=interface.name,
            method=method, ip_addresses=cidr,
            gateway=gateway,
            pppoe_user=username,
            pppoe_pass=password)
        if real_connection_name:  # rename the connection if it is not in our format ({interface.name}_con)
            if not real_connection_name == connection_name:
                rename_cmd = "nmcli connection modify '{}' connection.id {}".format(real_connection_name,
                                                                                    connection_name)
                sudo_runner(rename_cmd)

        if real_connection_name and not is_connection_changed:
            print_if_debug("It is not require to apply changes in network")
            should_apply_changes = False

        if real_connection_name and (not interface.is_enabled or should_apply_changes):
            # The interface has related connection but it is not enabled by admin or it must changed,
            #  so it should be deleted!"
            cmd = "nmcli connection down {connection_name}; nmcli connection delete {connection_name}".format(
                connection_name=connection_name)
            status, output = apply_network_command(cmd, interface=interface)

            if not status:
                interface.status = 'failed'
                interface.save()
                res = False
            else:
                interface.status = 'succeeded'
                interface.save()
                res = True

        add_cmd = ""
        # if the connection is not exist or it should change, create new connection. Note: in second case,
        # the connection was removed by last previous lines
        if interface.is_enabled and (not real_connection_name or (
                real_connection_name and should_apply_changes)):
            if interface.link_type == 'Ethernet':
                nmcli_pppoe_cmd = ''
            elif interface.link_type == 'PPPOE':
                nmcli_pppoe_cmd = " pppoe.username {username} pppoe.password {password}".format(
                    username=username, password=password)

            if interface.is_dhcp_enabled:
                add_cmd = "nmcli connection add type {type} con-name '{connection_name}' ifname {interface}" \
                          " {pppoe_options} autoconnect yes".format(
                    type=con_type_nmcli,
                    connection_name=connection_name,
                    interface=interface.name,
                    pppoe_options=nmcli_pppoe_cmd)
            elif cidr:
                add_cmd = "nmcli con add type {type} con-name '{connection_name}' " \
                          "ifname {interface} autoconnect yes {pppoe_options} {cidr} {gw_options}".format(
                    type=con_type_nmcli,
                    connection_name=connection_name,
                    interface=interface.name,
                    pppoe_options=nmcli_pppoe_cmd,
                    cidr=cidr2,
                    gw_options='gw4 %s' % gateway if gateway else '')
            else:
                print_if_debug("Can't modify manual connection {} without ip address".format(connection_name))

            if add_cmd:
                if not apply_network_command(add_cmd, interface=interface, request_username=request_username,
                                             should_notify=True)[0]:
                    interface.status = 'failed'
                    interface.save()
                    res = False

        # if not connection_name:
        #     connection_name = get_interface_active_connection(interface.name)

        # if interface == get_chilli_interfaces()['LAN'] and \
        #         get_service_status('chilli'):
        #     cmd = 'ifconfig %s 0.0.0.0' % interface
        #     subprocess.Popen(cmd, shell=True,
        #                     stdout=subprocess.PIPE,
        #                     stderr=subprocess.STDOUT).communicate()

        if interface.is_default_gateway:
            status, result, cmd = set_primary_default_gateway(new_default_gw_interface, old_default_gw_interface)
            if cmd:
                should_apply_changes = True
            if not status:
                interface.status = 'failed'
                interface.save()
                log('config', 'interface', 'update', 'fail', username=request_username)

        if interface.is_enabled and get_interface_link_status(interface.name) and should_apply_changes:
            cmd = "nmcli con up '{}'".format(connection_name)

            from config_app.utils import set_Bridge_configuration
            status, output = apply_network_command(cmd, interface=interface)
            if not status:
                interface.status = 'failed'
                interface.save()
                res = False
            else:
                res = True

                all_bridge_interface = Interface.objects.filter(mode='bridge')
                if all_bridge_interface:
                    for obj in all_bridge_interface:
                        for inter in obj.data[0]['interface']:
                            if inter == interface.name:
                                run_thread(target=set_Bridge_configuration, name='set_Bridge_config',
                                           args=(obj, 'update', None, None, True))

        if not interface.is_enabled:
            interface.status = 'disabled'
        elif res:
            interface.status = 'succeeded'
        interface.save()
        if res:
            Notification.objects.filter(source='interface', item__id=interface.name).delete()

        print_if_debug("----------final add time:{}---------".format(time.time() - start_time))

        return res

    except Exception as e:
        print_if_debug(
            "We got an exception in config_interface during configuring {} for {}".format(interface.name, str(e)))
        error = "Can't config network interface"
        interface.status = 'failed'
        interface.save()

        details = {
            'items': {
                'name': interface.name
            },
            'error': error
        }
        if not is_watcher:
            log('config', 'interface', 'update', 'fail',
                username=request_username, ip=get_client_ip(request), details=details)
        return False


def get_chilli_interfaces():
    """
        reads chilli configs and returns WAN and LAN interfaces.
        returns None in failure.
    """

    result = {'WAN_list': list(), 'LAN': str()}
    ppp_map = get_pppoe_interfaces_map()

    # print(ppp_map)
    try:
        with open('/etc/chilli/config', 'r') as chilli_file:
            content = chilli_file.read()

            wan_result = re.search(r'HS_WANIF\s*=\s*(\S+)', content)
            result['WAN_list'] = list()
            if wan_result:
                wan_physical = wan_result.group(1).split(',')
                for interface in wan_physical:
                    for key, value in list(ppp_map.items()):
                        if value == interface:
                            result['WAN_list'].append(key)
                            break
                    else:
                        result['WAN_list'].append(interface)

            lan_result = re.search(r'HS_LANIF\s*=\s*(\S+)', content)
            if lan_result:
                result['LAN'] = lan_result.group(1)
    except  Exception as e:
        # print(e)
        logger.error(str(e))
        return None
    return result


def config_update_server_address(address):
    try:
        data = {'server': address}
        resp = requests.post(config['UPDATE_MANAGER'] + 'set_server', json=data)
    except Exception as e:
        logger.error(str(e))
        return False

    logger.error(resp.status_code)
    if resp.status_code == 200:
        return True
    else:
        return False


def get_all_default_gateway_interfaces_name_and_metric(table):
    """
        this function executes "ip route" for an specified table and get
        interface of all default gateways from it's output.
    """

    cmd = 'ip route show table %s' % table
    status, output = sudo_runner(cmd)

    if not status:
        logger.warning("Can't execute 'route' command.")
        return None

    routes = list()
    for row in output.split('\n'):
        if row:
            split_row = row.split()
            if len(split_row) > 4 and split_row[0] == 'default':
                routes.append({
                    'interface': split_row[4],
                    'metric': int(split_row[8]) if len(split_row) > 7 else 0
                })
    routes.sort(key=lambda x: x['metric'])
    return routes


def get_primary_default_gateway_interface_name():
    default_table = get_all_default_gateway_interfaces_name_and_metric('main')
    if not default_table:
        default_table = get_all_default_gateway_interfaces_name_and_metric('default')

    if default_table:
        interface = default_table[0]['interface']
        ppp_map = get_pppoe_interfaces_map()
        if interface in ppp_map.values():
            invert_ppp_map = {v: k for k, v in ppp_map.iteritems()}
            interface = invert_ppp_map[interface]
        return interface
    else:
        return None


def set_route_metric_nmcli(connection, metric, make_up=True):
    """
        set route metric of a connection with nmcli.
    """

    cmd = "nmcli connection modify '{}' ipv4.route-metric {}".format(connection, metric)
    print_if_debug("trying to run(metric):{}".format(cmd))
    status, result = sudo_runner(cmd)

    if not status:
        logger.warning("Can't execute nmcli to change metric.")
        return status, result, cmd

    if make_up:
        if "_con" in connection:
            interface_name = connection[:-4]
        if get_interface_link_status(interface_name):
            cmd = "nmcli connection up '{}'".format(connection)
            print_if_debug("trying to run(metric):{}".format(cmd))
            status, result = sudo_runner(cmd)

            if not status:
                logger.warning("Can't execute nmcli to change metric.")
                return status, result, cmd

    return status, result, cmd


def set_primary_default_gateway(new_default_gw_interface, old_default_gw_interface):
    """
        This function gets two interface as parameter,
        checks old_interface is default gateway that is
        applied, if it was not, we increase metric for
        both old applied interface and old_interface, else
        we increase just old_interface. Finally the new_interface's metric
        will decreased.
    """
    if not new_default_gw_interface:
        return True, "the new default gateway is empty", None
    primary_default_gw = get_primary_default_gateway_interface_name()

    if primary_default_gw == new_default_gw_interface:
        return True, "current default gateway is equal to interface", None

    if old_default_gw_interface:
        if primary_default_gw and old_default_gw_interface.name != primary_default_gw:
            logger.warning("Old default gateway interface is not same as 'route' output")
            connection = "{}_con".format(primary_default_gw)
            set_route_metric_nmcli(connection, 100, make_up=True)

        connection_old_interface = "{}_con".format(old_default_gw_interface.name)
        set_route_metric_nmcli(connection_old_interface, 100, make_up=True)

    connection_new_interface = "{}_con".format(new_default_gw_interface)
    status, result, cmd = set_route_metric_nmcli(connection_new_interface, 50, make_up=False)
    return status, result, cmd


def check_first_multiwan_opration():
    """
        This function reads dastabase and returns True if
        at least one record exist, else retruns False.
    """

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    result = None
    try:
        cursor.execute("SELECT 1 FROM %s LIMIT 1",
                       (AsIs(config['MWLINK_TABLE']),)
                       )

        if not cursor.fetchone():
            result = True
        else:
            result = False
    except Exception as e:
        logger.error(str(e))
        result = False
    finally:
        cursor.close()

    return result


def get_mwlink_data():
    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor(cursor_factory=DictCursor)
    result = list()

    try:
        ppp_interfaces_map = get_pppoe_interfaces_map()
        cursor.execute("SELECT interface, weight FROM %s WHERE enable=%s \
            ORDER BY weight", (AsIs(config['MWLINK_TABLE']), True))
        fetched_data = cursor.fetchall()
        if fetched_data:
            for row in fetched_data:
                if row['interface'] in ppp_interfaces_map:
                    interface = ppp_interfaces_map[row['interface']]
                else:
                    interface = row['interface']

                gw = get_interface_gateway(interface)
                if gw and check_gateway(gw) == 80:
                    result.append({
                        'interface': interface,
                        'weight': row['weight'],
                        'gateway': gw
                    })
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return result


def save_multiwan_record_db(interface, weight, enable):
    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    result = None

    try:
        cursor.execute("SELECT 1 FROM %s WHERE interface=%s",
                       (AsIs(config['MWLINK_TABLE']), interface))
        if cursor.fetchone():
            cursor.execute("UPDATE %s SET weight=%s,enable=%s \
                WHERE interface=%s",
                           (AsIs(config['MWLINK_TABLE']),
                            int(weight), bool(enable), interface)
                           )
        else:
            cursor.execute("INSERT INTO %s (interface, weight, enable) VALUES \
                (%s,%s,%s)",
                           (AsIs(config['MWLINK_TABLE']),
                            interface, int(weight), bool(enable))
                           )
        con.commit()
        result = True
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        result = False
    finally:
        cursor.close()

    return result


def delete_multiwan_record_db(interface):
    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    result = None

    try:
        cursor.execute("DELETE FROM %s WHERE interface=%s",
                       (AsIs(config['MWLINK_TABLE']), interface)
                       )
        con.commit()
        result = True
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        result = False
    finally:
        cursor.close()

    return result


def add_multiwan_defaults():
    if add_default_route_table():
        if add_default_rule() == 50 or 30:
            return True
        else:
            return False
    else:
        return True


def get_iptables_rules(chain):
    """
        This function takes a chain name and executes iptables -S on it.
        Return list of output lines.
    """

    cmd = 'iptables -S %s' % chain
    status, output = sudo_runner(cmd)

    if not status:
        return list()

    return filter(lambda x: x, output.split('\n'))


def change_ip_white_list(ip, operation):
    if operation not in ('add', 'delete'):
        raise ValueError('operation must be add or delete')

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    result = None

    try:
        cursor.execute("SELECT 1 FROM %s WHERE ip=%s LIMIT 1",
                       (AsIs(parser_utils.config['IP_WHITE_LIST']), ip)
                       )
        fetched_data = cursor.fetchone()

        if operation == 'add':
            if fetched_data:
                result = False, 'This IP exists.'
            else:
                cursor.execute("INSERT INTO %s VALUES (%s)",
                               (AsIs(parser_utils.config['IP_WHITE_LIST']), ip)
                               )

        elif operation == 'delete':
            if not fetched_data:
                result = False, 'This IP dose\'nt exist.'
            else:
                cursor.execute("DELETE FROM %s WHERE ip=%s",
                               (AsIs(parser_utils.config['IP_WHITE_LIST']), ip)
                               )
                logout_user(ip)

        con.commit()
        result = True, 'OK'
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        result = False, 'Error'
    finally:
        cursor.close()

    return result


def get_ip_white_list():
    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    result = []

    try:
        cursor.execute("SELECT ip FROM %s",
                       (AsIs(parser_utils.config['IP_WHITE_LIST']),)
                       )
        for row in cursor.fetchall():
            result.append(row[0])
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return result
