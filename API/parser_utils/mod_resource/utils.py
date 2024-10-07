import json
import re
import subprocess
from configparser import ConfigParser
from datetime import datetime

import redis
from psycopg2.extensions import AsIs

import parser_utils.config
from parser_utils import connect_to_db, logger
from parser_utils.mod_profile.utils import get_user_list, get_online_user_macs
from root_runner.sudo_utils import sudo_runner


def get_partitions_data():
    data = list()

    status, lsblk_content = sudo_runner("lsblk -J")

    status, df_result = sudo_runner("df -m")

    lsblk_content = json.loads(lsblk_content)

    for device in lsblk_content['blockdevices']:
        if 'children' in device:
            for part in device['children']:
                result = re.search(r'^/dev/%s.+$' % part['name'], str(df_result), re.M)
                if result:
                    result_list = result.group().split()
                    data.append({'addr': result_list[0], 'size': result_list[1],
                                 'used': result_list[2], 'used_percentage': result_list[4],
                                 'mounted_on': result_list[5][:-2]})
    return data


def calculate_used_traffic(interval, order_by='download', direction='asc', page=1, page_size=10, username=None):
    con = next(connect_to_db())
    if not con:
        return list()
    cursor = con.cursor()
    offset = (page - 1) * page_size
    if offset < 0:
        offset = 0

    try:
        count_query = 'SELECT COUNT(DISTINCT username) FROM %s WHERE \
            AcctStopTime::ABSTIME::INT4 > date_trunc(%s, \
            current_date)::ABSTIME::INT4 OR AcctStopTime IS NULL'

        cursor.execute(count_query, (AsIs(parser_utils.config['acct_table']), interval))
        count_fetched_data = cursor.fetchone()
        if count_fetched_data:
            count = count_fetched_data[0]
        else:
            count = 0

        query = "SELECT username, SUM(AcctInputOctets) as download, \
            SUM(AcctOutputOctets) as upload FROM %s WHERE \
            (AcctStopTime::ABSTIME::INT4 > date_trunc(%s, \
            current_date)::ABSTIME::INT4) OR AcctStopTime IS NULL "
        if username: query += cursor.mogrify("AND username=%s", (username,))
        query += " GROUP BY username ORDER BY %s %s OFFSET %s LIMIT %s"

        # print(query)
        cursor.execute(query,
                       (AsIs(parser_utils.config['acct_table']), interval, AsIs(order_by),
                        AsIs(direction), AsIs(offset), AsIs(page_size)))

    except Exception as e:
        logger.error(e)
        con.rollback()

    data = list()
    for row in cursor.fetchall():
        online_device_data = get_online_user_macs(row[0])
        data.append({
            'username': row[0],
            'download': int(row[1]) / 1000.0,
            'upload': int(row[2]) / 1000.0,
            'online_devices': online_device_data,
            'online': bool(online_device_data)
        })

    return {'data': data, 'count': count}


def calculate_top_users(interval, action='download', count=10):
    if action == 'download':
        action_col = 'AcctInputOctets'
    elif action == 'upload':
        action_col = 'AcctOutputOctets'
    elif action == 'total':
        action_col = 'AcctInputOctets + AcctOutputOctets'
    else:
        logger.error("I can't understand %s" % action)
        return

    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()

    try:
        if action == 'total':
            cursor.execute("SELECT username, SUM(%s) AS total, \
                SUM(AcctInputOctets) AS download, SUM(AcctOutputOctets) \
                AS upload FROM %s WHERE AcctStartTime::ABSTIME::INT4 > \
                date_trunc(%s, current_date)::ABSTIME::INT4 GROUP BY username \
                ORDER BY total DESC LIMIT %s",
                           (AsIs(action_col), AsIs(parser_utils.config['acct_table']), interval, AsIs(count)))
        else:
            cursor.execute("SELECT username, SUM(%s) as calculated FROM %s WHERE \
                AcctStartTime::ABSTIME::INT4 > date_trunc(%s, \
                current_date)::ABSTIME::INT4 GROUP BY username \
                ORDER BY calculated DESC LIMIT %s",
                           (AsIs(action_col), AsIs(parser_utils.config['acct_table']), interval, AsIs(count)))
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    result = cursor.fetchall()

    # TODO: to prevent MAC address bug
    user_list = get_user_list()
    for x in result:
        if x[0] not in user_list:
            result.remove(x)

    return result


def get_bandwidth(interface):
    data = {}

    status, cmd_output = sudo_runner('ifstat -i %s 1 1 | tail -n 1' % interface)

    result = re.search(r'^\s*([\d\.]+)\s+([\d\.]+)', cmd_output, re.M)
    if result:
        data['download_rate'] = result.group(1)
        data['upload_rate'] = result.group(2)

    return data


def get_bandwidth_history(interface, interval, _type, time, limit=60):
    config = ConfigParser()
    config.read(parser_utils.config['NETWORK_IF_CONFIG_PATH'])

    if config.has_section(interface):
        interface_db_data = dict(config.items(interface))
    else:
        logger.error("I can't find '%s' section in %s" % (interface, parser_utils.config['NETWORK_IF_CONFIG_PATH']))
        return None
    try:
        if interval == 'min':
            db_num = interface_db_data['min']
        elif interval == 'hour':
            db_num = interface_db_data['hour']
        elif interval == 'day':
            db_num = interface_db_data['day']
        else:
            return
    except KeyError as e:
        logger.error(str(e))
        return

    redis_con = redis.StrictRedis(host=parser_utils.config['REDIS_HOST'],
                                  port=parser_utils.config['REDIS_PORT'],
                                  db=db_num)

    all_keys = map(lambda x: int(x), redis_con.keys())

    if _type == 'from':
        true_keys = filter(lambda x: x > int(time), all_keys)
        true_keys.sort()
        true_keys = true_keys[:limit]
    elif _type == 'to':
        true_keys = filter(lambda x: x < int(time), all_keys)
        true_keys.sort()
        true_keys = true_keys[-limit:]
    else:
        return

    data = list()
    for key in true_keys:
        result = redis_con.hgetall(str(key))
        str_time = datetime.fromtimestamp(key).strftime('%Y-%m-%d %H:%M:%S')
        data.append(
            {
                'download_rate': result['download_rate'],
                'upload_rate': result['upload_rate'],
                'time': str_time,
                'epoch_time': int(key)
            }
        )

    return data


# This function will return active connection name related to input interface_name
def get_interface_active_connection(interface_name):
    cmd = "nmcli -t -f GENERAL.CONNECTION device show {}".format(interface_name)

    status, connection_name = sudo_runner(cmd)
    if status and "GENERAL.CONNECTION:" in connection_name:
        connection_name = connection_name.split(':')[1]

    if not status or connection_name in ['--', '']:
        connection_name = None

    return connection_name


def has_related_connection(interface_name):
    """
        This function assumed that the any connection is created by a standard name <interface_name>_con
    """
    cmd = "nmcli connection show '{}_con'".format(interface_name)

    status, connection_status = sudo_runner(cmd)
    return status


def get_network_interfaces(state=None):
    """
        This function retruns list of phisycal interfacfes.
        If state == True: returns just linked interfaces,
        if state == False: returns just not linked interfaces,
        if state == None: returns all interfaces.
    """

    s, o = sudo_runner("find /sys/class/net -type l -not -lname '*virtual*' -printf '%f\n'")
    if not s:
        raise Exception(o)

    interfaces = o.split('\n')

    for interface in interfaces:
        interface = interface.strip()
        if not interface or 'failed' in interface:
            interfaces.remove(interface)

    if state is True:
        for interface in interfaces:
            if not is_interface_active(interface):
                interfaces.remove(interface)

    elif state is False:
        for interface in interfaces:
            if is_interface_active(interface):
                interfaces.remove(interface)

    elif state is None:
        pass

    return interfaces


def get_internet_status():
    cmd = "ping -c 1 4.2.2.4"
    status, output = sudo_runner(cmd)
    return status


def get_pppoe_interfaces_map():
    from parser_utils.mod_setting.utils import convert_from_cidr
    result = dict()

    get_ppp_if_cmd = 'ifconfig'
    status, get_ppp_if_output = sudo_runner(get_ppp_if_cmd)
    ppp_list = re.findall(r'ppp\d+', get_ppp_if_output, re.DOTALL)

    if not ppp_list:
        return result

    ifconfig_data = list()

    for interface in ppp_list:
        ifconfig_data.append({
            'interface': interface,
            'ip': get_interface_ip(interface)
        })

    nmcli_cmd = 'nmcli connection show --active'
    status, nmcli_output = sudo_runner(nmcli_cmd)
    nmcli_show_lines = filter(lambda x: x, nmcli_output.split('\n'))

    for line in nmcli_show_lines:
        nmcli_interface = interface and line.strip().split()[-1]
        nmcli_con_type = interface and line.strip().split()[-2]
        nmcli_con_uuid = interface and line.strip().split()[-3]

        if nmcli_con_type == 'pppoe':
            # print("nmcli_con_type:", nmcli_con_type)
            nmcli_details_cmd = 'nmcli connection show %s | grep IP4.ADDRESS' % nmcli_con_uuid
            status, nmcli_details_output = sudo_runner(nmcli_details_cmd)
            cidr_result = convert_from_cidr(nmcli_details_output.split()[-1])

            if cidr_result is None:
                continue

            ip, mask = cidr_result

            match_with_ifconfig = filter(lambda x: x['ip'] == ip, ifconfig_data)
            if match_with_ifconfig:
                result[nmcli_interface] = match_with_ifconfig[0]['interface']

    return result


def get_interface_dns(interface):
    cmd = "nmcli device show %s | grep 'IP4.DNS' | cut -d: -f2" % interface
    status, output = sudo_runner(cmd)

    if '\n' == output[-1:]:
        output = output[:-1]

    if output:
        output = [out.strip() for out in output.split('\n')]

    return output


def get_interface_method(connection=None, interface_name=None, use_nmcli=True):
    if use_nmcli:
        if not connection:
            return None

        cmd = "(nmcli connection show %s | grep 'ipv4.method:' | awk '{print $2}') 2> /dev/null" % connection.replace(
            " ",
            "\ ")
        status, output = sudo_runner(cmd)
        return output
    else:
        cmd = 'ls /var/lib/dhcp/'
        status, result = sudo_runner(cmd)
        # print("get method:", status, result, interface_name in str(result))
        if status:
            if interface_name and ".{}.".format(interface_name) in str(result):
                return 'auto'
            else:
                return 'manual'


def get_interface_mac(interface, use_nmcli=True):
    if use_nmcli:
        cmd = "nmcli device show '{}' | grep 'GENERAL.HWADDR' | awk '{{print $2}}'".format(interface)
        ps, output = sudo_runner(cmd)

        if not ps:
            logger.error("Can't get interface MAC.")
            return None
    else:
        cmd = "ifconfig '{}' | grep -o 'HWaddr .*' | awk '{{print $2}}'".format(interface)
        ps, output = sudo_runner(cmd)

        if not ps:
            logger.error("Can't get interface MAC.")
            return None

    return output.upper()


def parse_interface_information(output, split_flag):
    from parser_utils.mod_setting.utils import convert_from_cidr
    result_list = []
    if split_flag in output:
        result = [item.split(split_flag)[1].split(':')[1] for item in output.split('\n') if split_flag in item]

        if split_flag == "IP4.ADDRESS":
            for address in result:
                if address:
                    ip, mask = convert_from_cidr(address)
                    result_list.append({'ip': ip, 'mask': mask})
        else:
            result_list = result

    if not result_list:
        result_list.append('')

    return result_list


def get_all_interface_real_data(use_nmcli=True):
    all_interface_info = {}
    if use_nmcli:
        cmd = 'nmcli -t -f GENERAL.DEVICE,IP4.ADDRESS,IP4.GATEWAY,GENERAL.CONNECTION,GENERAL.STATE device show'
        status, output = sudo_runner(cmd)

        if status:
            item_list = [item.split("GENERAL.DEVICE:")[1] for item in output.split("\n\n") if item]
            for interface_output in item_list:
                interface_name = interface_output.split("\n")[0]
                real_data = get_interface_real_data(interface_name, use_nmcli, interface_output)
                all_interface_info['{}_real_data'.format(interface_name)] = real_data

    return all_interface_info


def get_interface_real_data(interface_name, use_nmcli=True, output=None):
    if use_nmcli:
        if not output:
            cmd = 'nmcli -t -f WIRED-PROPERTIES.CARRIER,IP4.ADDRESS,IP4.GATEWAY,GENERAL.CONNECTION,GENERAL.STATE ' \
                  'device show {}'.format(interface_name)
            status, output = sudo_runner(cmd)
        else:
            status = True

        if status:
            real_data = {
                'real_ip_list': parse_interface_information(output, "IP4.ADDRESS"),
                'real_gateway': parse_interface_information(output, "IP4.GATEWAY")[0],
                'real_is_enabled': status,  # True if status is True!
                'is_link_connected': False if "20 (" in parse_interface_information(output, "GENERAL.STATE")[0]
                else True,
                'real_connection_name': parse_interface_information(output, "GENERAL.CONNECTION")[0],
                'real_link_state': True if "on" in parse_interface_information(output,
                                                                               'WIRED-PROPERTIES.CARRIER') else False
            }
        else:
            real_data = {
                'real_ip_list': [],
                'real_gateway': None,
                'real_is_enabled': False,
                'is_link_connected': None,
                'real_connection_name': None,
                'real_link_state': False
            }
    else:
        real_data = {
            'real_ip_list': get_interface_ip(interface_name, use_nmcli),
            'real_gateway': get_interface_gateway(interface_name, use_nmcli),
            'real_is_enabled': False,
            'is_link_connected': get_interface_link_status(interface_name, use_nmcli),
            'real_connection_name': None,
            'real_link_state': get_interface_link_status(interface_name)
        }

    return real_data


def get_all_ip_real(use_nmcli=True):
    if use_nmcli:
        cmd = 'nmcli -t -f IP4.ADDRESS device show '

        status, output = sudo_runner(cmd)
        if not status or not output:
            # todo: should raise error instead of returning empty list
            return []
        return parse_interface_information(output, "IP4.ADDRESS")


def get_interface_ip(interface_name, use_nmcli=True):
    from parser_utils.mod_setting.utils import convert_from_cidr
    if use_nmcli:
        cmd = 'nmcli -t -f IP4.ADDRESS device show {}'.format(interface_name)

        status, output = sudo_runner(cmd)
        if not status or not output:
            # todo: should raise error instead of returning empty list
            return []
        return parse_interface_information(output, "IP4.ADDRESS")

    else:
        cmd = 'ip addr show {} | grep "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/[0-9]\+" -o'.format(interface_name)
        status, output = sudo_runner(cmd)
        if not status or not output:
            return []

        result = [item for item in output.split() if item]

        ip_list = []
        for address in result:
            if address:
                ip, mask = convert_from_cidr(address)
                ip_list.append({'ip': ip, 'mask': mask})

        return ip_list


def get_interface_mask(interface):
    cmd = 'ifconfig %s | grep "Mask" | cut -d: -f4' % interface
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)

    output = ps.communicate()[0]

    if ps.returncode != 0:
        logger.error("Can't run command correct to get interface mask.")
        return None

    if '\n' == output[-1:]:
        output = output[:-1]

    ip_regex = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if not ip_regex.match(output):
        result = None
    else:
        result = output

    return result


def get_interface_status(interface_name, use_nmcli=True):
    if not get_interface_link_status(interface_name):
        return "unplugged"

    if use_nmcli:
        cmd = 'nmcli -t -f GENERAL.STATE dev show {}'.format(interface_name)
        status, output = sudo_runner(cmd)
        if not status or "GENERAL.STATE:" not in output:
            return "unknown"
        if "100 " in output.split(":")[1]:
            return "connected"
        if "70 " in output.split(":")[1]:
            return "connecting"
        if "30 " in output.split(":")[1]:
            return "disconnected"
        if "20 " in output.split(":")[1]:
            return "unavailable"

        return "unknown"
    else:
        cmd = 'ifconfig %s | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1' % interface_name
        status, output = sudo_runner(cmd)

        if not status or not output:
            logger.error("Fail to get interface IP.")
            return "unknown"

        ip_regex = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_regex.match(output):
            return "uknown"

        return "connected"


def is_interface_active(interface_name, use_nmcli=True):
    if not get_interface_link_status(interface_name):
        return False

    if use_nmcli:
        connection_name = get_interface_active_connection(interface_name)

        if not connection_name:
            return False

        cmd = "nmcli -t -f GENERAL.STATE conn show '{}'".format(connection_name)
        status, output = sudo_runner(cmd)
        if not status or not output or 'activated' not in output:
            return False

        return True

    else:
        cmd = 'ifconfig %s | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1' % interface_name
        ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)

        output = ps.communicate()[0]

        if ps.returncode != 0:
            logger.error("Fail to get interface IP.")
            return False

        output = str(output).strip()

        if not output:
            return False

        ip_regex = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_regex.match(output):
            return False

        return True


def get_interface_link_status(interface_name):
    cmd = 'ethtool {}'.format(interface_name)
    status, result = sudo_runner(cmd)
    if not status:
        return False

    result = re.search(r'\s*Link detected:\s*(\S+)\s*', str(result))
    if result and result.group(1) == 'yes':
        return True
    return False


def get_interface_gateway(interface, use_nmcli=True):
    if use_nmcli:
        cmd = "nmcli -t -f IP4.GATEWAY device show {}".format(interface)
        status, output = sudo_runner(cmd)
        if not status or not output:
            return None

        result = parse_interface_information(output, "IP4.GATEWAY")
        if not result or result[0] == '':
            return None
        else:
            return result[0]


    else:
        gateway = read_route_tables('default', interface)
        if not gateway:
            gateway = read_route_tables('main', interface)
        return gateway


def get_link_type(interface):
    cmd = "nmcli device show %s | grep 'GENERAL.TYPE' | awk '{print $2}'" % interface
    status, result = sudo_runner(cmd)
    if status:
        return result
    else:
        return None


def read_route_tables(table, interface):
    cmd = "ip route show table {}".format(table)
    status, output = sudo_runner(cmd)
    gw = None

    for line in output.split('\n'):
        split_line = line.split()
        if split_line and split_line[4] == interface and split_line[0] == 'default':
            gw = split_line[2]
            break

    return gw


def get_service_status(service):
    cmd = 'systemctl status {}.service'.format(service)
    status, output = sudo_runner(cmd)

    result = re.search(r'\s*Active:\s*(\S+)\s*', output)

    if result:
        if result.group(1) == 'active':
            return True
        else:
            return False

    else:
        return None


def get_captive_portal_status():
    return {
        'chilli': get_service_status('chilli'),
        'freeradius': get_service_status('freeradius'),
        'postgresql': get_service_status('postgresql'),
        'user_portal': get_service_status('user_portal')
    }


def get_cpu_usage():
    cmd = "vmstat 1 2|tail -1|awk '{print $15}'"
    status, output = sudo_runner(cmd)

    try:
        percentage = 100 - round(float(output), 2)
    except ValueError:
        percentage = None

    return percentage


def get_tun_interfaces():
    """
        This function gets tun interfaces and returns them in a list.
    """
    cmd = "find /sys/class/net -type l -lname '*tun*' -printf '%f\n'"
    status, output = sudo_runner(cmd)
    return filter(lambda x: x, output.split('\n'))


def get_ip_interface_nmcli(interface):
    """
        This function reads IP of an interface from  it's connection
        on network manager.
        Returns False if comand of nmcli dose not execute correctly,
        None if connection exist but has no IP or an exception raises.
        a string that contains IP.
    """
    connection_name = get_interface_active_connection(interface)

    if not connection_name:
        return False

    cmd = "nmcli connection show {} | grep -i 'ipv4.addresses' | head -n 1".format(connection_name.replace(" ", "\ "))
    status, output = sudo_runner(cmd)

    if 'error' in output.lower():
        return False

    ip = None
    try:
        rgx_result = re.search(r'(\d+\.\d+\.\d+\.\d+)', output)
        if rgx_result:
            ip = rgx_result.group(1)
    except Exception as e:
        logger.error(e)

    return ip


def get_map_tun_interfaces():
    """
        This function returns a dictionary that maps interfaces and their tuns.
        example: {"enp0s8": "tun0"}
    """

    tuns = get_tun_interfaces()
    data = dict()
    for tun in tuns:
        tun_ip = get_interface_ip(tun)
        if tun_ip:
            for physical_interface in get_network_interfaces():
                if get_ip_interface_nmcli(physical_interface) == tun_ip:
                    data[physical_interface] = tun
                    break
    return data


def get_uptime():
    cmd = 'uptime -p'
    status, output = sudo_runner(cmd)

    if output[-1] == '\n':
        output = output[:-1]

    if not status:
        return None
    else:
        return output


def get_hostname():
    cmd = 'hostname'
    status, output = sudo_runner(cmd)

    if output[-1] == '\n':
        output = output[:-1]

    if not status:
        return None
    else:
        return output


def get_datetime():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_or_add_mark(policy_id, key):
    con = next(connect_to_db())
    if not con:
        return
    cursor = con.cursor()
    try:
        cursor.execute("SELECT mark FROM %s WHERE key=%s AND policy_id=%s \
                        LIMIT 1",
                       (AsIs("mark_map"), key, policy_id))
        fetched_data = cursor.fetchone()
        if fetched_data:
            mark = fetched_data[0]
        else:
            mark = None

        if mark is None:
            cursor.execute("SELECT s.i AS missing_cmd FROM \
                           generate_series(1,10000) s(i) WHERE NOT EXISTS \
                           (SELECT 1 FROM %s WHERE mark = s.i) limit 1",
                           (AsIs("mark_map"),))
            fetched_data = cursor.fetchone()
            if fetched_data:
                mark = fetched_data[0]
                cursor.execute("DELETE FROM %s WHERE key=%s AND policy_id=%s",
                               (AsIs("mark_map"), key, policy_id))
                cursor.execute("INSERT INTO %s (key, mark, policy_id) VALUES (%s, %s, %s)",
                               (AsIs("mark_map"), key, mark, policy_id))
                con.commit()
            else:
                mark = None
    except Exception as e:
        logger.error(e)
        # print(e)
        con.rollback()
    finally:
        cursor.close()

    return mark


def get_mark(policy_id, key):
    con = next(connect_to_db())
    mark = None
    if not con:
        return
    cursor = con.cursor()
    try:
        cursor.execute("SELECT mark FROM %s WHERE key=%s AND policy_id=%s \
                        LIMIT 1",
                       (AsIs("mark_map"), key, policy_id))
        fetched_data = cursor.fetchone()
        if fetched_data:
            mark = fetched_data[0]
        else:
            mark = None
    except Exception as e:
        logger.error(e)
        # print(e)
        con.rollback()
    finally:
        cursor.close()
    return mark


def delete_mark(policy_id, key):
    con = next(connect_to_db())
    success = None
    if not con:
        return
    cursor = con.cursor()
    try:
        cursor.execute("DELETE FROM %s WHERE key=%s AND policy_id=%s",
                       (AsIs("mark_map"), key, policy_id))
        con.commit()
        success = True
    except Exception as e:
        logger.error(e)
        # print(e)
        con.rollback()
        success = False
    finally:
        cursor.close()
    # print(success)
    return success
