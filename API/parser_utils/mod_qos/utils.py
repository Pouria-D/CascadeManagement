import re
import sys
from os import abort

from psycopg2.extensions import AsIs
from psycopg2.extras import Json, DictCursor

from parser_utils import connect_to_db, printLog, logger
from parser_utils.config import config
from parser_utils.mod_qos import addShapingPolicy, deleteShapingPolicy, generalShapingConfiguration, clearConfig
from parser_utils.mod_resource.utils import get_map_tun_interfaces, \
    get_pppoe_interfaces_map

sys.path.append(config['TC_MIDDDLEWARE_PATH'])


################################################################################

def convert_ui_shaper_id_to_low_level_id(ui_id):
    '''
        This function gets an id as UI shaper ID and
        queries on DB to get generated shaper ID.
        Returns None if that shaper ID is not extsts on radius databse.
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()

    try:
        cursor.execute('SELECT id FROM %s WHERE ui_id=%s LIMIT 1',
                       (AsIs(config['QOS_SHAPER_TABLE']), ui_id)
                       )
        fetch_result = cursor.fetchone()
        if fetch_result:
            _id = fetch_result[0]
        else:
            _id = None
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()

    return _id


################################################################################

def get_shaper_id_of_policy_interface(interface, policy_id, traffic_type):
    '''
        This function takes interface name, policy ID and
        traffic type (download/upload) and queries on DB to return
        shaper ID and parent ID.
        Returns False if fetched data was empthy, None if an error occured,
        a dict with {'shaper_id': <int>, 'parent_id': <int>} if it
        fetched successfully.
    '''

    if traffic_type == 'download':
        shaper_query_column = 'reverse_shaper_id'
        shaper_parent_query_column = 'reverse_shaper_parent_id'
    elif traffic_type == 'upload':
        shaper_query_column = 'shaper_id'
        shaper_parent_query_column = 'shaper_parent_id'

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    result = dict()
    try:
        cursor.execute('SELECT %s, %s FROM %s \
            WHERE policy_id=%s AND interface=%s',
                       (AsIs(shaper_query_column),
                        AsIs(shaper_parent_query_column),
                        AsIs(config['QOS_POLICY_TABLE']),
                        policy_id, interface)
                       )
        fetch_result = cursor.fetchone()
        if fetch_result:
            if len(fetch_result) > 0 and fetch_result[1] is not None:
                if fetch_result[1] != 1:
                    result['shaper_id'] = fetch_result[1]
                    result['parent_id'] = fetch_result[0]
                else:
                    result['shaper_id'] = fetch_result[0]
                    result['parent_id'] = fetch_result[1]
        else:
            logger.warning("There is no policy with id: %s on interface %s" % \
                           (policy_id, interface))
            return False
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        printLog(e)
        return None
    finally:
        cursor.close()

    return result


################################################################################

def get_tc_data(interface, class_id, parent_id, date_from, traffic_type):
    '''
        This fuction takes interface name, shaper (class) ID, it's parent ID
        a datetime (with datetime.datetime type) and
        traffic_type (download/upload) and queries on DB to fetch data of
        tc and returns them as a list of dictonaries.
    '''

    if traffic_type == 'download':
        interface = get_ifb_of_interface(interface)

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor(cursor_factory=DictCursor)
    data = list()
    try:
        cursor.execute("SELECT * FROM %s WHERE interface=%s AND class_id=%s AND \
            parent_id=%s AND datetime >= %s ORDER by datetime",
                       (AsIs('tc_data'), interface, class_id, parent_id, date_from)
                       )
        fetched_data = cursor.fetchall()

        for record in fetched_data:
            data.append({
                'sent_bytes': record['sent_bytes'],
                'dropped_packets': int(record['dropped_packets']),
                'bandwidth': int(record['bandwidth']),
                'datetime': record['datetime'].strftime("%Y-%m-%d %H:%M:%S"),
            })
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    return data


################################################################################

def get_generated_shaper_id(ui_shaper_id):
    '''
        This function gets a shaper ID and returns it's generated shaper ID.
    '''
    if ui_shaper_id == None: return None

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    try:
        cursor.execute('SELECT id FROM %s WHERE ui_id=%s LIMIT 1',
                       (AsIs(config['QOS_SHAPER_TABLE']), ui_shaper_id)
                       )
        result = cursor.fetchone()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    if result:
        shaper_id = result[0]
    else:
        shaper_id = None

    return shaper_id


################################################################################

def get_interface_bw(interface, traffic_type, get_guarenteed_bw=True):
    '''
        This fuction takes an interface name and traffic type (downlaod/upload)
        and queries on DB (QoS  general config) to fetch guaranteed bandwidth
        of that. a paramter that recognizing return data (get_guarenteed_bw),
        if True, function will return guaranteed bandwidth ele max bandwidth.
        Returns an interger for bandwidth (bit per second) or
        None if fetch result was empthy.

    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()

    if traffic_type == 'download':
        if get_guarenteed_bw:
            query_column = 'guaranteed_bw_download'
        else:
            query_column = 'max_bw_download'

    elif traffic_type == 'upload':
        if get_guarenteed_bw:
            query_column = 'guaranteed_bw_upload'
        else:
            query_column = 'max_bw_upload'
    else:
        logger.error('%s recieved as traffic_type parameter.' % traffic_type)
        return None

    try:
        cursor.execute('SELECT %s FROM %s WHERE interface=%s LIMIT 1',
                       (AsIs(query_column),
                        AsIs(config['QOS_GENERAL_CONFIG_TABLE']),
                        interface)
                       )
        db_result = cursor.fetchone()
        if db_result and db_result[0]:
            result = cast_to_byte_per_second(db_result[0])
        else:
            return None
    except Exception as e:
        printLog(e)
        logger.error(str(e))

    return result


################################################################################

def get_interface_chart_free_slice(interface, traffic_type, data, with_max_bw=False):
    '''
        This fuction takes an interface name and traffic type (downlaod/upload)
        and some data about a chart in data parameter that is a list
        (other slice of a chart - used bandwidth) and gets total bandwidth on
        interface to calculating free bandwidth slice of chart.
    '''
    if not with_max_bw:
        total = get_interface_bw(interface, traffic_type)
    else:
        total = get_interface_bw(interface, traffic_type, get_guarenteed_bw=False)
        if not total:
            total = get_interface_bw(interface, traffic_type)
    if not total:
        return None
    total = total * 8 / 1000  # convert byte to Kbit
    used_bandwidth = 0
    for record in data:
        used_bandwidth += record['bandwidth']
    return total - used_bandwidth


################################################################################

def cast_to_byte_per_second(data, interface_data=None):
    '''
        Convert data to Bps.
        Returns integer.
    '''

    data = data.split()
    try:
        if 'Mbitps'.lower() in data[1].lower():
            result = int(float(data[0]) * 1000 * 1000 / 8)
        elif 'Kbitps'.lower() in data[1].lower():
            result = int(float(data[0]) * 1000 / 8)
        elif '%' in data[1] and interface_data:
            result = int(float(data[0]) / 100 * cast_to_byte_per_second(interface_data))
        elif '%' in data[1] and not interface_data:
            raise ValueError('Data contains %% but there in not any interface_data')
        else:
            raise ValueError('Data contains unknown value type')

    except ValueError as e:
        logger.error(str(e))
        result = None
    return result


################################################################################

def get_interface_shaper_chart(interface, traffic_type, with_max_bw=False):
    '''
        This fuction takes an interface name and traffic type (downlaod/upload)
        and check interface to be configured. Queries to DB to get policeis and
        shapers of an interface, calculates creates chart slices and returns it.
    '''

    con = next(connect_to_db())
    if not con: abort(500)
    cursor = con.cursor()

    try:
        cursor.execute("SELECT interface FROM %s WHERE enable='t'",
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']),)
                       )
        interface_list = [row[0] for row in cursor.fetchall()]
        if interface not in interface_list:
            return -1

        if traffic_type == 'download':
            shaper_query_column = 'reverse_shaper_id'
            is_ifb = True
        else:
            shaper_query_column = 'shaper_id'
            is_ifb = False

        cursor.execute("SELECT policy_id, %s FROM %s \
            WHERE interface=%s and enable='t'",
                       (AsIs(shaper_query_column),
                        AsIs(config['QOS_POLICY_TABLE']),
                        interface)
                       )
        fetch_result = cursor.fetchall()
        result = dict()
        for row in fetch_result:
            if row[1]:
                shaper_data = get_shaper(row[1], interface=interface, is_ifb=is_ifb)
                if shaper_data['shaper_id'] in list(result.keys()):
                    result[shaper_data['shaper_id']]['policy_list'].append(row[0])
                else:
                    rgx_result = re.search(r'(\d+)', shaper_data['shaper_gbw'])
                    if rgx_result:
                        bandwidth = int(rgx_result.group(1)) * 8 / 1000.0
                    else:
                        continue
                    chart_slice = {
                        'type': shaper_data['apply_type'],
                        'bandwidth': bandwidth,
                        'policy_list': [row[0]]
                    }
                    result[shaper_data['shaper_id']] = chart_slice

        extracted_data = list()
        for key, value in list(result.items()):
            if len(result[key]['policy_list']) > 1 and result[key]['type'] == 'per':
                for policy_id in result[key]['policy_list']:
                    extracted_data.append({
                        'type': result[key]['type'],
                        'bandwidth': result[key]['bandwidth'],
                        'policy_list': [policy_id]
                    })
            else:
                extracted_data.append(value)

        free_bw = get_interface_chart_free_slice(interface,
                                                 traffic_type, extracted_data, with_max_bw=with_max_bw)

        extracted_data.append({
            'type': 'free',
            'bandwidth': free_bw,
            'policy_list': [0]
        })

        return extracted_data
    except Exception as e:
        logger.error(str(e))
        return None
    finally:
        cursor.close()
        con.close()


################################################################################

def generate_shaper_id():
    '''
        This function choose the smallest number that there is not in ID of
        shaper table and parent_id of QoS policy table.
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    try:
        cursor.execute('SELECT shaper_parent_id FROM %s UNION SELECT \
            reverse_shaper_parent_id FROM %s UNION SELECT id FROM %s \
            UNION SELECT ui_id FROM %s',
                       (AsIs(config['QOS_POLICY_TABLE']),
                        AsIs(config['QOS_POLICY_TABLE']),
                        AsIs(config['QOS_SHAPER_TABLE']),
                        AsIs(config['QOS_SHAPER_TABLE']))
                       )
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return None

    result = cursor.fetchall()
    id_list = [record[0] for record in result]
    id_list.sort()
    if len(id_list) == 0:
        return 2
    for number in range(2, id_list[-1] + 1):
        if number not in id_list:
            return number
    return id_list[-1] + 1


################################################################################

def get_ifb_of_interface(interface):
    '''
        This function takes a query to QoS general config table and gets index
        of ifb that mapped to interface x and return ifb name (complete name).
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor(cursor_factory=DictCursor)
    try:
        cursor.execute('SELECT ifb_id FROM %s WHERE interface=%s LIMIT 1',
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']), interface))
        result = cursor.fetchone()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    if result:
        return 'ifb' + str(result[0] - 1)
    else:
        return None


################################################################################

def get_shaper_interfaces(shaper_id, policy_id=None, map_ifb=False):
    '''
        This function gets a shaper id and returns a list of interfaces that
        this shaper used in those. ( with count of repetitions )
    '''

    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    try:
        if policy_id and (not map_ifb):
            cursor.execute("SELECT interface FROM %s WHERE shaper_id=%s \
                AND policy_id != %s AND enable='t' AND enable_interface='t'",
                           (AsIs(config['QOS_POLICY_TABLE']), shaper_id, policy_id))

        elif policy_id and map_ifb:
            cursor.execute("SELECT interface FROM %s WHERE \
                reverse_shaper_id=%s AND policy_id != %s AND enable='t' AND enable_interface='t'",
                           (AsIs(config['QOS_POLICY_TABLE']), shaper_id, policy_id))

        else:
            cursor.execute("SELECT interface FROM %s WHERE shaper_id=%s AND enable='t' AND enable_interface='t'",
                           (AsIs(config['QOS_POLICY_TABLE']), shaper_id))
        result = cursor.fetchall()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    interfaces = [x[0] for x in result]
    data = list()
    if map_ifb:

        while len(interfaces) > 0:
            interface = interfaces.pop()
            data.append({'name': get_ifb_of_interface(interface),
                         'count': interfaces.count(interface) + 1})
            try:
                while True: interfaces.remove(interface)
            except ValueError:
                pass
    else:
        while len(interfaces) > 0:
            interface = interfaces.pop()
            data.append({'name': interface,
                         'count': interfaces.count(interface) + 1})
            try:
                while True: interfaces.remove(interface)
            except ValueError:
                pass

    return data


################################################################################

def get_policies_of_interface(interface):
    '''
        Gets an interface and returns policy ID
        of policies that seted on this interface.
    '''

    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    try:
        cursor.execute('SELECT DISTINCT policy_id FROM %s WHERE interface=%s',
                       (AsIs(config['QOS_POLICY_TABLE']), interface)
                       )
        result = cursor.fetchall()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return [row[0] for row in result]


################################################################################

def get_interface_status(interface):
    '''
        Returns True if interface was enable, False if was disabled.
    '''

    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    status = None

    try:
        cursor.execute('SELECT enable FROM %s WHERE interface=%s LIMIT 1',
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']), interface)
                       )
        result = cursor.fetchone()
        if result:
            status = result[0]
        else:
            status = None
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        status = None

    return status


################################################################################

def get_shaper(shaper_id, interface=None, is_ifb=True):
    '''
        This function fetches a shaper from database with it's ID.
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor(cursor_factory=DictCursor)
    try:
        cursor.execute('SELECT id, guaranteed_bw, max_bw, priority, apply_type \
            FROM %s WHERE id=%s LIMIT 1', (AsIs(config['QOS_SHAPER_TABLE']),
                                           shaper_id)
                       )
        shaper_result = cursor.fetchone()

        if interface:
            cursor.execute('SELECT guaranteed_bw_download, guaranteed_bw_upload, \
                max_bw_upload, max_bw_download FROM %s WHERE interface=%s LIMIT 1',
                           (AsIs(config['QOS_GENERAL_CONFIG_TABLE']), interface)
                           )
            interface_result = cursor.fetchone()
            if not interface_result:
                logger.error("Can't read data of %s from %s" % \
                             (interface, config['QOS_GENERAL_CONFIG_TABLE']))
                return None
            interface_data = dict(interface_result)
    except KeyError as e:
        logger.error(str(e))
        raise e
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    if not shaper_result:
        logger.error('This shaper (%s) is not exists.' % shaper_id)
        return None

    shaper = dict()
    shaper['shaper_id'] = shaper_result['id']

    if interface:
        if is_ifb:
            guaranteed_bw_bps = cast_to_byte_per_second(shaper_result['guaranteed_bw'],
                                                        interface_data['guaranteed_bw_download'])
        elif not is_ifb:
            guaranteed_bw_bps = cast_to_byte_per_second(shaper_result['guaranteed_bw'],
                                                        interface_data['guaranteed_bw_upload'])
        if is_ifb:
            if shaper_result['max_bw']:
                max_bw_bps = cast_to_byte_per_second(shaper_result['max_bw'],
                                                     interface_data['guaranteed_bw_download'])
            else:
                max_bw_bps = None
        elif not is_ifb:
            if shaper_result['max_bw']:
                max_bw_bps = cast_to_byte_per_second(shaper_result['max_bw'],
                                                     interface_data['guaranteed_bw_upload'])
            else:
                max_bw_bps = None

        if guaranteed_bw_bps:
            shaper['shaper_gbw'] = str(guaranteed_bw_bps) + 'bps'
        else:
            shaper['shaper_gbw'] = None

        if max_bw_bps:
            shaper['shaper_mbw'] = str(max_bw_bps) + 'bps'
        else:
            shaper['shaper_mbw'] = None

    shaper['priority'] = shaper_result['priority']
    shaper['apply_type'] = shaper_result['apply_type']

    return shaper


################################################################################

def get_policy(policy_id):
    '''
        Gets a policy ID and returns complete policy.
        If interface passed to this function, it will
        return policies with spesific interface.
    '''

    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor(cursor_factory=DictCursor)

    try:
        cursor.execute('SELECT policy_id, policy_order, src_address, src_user, \
            src_group, dst, schadule, interface, services, shaper_id,\
            reverse_shaper_id, shaper_parent_id, reverse_shaper_parent_id, enable \
            FROM %s WHERE policy_id=%s',
                       (AsIs(config['QOS_POLICY_TABLE']), policy_id)
                       )
        result = cursor.fetchall()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    policy_list = list()
    for record in result:
        policy = dict()
        policy[config['QOS_POLICY_ID']] = record['policy_id']
        policy[config['QOS_POLICY_ORDER']] = record['policy_order']
        policy[config['QOS_POLICY_SRC']] = record['src_address']
        policy[config['QOS_POLICY_USERS']] = record['src_user']
        policy[config['QOS_POLICY_GROUPS']] = record['src_group']
        policy[config['QOS_POLICY_DST']] = record['dst']
        policy[config['QOS_POLICY_SCHEDULE']] = record['schadule']
        policy[config['QOS_POLICY_SHAPER_ID']] = record['shaper_id']
        policy[config['QOS_POLICY_RVS_SHAPER']] = record['reverse_shaper_id']
        policy[config['QOS_POLICY_INTERFACES']] = record['interface']
        policy['ifb_int'] = get_ifb_of_interface(record['interface'])
        policy[config['QOS_POLICY_SERVICES']] = record['services']
        policy['enable'] = record['enable']

        if policy[config['QOS_POLICY_SHAPER_ID']]:
            policy['shaper'] = get_shaper(policy[config['QOS_POLICY_SHAPER_ID']],
                                          policy[config['QOS_POLICY_INTERFACES']], True)

            if policy['shaper']['apply_type'] == 'shared':
                policy['shaper']['parent_id'] = 1
                policy['shaper_existed'] = \
                    get_shaper_interfaces(policy['shaper']['shaper_id'],
                                          policy[config['QOS_POLICY_ID']])

            elif policy['shaper']['apply_type'] == 'per':
                policy['shaper']['parent_id'] = policy['shaper']['shaper_id']
                policy['shaper']['shaper_id'] = record['shaper_parent_id']
                policy['shaper_existed'] = \
                    get_shaper_interfaces(policy['shaper']['parent_id'],
                                          policy[config['QOS_POLICY_ID']])

        if policy[config['QOS_POLICY_RVS_SHAPER']]:
            policy['reverse_shaper'] = \
                get_shaper(policy[config['QOS_POLICY_RVS_SHAPER']],
                           policy[config['QOS_POLICY_INTERFACES']], False)

            if policy['reverse_shaper']['apply_type'] == 'shared':
                policy['reverse_shaper']['parent_id'] = 1
                policy['rvs_shaper_existed'] = \
                    get_shaper_interfaces(policy['reverse_shaper']['shaper_id'],
                                          policy[config['QOS_POLICY_ID']], map_ifb=True)

            elif policy['reverse_shaper']['apply_type'] == 'per':
                policy['reverse_shaper']['parent_id'] = \
                    policy['reverse_shaper']['shaper_id']
                policy['reverse_shaper']['shaper_id'] = \
                    record['reverse_shaper_parent_id']
                policy['rvs_shaper_existed'] = \
                    get_shaper_interfaces(policy['reverse_shaper']['parent_id'],
                                          policy[config['QOS_POLICY_ID']], map_ifb=True)

        if 'shaper_existed' not in list(policy.keys()):
            policy['shaper_existed'] = list()
        if 'rvs_shaper_existed' not in list(policy.keys()):
            policy['rvs_shaper_existed'] = list()

        # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        if policy['shaper']:
            wan_mbw = get_interface_bw(policy[config['QOS_POLICY_INTERFACES']],
                                       'upload', get_guarenteed_bw=False)
            if not wan_mbw:
                wan_mbw = get_interface_bw(
                    policy[config['QOS_POLICY_INTERFACES']],
                    'upload', get_guarenteed_bw=True)
                if wan_mbw:
                    wan_mbw = "%sbps" % wan_mbw
                else:
                    wan_mbw = None
            else:
                wan_mbw = "%sbps" % wan_mbw

            policy['wan_mbw'] = wan_mbw
            upload_chart = get_interface_shaper_chart(
                policy[config['QOS_POLICY_INTERFACES']], 'upload', with_max_bw=True)
            if upload_chart != -1:
                for _slice in upload_chart:
                    if _slice['type'] == 'free':
                        policy['wan_remain'] = _slice['bandwidth']
                        break
                else:
                    policy['wan_remain'] = None
            else:
                policy['wan_remain'] = None
        else:
            policy['wan_remain'] = None
            policy['wan_mbw'] = None
        # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        if policy['reverse_shaper']:
            ifb_mbw = get_interface_bw(policy[config['QOS_POLICY_INTERFACES']],
                                       'download', get_guarenteed_bw=False)
            if not ifb_mbw:
                ifb_mbw = get_interface_bw(policy[config['QOS_POLICY_INTERFACES']],
                                           'download', get_guarenteed_bw=True)
                if ifb_mbw:
                    ifb_mbw = "%sbps" % ifb_mbw
                else:
                    ifb_mbw = None
            else:
                ifb_mbw = "%sbps" % ifb_mbw
            policy['ifb_mbw'] = ifb_mbw

            download_chart = get_interface_shaper_chart(
                policy[config['QOS_POLICY_INTERFACES']],
                'download', with_max_bw=True)
            if download_chart != -1:
                for _slice in download_chart:
                    if _slice['type'] == 'free':
                        policy['ifb_remain'] = _slice['bandwidth']
                        break
                else:
                    policy['ifb_remain'] = None
            else:
                policy['ifb_remain'] = None

        else:
            policy['ifb_remain'] = None
            policy['ifb_mbw'] = None

        policy['tuns'] = get_map_tun_interfaces()
        pppoe_map = get_pppoe_interfaces_map()
        if pppoe_map is not None:
            policy['tuns'].update(pppoe_map)
        policy_list.append(policy)

    return policy_list


################################################################################

def add_policy(policy):
    '''
        Adds a QOS policy.
        Returns True for successfully save opration and False when it fails.
    '''

    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()

    try:
        for interface in policy[config['QOS_POLICY_INTERFACES']]:
            cursor.execute('INSERT INTO %s (policy_id, policy_order, src_address, \
                src_user, src_group, dst, schadule, shaper_id, reverse_shaper_id, \
                services, enable, enable_interface, interface) VALUES \
                (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                           (AsIs(config['QOS_POLICY_TABLE']),
                            policy[config['QOS_POLICY_ID']],
                            policy[config['QOS_POLICY_ORDER']],
                            Json(policy[config['QOS_POLICY_SRC']]),
                            Json(policy[config['QOS_POLICY_USERS']]),
                            Json(policy[config['QOS_POLICY_GROUPS']]),
                            Json(policy[config['QOS_POLICY_DST']]),
                            Json(policy[config['QOS_POLICY_SCHEDULE']]),
                            get_generated_shaper_id(policy[config['QOS_POLICY_SHAPER_ID']]),
                            get_generated_shaper_id(policy[config['QOS_POLICY_RVS_SHAPER']]),
                            Json(policy[config['QOS_POLICY_SERVICES']]),
                            policy[config['QOS_POLICY_STATUS']],
                            get_interface_status(interface),
                            interface)
                           )

        if policy[config['QOS_POLICY_SHAPER_ID']]:

            policy['shaper'] = get_shaper(get_generated_shaper_id(policy[config['QOS_POLICY_SHAPER_ID']]))

            if policy['shaper']['apply_type'] == 'shared':

                policy['shaper']['parent_id'] = 1

                cursor.execute('UPDATE %s SET shaper_parent_id=%s WHERE policy_id=%s',
                               (AsIs(config['QOS_POLICY_TABLE']),
                                policy['shaper']['parent_id'],
                                policy[config['QOS_POLICY_ID']])
                               )

            elif policy['shaper']['apply_type'] == 'per':

                policy['shaper']['parent_id'] = policy['shaper']['shaper_id']

                policy['shaper']['shaper_id'] = generate_shaper_id()

                cursor.execute('UPDATE %s SET shaper_parent_id=%s WHERE policy_id=%s',
                               (AsIs(config['QOS_POLICY_TABLE']),
                                policy['shaper']['shaper_id'],
                                policy[config['QOS_POLICY_ID']])
                               )

        if policy[config['QOS_POLICY_RVS_SHAPER']]:

            policy['reverse_shaper'] = \
                get_shaper(get_generated_shaper_id(policy[config['QOS_POLICY_RVS_SHAPER']]))

            if policy['reverse_shaper']['apply_type'] == 'shared':

                policy['reverse_shaper']['parent_id'] = 1

                cursor.execute('UPDATE %s SET reverse_shaper_parent_id=%s \
                    WHERE policy_id=%s',
                               (AsIs(config['QOS_POLICY_TABLE']),
                                policy['reverse_shaper']['parent_id'],
                                policy[config['QOS_POLICY_ID']])
                               )

            elif policy['reverse_shaper']['apply_type'] == 'per':
                policy['reverse_shaper']['parent_id'] = \
                    policy['reverse_shaper']['shaper_id']

                policy['reverse_shaper']['shaper_id'] = generate_shaper_id()

                cursor.execute('UPDATE %s SET reverse_shaper_parent_id=%s \
                    WHERE policy_id=%s',
                               (AsIs(config['QOS_POLICY_TABLE']),
                                policy['reverse_shaper']['shaper_id'],
                                policy[config['QOS_POLICY_ID']])
                               )

        con.commit()
    except Exception as e:
        logger.error(e)
        con.rollback()
        return False
    finally:
        cursor.close()

    policy_list = get_policy(policy[config['QOS_POLICY_ID']])

    returned_codes_mw = list()
    for p in policy_list:
        if get_interface_status(p[config['QOS_POLICY_INTERFACES']]) and p['enable']:
            returned_codes_mw.append(addShapingPolicy(p))

    if 1 in returned_codes_mw:
        return 1
    elif 6 in returned_codes_mw:
        return 6
    else:
        return 2


################################################################################

def increase_policy_remain_field(policy):
    if policy['ifb_remain']:
        shaper_rgx = re.search(r'(\d+)', policy['reverse_shaper']['shaper_gbw'])
        if shaper_rgx:
            shaper_amount = float(shaper_rgx.group(1))
        else:
            shaper_amount = 0
        policy['ifb_remain'] = (policy['ifb_remain'] * 1000 / 8 + shaper_amount) * 8 / 1000

    if policy['wan_remain']:
        shaper_rgx = re.search(r'(\d+)', policy['shaper']['shaper_gbw'])
        if shaper_rgx:
            shaper_amount = float(shaper_rgx.group(1))
        else:
            shaper_amount = 0
        policy['wan_remain'] = (policy['wan_remain'] * 1000 / 8 + shaper_amount) * 8 / 1000
    return policy


################################################################################

def delete_policy(policy_id):
    '''
        Deletes a policy.
        Returns True for successfully save opration and False when it fails.
    '''

    policy_list = get_policy(policy_id)

    returned_codes_mw = list()
    for policy in policy_list:
        if get_interface_status(policy[config['QOS_POLICY_INTERFACES']]) and \
                policy['enable']:
            policy = increase_policy_remain_field(policy)
            returned_codes_mw.append(deleteShapingPolicy(policy))

    if 1 in returned_codes_mw:
        return 1
    elif 6 in returned_codes_mw:
        return 6
    else:
        con = next(connect_to_db())
        if not con: return None
        cursor = con.cursor()
        try:
            for policy in policy_list:
                cursor.execute('DELETE FROM %s WHERE policy_id=%s',
                               (AsIs(config['QOS_POLICY_TABLE']), policy['policy_id']))

            con.commit()
        except Exception as e:
            logger.error(str(e))
            con.rollback()
            return None
        finally:
            cursor.close()
        return 2


################################################################################

def update_policy(policy):
    '''
        Updates a QOS policy.
        Returns True for successfully save opration and False when it fails.
    '''

    con = next(connect_to_db())
    if not con: return 1
    cursor = con.cursor()
    try:
        cursor.execute('SELECT policy_order FROM %s WHERE policy_id=%s LIMIT 1',
                       (AsIs(config['QOS_POLICY_TABLE']),
                        policy[config['QOS_POLICY_ID']])
                       )
        result = cursor.fetchone()
        if result:
            if policy[config['QOS_POLICY_ORDER']] > result[0]:
                cursor.execute('UPDATE %s SET policy_order = policy_order - 1\
                    WHERE policy_order > %s AND policy_order <= %s',
                               (AsIs(config['QOS_POLICY_TABLE']), result[0],
                                policy[config['QOS_POLICY_ORDER']])
                               )
            elif policy[config['QOS_POLICY_ORDER']] < result[0]:
                cursor.execute('UPDATE %s SET policy_order = policy_order + 1\
                    WHERE policy_order < %s AND policy_order >= %s',
                               (AsIs(config['QOS_POLICY_TABLE']), result[0],
                                policy[config['QOS_POLICY_ORDER']])
                               )
            con.commit()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    if delete_policy(policy[config['QOS_POLICY_ID']]) == 2:
        return add_policy(policy)
    else:
        return 1


################################################################################

def update_policy_by_id(policy_id):
    '''
        Updates a QOS policy. (fetches from database then updates it.)
        Returns True for successfully save opration and False when it fails.
    '''

    policy_list = get_policy(policy_id)
    returned_codes_mw = list()
    for policy in policy_list:
        if get_interface_status(policy[config['QOS_POLICY_INTERFACES']]) and \
                policy['enable']:
            returned_codes_mw.append(deleteShapingPolicy(policy))

    for policy in policy_list:
        if get_interface_status(policy[config['QOS_POLICY_INTERFACES']]) and \
                policy['enable']:
            returned_codes_mw.append(addShapingPolicy(policy))

    if 1 in returned_codes_mw:
        return 1
    elif 6 in returned_codes_mw:
        return 6
    else:
        return 2


################################################################################

def test_policy_exstance(policy_id):
    '''
        Tests a policy exists or not.
        Returns True if exists.
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()
    try:
        cursor.execute('SELECT policy_id FROM %s WHERE policy_id=%s',
                       (AsIs(config['QOS_POLICY_TABLE']), policy_id))
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return None

    count = cursor.rowcount
    cursor.close()
    return count


################################################################################

def add_shaper(shaper):
    '''
        Adds a QOS shaper.
        Returns True for successfully save opration and False when it fails.
    '''

    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        shaper_id = generate_shaper_id()
        cursor.execute('INSERT INTO %s (ui_id, guaranteed_bw, max_bw, \
            priority, apply_type, id) VALUES (%s,%s,%s,%s,%s,%s)',
                       (AsIs(config['QOS_SHAPER_TABLE']),
                        shaper[config['QOS_SHAPER_ID']],
                        shaper[config['QOS_SHAPER_GUARANTEED_BW']],
                        shaper[config['QOS_SHAPER_MAX_BW']],
                        shaper[config['QOS_SHAPER_PRIORITY']],
                        shaper[config['QOS_SHAPER_APPLY_TYPE']],
                        shaper_id)
                       )
        con.commit()
    except KeyError as e:
        logger.error(str(e))
        raise e
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()

    return True


################################################################################

def update_shaper(shaper):
    '''
        Updates a QOS shaper.
        Returns True for successfully save opration and False when it fails.
    '''
    returned_codes_mw = list()

    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        cursor.execute('SELECT policy_id from %s WHERE shaper_id=%s OR \
            reverse_shaper_id=%s',
                       (AsIs(config['QOS_POLICY_TABLE']),
                        get_generated_shaper_id(shaper[config['QOS_SHAPER_ID']]),
                        get_generated_shaper_id(shaper[config['QOS_SHAPER_ID']]))
                       )
        policy_id_list = [row[0] for row in cursor.fetchall()]
        policy_id_list = set(policy_id_list)
    except KeyError as e:
        logger.error(str(e))
        raise e
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()
    for policy_id in policy_id_list:
        policy_list = get_policy(policy_id)
        for policy in policy_list:
            if get_interface_status(policy[config['QOS_POLICY_INTERFACES']]) and \
                    policy['enable']:
                returned_codes_mw.append(deleteShapingPolicy(policy))

    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        cursor.execute('SELECT apply_type FROM %s WHERE ui_id=%s LIMIT 1',
                       (AsIs(config['QOS_SHAPER_TABLE']),
                        shaper[config['QOS_SHAPER_ID']])
                       )
        result = cursor.fetchone()
        if not result:
            return False

        if result[0] != shaper[config['QOS_SHAPER_APPLY_TYPE']]:
            for policy_id in policy_id_list:
                if shaper[config['QOS_SHAPER_APPLY_TYPE']] == 'shared':
                    cursor.execute('UPDATE %s SET shaper_parent_id=1 WHERE shaper_id=%s AND policy_id=%s',
                                   (AsIs(config['QOS_POLICY_TABLE']),
                                    shaper[config['QOS_SHAPER_ID']],
                                    policy_id)
                                   )
                    cursor.execute('UPDATE %s SET reverse_shaper_parent_id=1 \
                        WHERE reverse_shaper_id=%s AND policy_id=%s',
                                   (AsIs(config['QOS_POLICY_TABLE']),
                                    shaper[config['QOS_SHAPER_ID']],
                                    policy_id)
                                   )

                elif shaper[config['QOS_SHAPER_APPLY_TYPE']] == 'per':
                    cursor.execute('UPDATE %s SET shaper_parent_id=%s \
                        WHERE shaper_id=%s AND policy_id=%s',
                                   (AsIs(config['QOS_POLICY_TABLE']),
                                    generate_shaper_id(),
                                    shaper[config['QOS_SHAPER_ID']],
                                    policy_id)
                                   )
                    cursor.execute('UPDATE %s SET reverse_shaper_parent_id=%s \
                        WHERE reverse_shaper_id=%s AND policy_id=%s',
                                   (AsIs(config['QOS_POLICY_TABLE']),
                                    generate_shaper_id(),
                                    shaper[config['QOS_SHAPER_ID']],
                                    policy_id)
                                   )

        cursor.execute('UPDATE %s SET guaranteed_bw=%s, max_bw=%s, \
            priority=%s, apply_type=%s WHERE ui_id=%s',
                       (AsIs(config['QOS_SHAPER_TABLE']),
                        shaper[config['QOS_SHAPER_GUARANTEED_BW']],
                        shaper[config['QOS_SHAPER_MAX_BW']],
                        shaper[config['QOS_SHAPER_PRIORITY']],
                        shaper[config['QOS_SHAPER_APPLY_TYPE']],
                        shaper[config['QOS_SHAPER_ID']])
                       )
        con.commit()
    except KeyError as e:
        logger.error(str(e))
        raise e
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()

    for policy_id in policy_id_list:
        policy_list = get_policy(policy_id)
        for p in policy_list:
            if get_interface_status(p[config['QOS_POLICY_INTERFACES']]) and \
                    p['enable']:
                returned_codes_mw.append(addShapingPolicy(p))

    if 1 in returned_codes_mw:
        return 1
    elif 6 in returned_codes_mw:
        return 6
    else:
        return 2


################################################################################

def delete_shaper(shaper_id):
    '''
        Deletes a shaper.
        Returns True for successfully save opration and False when it fails.
    '''

    status = False
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()

    try:
        cursor.execute('SELECT policy_id from %s WHERE shaper_id=%s OR \
            reverse_shaper_id=%s', (AsIs(config['QOS_POLICY_TABLE']),
                                    shaper_id, shaper_id)
                       )
        policy_list = [row[0] for row in cursor.fetchall()]
        policy_list = set(policy_list)

        cursor.execute('DELETE FROM %s WHERE ui_id=%s',
                       (AsIs(config['QOS_SHAPER_TABLE']), shaper_id)
                       )

        con.commit()
        status = True
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    if status:
        returned_codes_mw = list()
        for policy_id in policy_list:
            returned_codes_mw.append(delete_policy(policy_id))

        if 1 in returned_codes_mw:
            return 1
        elif 6 in returned_codes_mw:
            return 6
        else:
            return 2
    else:
        return False


################################################################################

def test_shaper_exstance(shaper_id):
    '''
        Tests a shaper exists or not.
        Returns True if exists.
    '''

    con = next(connect_to_db())
    if not con: return 0
    cursor = con.cursor()
    try:
        cursor.execute('SELECT ui_id FROM %s WHERE ui_id=%s',
                       (AsIs(config['QOS_SHAPER_TABLE']), shaper_id))
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return None

    count = cursor.rowcount
    cursor.close()
    return count


################################################################################

def test_interface_general_config(interface):
    '''
        Tests interface general configs exists or not.
        Returns True if exists.
    '''

    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    try:
        cursor.execute('SELECT interface, enable FROM %s WHERE interface=%s',
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']), interface))
        result = cursor.fetchone()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return result


################################################################################

def set_general_config(config):
    '''
        Config network interafaces general configs (guaranteed or max bandwidth).
        Returns True for successfully save opration and False when it fails.
    '''
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()

    try:
        if config[config['QOS_GC_MAX_BW_UPLOAD']]:
            max_upload = str(cast_to_byte_per_second(config[config['QOS_GC_MAX_BW_UPLOAD']])) + 'bps'
        else:
            max_upload = None
        if config[config['QOS_GC_MAX_BW_DOWNLOAD']]:
            max_download = str(cast_to_byte_per_second(config[config['QOS_GC_MAX_BW_DOWNLOAD']])) + 'bps'
        else:
            max_download = None

        data = {
            'interface': config[config['QOS_GC_WAN']],
            'dl_mbw': max_download,
            'ul_mbw': max_upload,
            'dl_gbw': str(cast_to_byte_per_second(config[config['QOS_GC_GUARANTEED_BW_DOWNLOAD']])) + 'bps',
            'ul_gbw': str(cast_to_byte_per_second(config[config['QOS_GC_GUARANTEED_BW_UPLOAD']])) + 'bps',
        }

        if test_interface_general_config(config[config['QOS_GC_WAN']]):

            cursor.execute('UPDATE %s SET guaranteed_bw_download=%s, \
                guaranteed_bw_upload=%s, max_bw_upload=%s, max_bw_download=%s \
                WHERE interface=%s',
                           (AsIs(config['QOS_GENERAL_CONFIG_TABLE']),
                            config[config['QOS_GC_GUARANTEED_BW_DOWNLOAD']],
                            config[config['QOS_GC_GUARANTEED_BW_UPLOAD']],
                            config[config['QOS_GC_MAX_BW_UPLOAD']],
                            config[config['QOS_GC_MAX_BW_DOWNLOAD']],
                            config[config['QOS_GC_WAN']])
                           )

            data['action'] = 'update'

        else:
            cursor.execute('INSERT INTO %s (interface, guaranteed_bw_download, \
                guaranteed_bw_upload, max_bw_upload, max_bw_download) \
                VALUES (%s,%s,%s,%s,%s)',
                           (AsIs(config['QOS_GENERAL_CONFIG_TABLE']),
                            config[config['QOS_GC_WAN']],
                            config[config['QOS_GC_GUARANTEED_BW_DOWNLOAD']],
                            config[config['QOS_GC_GUARANTEED_BW_UPLOAD']],
                            config[config['QOS_GC_MAX_BW_UPLOAD']],
                            config[config['QOS_GC_MAX_BW_DOWNLOAD']])
                           )

            data['action'] = 'add'

        con.commit()
        data['ifb'] = get_ifb_of_interface(config[config['QOS_GC_WAN']])
        data['tuns'] = get_map_tun_interfaces()
        pppoe_map = get_pppoe_interfaces_map()
        if pppoe_map is not None:
            data['tuns'].update(pppoe_map)
        cursor.execute("SELECT enable FROM %s WHERE interface=%s",
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']),
                        config[config['QOS_GC_WAN']])
                       )

        interface_is_enable = cursor.fetchone()
        if interface_is_enable and interface_is_enable[0]:
            result = generalShapingConfiguration(data)
            if data['action'] == 'update':
                policy_list = get_policies_of_interface(config[config['QOS_GC_WAN']])
                for policy_id in policy_list:
                    update_policy_by_id(policy_id)
        else:
            result = 2

    except KeyError as e:
        logger.error(str(e))
        raise e
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()

    return result


################################################################################

def set_false_enable_interface_all_qos_policy(interface):
    state = False
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        cursor.execute("UPDATE %s SET enable_interface='f' WHERE interface=%s",
                       (AsIs(config['QOS_POLICY_TABLE']), interface)
                       )
        con.commit()
        state = True
    except Exception as e:
        con.rollback()
    return state


################################################################################

def set_true_enable_interface_one_qos_policy(policy_id, interface):
    state = False
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        cursor.execute("UPDATE %s SET enable_interface='t' \
            WHERE interface=%s AND policy_id=%s",
                       (AsIs(config['QOS_POLICY_TABLE']), interface, policy_id)
                       )
        con.commit()
        state = True
    except Exception as e:
        con.rollback()
    return state


################################################################################

def change_status_interface(interface, enable):
    '''
        This function changes status of an interface and disables
        policies  of that interface before disable and enables
        policies of that interface after enable.
    '''

    current_interface_data = test_interface_general_config(interface)
    if not current_interface_data:
        return None

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor(cursor_factory=DictCursor)
    try:
        cursor.execute('UPDATE %s SET enable=%s WHERE interface=%s',
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']), enable, interface)
                       )

        con.commit()

        cursor.execute('SELECT interface, guaranteed_bw_download,\
            guaranteed_bw_upload, max_bw_upload, max_bw_download \
            FROM %s WHERE interface=%s LIMIT 1',
                       (AsIs(config['QOS_GENERAL_CONFIG_TABLE']), interface)
                       )
        result = cursor.fetchone()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return None
    finally:
        cursor.close()

    if result:
        policy_id_list = get_policies_of_interface(interface)
        if enable:
            if result['max_bw_upload']:
                max_upload = str(cast_to_byte_per_second(result['max_bw_upload'])) + 'bps'
            else:
                max_upload = None
            if result['max_bw_download']:
                max_download = str(cast_to_byte_per_second(result['max_bw_download'])) + 'bps'
            else:
                max_download = None

            data = {
                'interface': result['interface'],
                'dl_mbw': max_download,
                'ul_mbw': max_upload,
                'dl_gbw': str(cast_to_byte_per_second(result['guaranteed_bw_download'])) + 'bps',
                'ul_gbw': str(cast_to_byte_per_second(result['guaranteed_bw_upload'])) + 'bps',
                'ifb': get_ifb_of_interface(result['interface']),
                'action': 'add'

            }
            data['tuns'] = get_map_tun_interfaces()
            pppoe_map = get_pppoe_interfaces_map()
            if pppoe_map is not None:
                data['tuns'].update(pppoe_map)
            generalShapingConfiguration(data)

            returned_codes_mw = list()
            for policy_id in policy_id_list:
                policy_list = get_policy(policy_id)
                if set_true_enable_interface_one_qos_policy(policy_id, interface):
                    for policy in policy_list:
                        if policy[config['QOS_POLICY_INTERFACES']] == \
                                interface and policy['enable']:
                            returned_codes_mw.append(addShapingPolicy(policy))

            if 1 in returned_codes_mw:
                return 1
            elif 6 in returned_codes_mw:
                return 6
            else:
                return 2
        else:
            map_interfaces = get_map_tun_interfaces()
            pppoe_map = get_pppoe_interfaces_map()
            if pppoe_map is not None:
                map_interfaces.update(pppoe_map)
            if set_false_enable_interface_all_qos_policy(result['interface']):
                clearConfig(result['interface'],
                            get_ifb_of_interface(result['interface']),
                            map_interfaces,
                            policy_id_list
                            )
                return 2
            else:
                return 1
    else:
        return None


################################################################################

def change_policy_order(policy_id, order):
    '''
        Change order of policy.
    '''
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        cursor.execute('UPDATE %s SET policy_order=%s WHERE policy_id =%s',
                       (AsIs(config['QOS_POLICY_TABLE']), order, policy_id))
        con.commit()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()

    return True


################################################################################

def change_policy_status(policy_id, status):
    '''
        Change status of policy.
        Type of status is boolean.
    '''
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    try:
        cursor.execute('SELECT enable FROM %s WHERE policy_id=%s LIMIT 1',
                       (AsIs(config['QOS_POLICY_TABLE']), policy_id)
                       )

        old_status = cursor.fetchone()
        if old_status and old_status[0] == status:
            return True

        cursor.execute('UPDATE %s SET enable=%s WHERE policy_id =%s',
                       (AsIs(config['QOS_POLICY_TABLE']), status, policy_id))
        con.commit()
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False
    finally:
        cursor.close()

    policy_list = get_policy(policy_id)
    returned_codes_mw = list()
    for policy in policy_list:
        if status:
            if get_interface_status(policy[config['QOS_POLICY_INTERFACES']]):
                returned_codes_mw.append(addShapingPolicy(policy))
        else:
            if get_interface_status(policy[config['QOS_POLICY_INTERFACES']]):
                returned_codes_mw.append(deleteShapingPolicy(policy))

    if 1 in returned_codes_mw:
        return 1
    elif 4 in returned_codes_mw:
        return 4
    else:
        return 2


################################################################################

def get_policy_list():
    '''
        Returns list of {"id": x, "order": y}
    '''

    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    try:
        cursor.execute("SELECT DISTINCT policy_id, policy_order FROM %s",
                       (AsIs(config['QOS_POLICY_TABLE']),))
        result = cursor.fetchall()
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    return [{'id': int(row[0]), 'order': int(row[1])} for row in result]


################################################################################

def reapply_qos_policies_of_interface(interface, opration=False):
    if opration not in ("ADD", "DELETE"):
        raise ValueError('"opration" value must be "ADD" or "DELETE"')

    if opration == 'ADD':
        change_status_interface(interface, True)
    elif opration == 'DELETE':
        change_status_interface(interface, False)
