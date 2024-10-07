import logging
import logging.handlers
import re
import subprocess
from collections import Counter

INVALID = 30
REJECT = 40
SUCCESS = 50
ERROR = 60
GW_CONFIG_FOUND = 70
ACTIVE_GW = 80
INACTIVE_GW = 90

DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING = "mydefaulttable"
DEFAULT_TABLE_ID_FOR_MULTIWAN_LOAD_BALANCING = 1000

rtabl_file_temp = "/tmp/rt_table_temp"

logger = logging.getLogger('MWMW')


def setLoggingConfigs():
    global logger
    logger.setLevel(logging.INFO)
    ch = logging.handlers.SysLogHandler(address='/dev/log',
                                        facility=logging.handlers.SysLogHandler.LOG_LOCAL0)
    # ch = logging.StreamHandler()
    ch.setLevel(logging.NOTSET)
    # create formatter
    formatter = logging.Formatter('%(name)s : %(levelname)s: %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)


def run_process(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errors = process.communicate()

        if errors:
            # print("error for running cmd %s is\n%s" % (command, errors))
            logger.error("Error returns after running <%s>\nThe reason is: %s" % (command, errors))
            return None
        return process

    except Exception as e:
        logger.debug("Cant run <%s>\nThe exception is: %s" % (command, str(e)))
        return None


def run_process_for_parsing_res(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        return process

    except Exception as e:
        logger.debug("Cant run <%s>\nThe exception is: %s" % (command, str(e)))
        return None


def add_default_route_table():
    '''
    To add a routing table into rt_table file
    :return:
    '''
    try:
        # to check for any duplicated routing table
        with open(rtabl_file, 'a+') as rt_table_file:
            if re.search("%s\t%s\n" % (
            DEFAULT_TABLE_ID_FOR_MULTIWAN_LOAD_BALANCING, DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING),
                         rt_table_file.read()):
                return INVALID

            rt_table_file.write("%s\t%s\n" % (
            DEFAULT_TABLE_ID_FOR_MULTIWAN_LOAD_BALANCING, DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING))
        return SUCCESS

    except IOError as e:
        logger.error(
            "An IOError error raised while adding route table to rt_table\n The reason is :%s" % (str(e)))
        return ERROR

    except Exception as e:
        logger.error(
            "An exception raised while adding route table to rt_table\n The reason is :%s" % (str(e)))
        return ERROR


def add_default_rule():
    rule_list_process = run_process_for_parsing_res('ip rule show')
    if rule_list_process and not rule_list_process.returncode:
        regex = "from all lookup %s" % DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING
        for line in iter(rule_list_process.stdout.readline, b''):
            if re.search(regex, line, re.M):
                return SUCCESS

        add_result = run_process('ip rule del table default')
        add_result = run_process('ip rule add from all table default prio 32768')
        add_result = run_process(
            'ip rule add from all table %s prio 32767' % DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING)
        if add_result and not add_result.returncode:
            return SUCCESS
    return REJECT


def add_default_routes(wan_link_list):
    '''
    Add or Update the routes of default SORTED BY WEIGHT Descending
    :param gateway_list: the list of all configured gateways with their interface name and weight
    each item of input list must contains:
        interface : Interface Name (eth0)
        gateway : Gateway ip address
        weight : balance each dev by a percentage of the connections based on weight
    :return: REJECT in case of any errors;otherwise returns SUCCESS
    '''
    routes_command = ""
    wanlinkkeys = ['gateway', 'interface', 'weight']

    for wan_link_data in wan_link_list:
        if Counter(wanlinkkeys) != Counter(list(wan_link_data.keys())):
            return INVALID

        elif wan_link_data['weight'] < 0 or wan_link_data['weight'] > 255:
            logger.error("Weight must be a possitive number, less than 255")
            return INVALID

        elif not re.match('^' + '[\.]'.join(['(\d{1,3})'] * 4) + '$', wan_link_data['gateway']):
            logger.error("Enter the valid IP format for gateway IP address")
            return INVALID

        routes_command = routes_command + "nexthop via %s dev %s weight %s " % (
        wan_link_data['gateway'], wan_link_data['interface'], wan_link_data['weight'])

    change_result = run_process("ip route add default table %s proto static %s" % (
    DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING, routes_command))

    if change_result and not change_result.returncode:
        return SUCCESS

    return REJECT


def delete_default_routes():
    delete_result = run_process("ip route flush table %s" % DEFAULT_TABLE_NAME_FOR_MULTIWAN_LOAD_BALANCING)
    if delete_result and not delete_result.returncode:
        return SUCCESS

    return REJECT


def update_default_routes(wan_link_list):
    delete_default_routes()
    return add_default_routes(wan_link_list)


def check_gateway(gw_ipaddr):
    '''
        returns INACTIVE_GW=90 if gateway is inactive,
        ACTIVE_GW=80 if gateway `is active`,
        None if parameter is not valid ip addr.
    '''
    gw_ipaddr = str(gw_ipaddr)
    ping_process = None
    if re.match('^' + '[\.]'.join(['(\d{1,3})'] * 4) + '$', gw_ipaddr):
        try:
            ping_process = run_process('ping %s -c 3 -W 1' % gw_ipaddr)
        except ValueError as e:
            logging.error("ping gateway IP command has been called with invalid arguments\n the reason is:%s" % str(e))
            return REJECT

        except Exception as e:
            logging.error("ping gateway IP command has been failed\n the reason is:%s" % str(e))
            return REJECT

        if ping_process and not ping_process.returncode:
            logger.info('gateway with ip address :' + gw_ipaddr + ' is active.')
            return ACTIVE_GW
        else:
            logger.info('gateway with ip address :' + gw_ipaddr + ' is inactive.')
            return INACTIVE_GW
    else:
        logger.error('you must enter a valid ip address to check the gateway')
        return INVALID


setLoggingConfigs()
