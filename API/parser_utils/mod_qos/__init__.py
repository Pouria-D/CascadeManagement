import logging
import logging.handlers
import os
import re
import subprocess
import time

from psycopg2.extras import *

# import coloredlogs as coloredlogs

TC = "tc"
IPTABLES = "iptables"
HANDLE = 10
MAX_NUM_IFBS = 8
ROOT_CLASS_ID = 1
DEFAULT_POLICY_ID = 9999
numberOfPacketsForNdpiDetection = 10
FAKE_MARK = 10000
# RLM codes
RLM_MODULE_REJECT = 0
RLM_MODULE_FAIL = 1
RLM_MODULE_OK = 2
RLM_MODULE_HANDLED = 3
RLM_MODULE_INVALID = 4
RLM_MODULE_USERLOCK = 5
RLM_MODULE_NOTFOUND = 6
RLM_MODULE_NOOP = 7
RLM_MODULE_UPDATED = 8
RLM_MODULE_NUMCODES = 9
# config
DL_GUARANTEED_BW = "dl_gbw"
DL_MAX_BW = "dl_mbw"
UL_GUARANTEED_BW = "ul_gbw"
UL_MAX_BW = "ul_mbw"
INTERFACE = "interface"
CONFIG_ACTION = "action"
IFB_INTERFACE = "ifb"
# shaper
SHAPER_ID = "shaper_id"
PARENT_ID = "parent_id"
SHAPER_GBW = "shaper_gbw"
SHAPER_MBW = "shaper_mbw"
PRIORITY = "priority"
APPLY_TYPE = "apply_type"
PER_POLICY = "per"
SHARED = "shared"

# policy
POLICY_ID = "policy_id"
POLICY_USERS = "users"
POLICY_GROUPS = "groups"
POLICY_SRC = "src"
POLICY_DST = "dst"
POLICY_ORDER = "policy_order"
POLICY_SCHEDULE = "schedule"
POLICY_SERVICES = "services"
WAN_INT = "interfaces"
IFB_INT = "ifb_int"
SHAPER = "shaper"
REVERSE_SHAPER = "reverse_shaper"
SHAPER_EXSITED = "shaper_existed"
REVERSE_SHAPER_EXISTED = "rvs_shaper_existed"
POLICY_LOG = "log"
OLD_NAME_PREFIX = "_old"
COUNT = "count"
NAME = "name"
WAN_REMAINED_BW = "wan_remain"
IFB_REMAINED_BW = "ifb_remain"
IFB_MAX_BW = "ifb_mbw"
WAN_MAX_BW = "wan_mbw"
# create logger
logger = logging.getLogger('QOSMW')


def setLoggingConfigs():
    global logger
    logger.setLevel(logging.DEBUG)
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    # ch = logging.handlers.SysLogHandler(address='/dev/log',
    #                                    facility=logging.handlers.SysLogHandler.LOG_LOCAL0)
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(levelname)s: %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    # add color to logger


#    coloredlogs.install(logger=logger)

def clearConfig(interface, ifb, tuns={}, policy_ids=None):
    checkClassExistance = TC + ' class show dev ' + str(interface)
    process = runProcess(checkClassExistance)
    exFlag = False
    result = None
    for line in iter(process.stdout.readline, b''):
        result = re.search("htb", line, re.M)
        break
    if result == None:
        exFlag = False
    else:
        exFlag = True

    if exFlag:
        clearRoot = TC + " qdisc del dev " + interface + " root"
        runProcess(clearRoot)
        clearIngress = TC + " qdisc del dev " + interface + " ingress"
        runProcess(clearIngress)
        clearIfb = TC + " qdisc del dev " + ifb + " root"
        runProcess(clearIfb)
        logger.info('all configurations removed on \'' + str(interface) + '\' and \'' + str(ifb) + '\'')
        deleteDefaultPolicy9999 = 'iptables -t mangle -D POSTROUTING -o ' + str(
            interface) + ' -m mark --mark 0x0 -j qos_policy_id_' + str(DEFAULT_POLICY_ID)
        process = runProcess(deleteDefaultPolicy9999)
        if process.returncode == 0:
            if canIdeleteDefaultChain9999():
                formatChainPolicy9999 = 'iptables -t mangle -F qos_policy_id_' + str(DEFAULT_POLICY_ID)
                process = runProcess(formatChainPolicy9999)

                deleteChainPolicy9999 = 'iptables -t mangle -X qos_policy_id_' + str(DEFAULT_POLICY_ID)
                process = runProcess(deleteChainPolicy9999)

        canIdeleteDpiCheck = True
        process = runProcess(IPTABLES + ' -t mangle -nvL POSTROUTING')
        re_pattern = r'\bqos_policy_id_9999.*?\b'
        for line in iter(process.stdout.readline, b''):
            result = re.findall(re_pattern, line)
            if result:
                canIdeleteDpiCheck = False
                break
        if canIdeleteDpiCheck:
            process = runProcess("iptables -t mangle -D PREROUTING -mndpi --dpi_check")

            process = runProcess("iptables -t mangle -D POSTROUTING -mndpi --dpi_check")

        if policy_ids:
            for policy_id in policy_ids:
                policyLineNumbersInIptables = getLinesOfPolicy(policy_id, interface)
                policyLineNumbersInIptables.sort()
                policyLineNumbersInIptables.reverse()
                # print(policyLineNumbersInIptables)
                if policyLineNumbersInIptables:
                    for line_num in policyLineNumbersInIptables:
                        deletePolicyFromIptable = 'iptables -t mangle -D POSTROUTING ' + str(line_num)
                        process = runProcess(deletePolicyFromIptable)
                        if process.returncode == 0:
                            logger.info(
                                'policy ' + str(policy_id) + ' for ' + str(interface) + ' in line ' + str(
                                    line_num) + ' deleted.')
                        else:
                            logger.info(
                                'can\'t delete policy ' + str(policy_id) + ' for ' + str(interface) + ' in line ' + str(
                                    line_num))
                            fillErrors(process)
                            return RLM_MODULE_FAIL
                if isThisChainUsedInAnotherPartOfPolicy(policy_id) == False:
                    formatChainOfPolicy = 'iptables -t mangle -F qos_policy_id_' + str(policy_id)
                    process = runProcess(formatChainOfPolicy)

                    deleteChainOfPolicy = 'iptables -t mangle -X qos_policy_id_' + str(policy_id)
                    process = runProcess(deleteChainOfPolicy)

    if interface in tuns:
        interface = tuns[interface]
        clearRoot = TC + " qdisc del dev " + interface + " root"
        runProcess(clearRoot)
        clearIngress = TC + " qdisc del dev " + interface + " ingress"
        runProcess(clearIngress)
        clearIfb = TC + " qdisc del dev " + ifb + " root"
        runProcess(clearIfb)
        logger.info('all configurations removed on \'' + str(interface) + '\' and \'' + str(ifb) + '\'')
        deleteDefaultPolicy9999 = 'iptables -t mangle -D POSTROUTING -o ' + str(
            interface) + ' -m mark --mark 0x0 -j qos_policy_id_' + str(DEFAULT_POLICY_ID)
        process = runProcess(deleteDefaultPolicy9999)
        if process.returncode == 0:
            if canIdeleteDefaultChain9999():
                formatChainPolicy9999 = 'iptables -t mangle -F qos_policy_id_' + str(DEFAULT_POLICY_ID)
                process = runProcess(formatChainPolicy9999)
                if process.returncode != 0:
                    fillErrors(process)
                    return RLM_MODULE_FAIL
                deleteChainPolicy9999 = 'iptables -t mangle -X qos_policy_id_' + str(DEFAULT_POLICY_ID)
                process = runProcess(deleteChainPolicy9999)
                if process.returncode != 0:
                    fillErrors(process)
                    return RLM_MODULE_FAIL
        else:
            fillErrors(process)
            logger.error('can\'t delete default policy for ' + deleteDefaultPolicy9999)
            return RLM_MODULE_FAIL
        canIdeleteDpiCheck = True
        process = runProcess(IPTABLES + ' -t mangle -nvL POSTROUTING')
        re_pattern = r'\bqos_policy_id_9999.*?\b'
        for line in iter(process.stdout.readline, b''):
            result = re.findall(re_pattern, line)
            if result:
                canIdeleteDpiCheck = False
                break
        if canIdeleteDpiCheck:
            process = runProcess("iptables -t mangle -D PREROUTING -mndpi --dpi_check")
            if process.returncode != 0:
                fillErrors(process)
                return RLM_MODULE_FAIL
            process = runProcess("iptables -t mangle -D POSTROUTING -mndpi --dpi_check")
            if process.returncode != 0:
                fillErrors(process)
                return RLM_MODULE_FAIL
        if policy_ids:
            for policy_id in policy_ids:
                policyLineNumbersInIptables = getLinesOfPolicy(policy_id, interface)
                policyLineNumbersInIptables.sort()
                policyLineNumbersInIptables.reverse()
                # print(policyLineNumbersInIptables)
                if policyLineNumbersInIptables:
                    for line_num in policyLineNumbersInIptables:
                        deletePolicyFromIptable = 'iptables -t mangle -D POSTROUTING ' + str(line_num)
                        process = runProcess(deletePolicyFromIptable)
                        if process.returncode == 0:
                            logger.info(
                                'policy ' + str(policy_id) + ' for ' + str(interface) + ' in line ' + str(
                                    line_num) + ' deleted.')
                        else:
                            logger.info(
                                'can\'t delete policy ' + str(policy_id) + ' for ' + str(interface) + ' in line ' + str(
                                    line_num))
                            fillErrors(process)
                            return RLM_MODULE_FAIL
                if isThisChainUsedInAnotherPartOfPolicy(policy_id) == False:
                    formatChainOfPolicy = 'iptables -t mangle -F qos_policy_id_' + str(policy_id)
                    process = runProcess(formatChainOfPolicy)
                    if process.returncode != 0:
                        fillErrors(process)
                        return RLM_MODULE_FAIL
                    deleteChainOfPolicy = 'iptables -t mangle -X qos_policy_id_' + str(policy_id)
                    process = runProcess(deleteChainOfPolicy)
                    if process.returncode != 0:
                        fillErrors(process)
                        return RLM_MODULE_FAIL

    return RLM_MODULE_OK


def isThisChainUsedInAnotherPartOfPolicy(policy_id):
    exist = False
    cmd = 'iptables -nvL POSTROUTING -t mangle --line-number'
    query = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    query_output = query.communicate()[0]
    if query.returncode == 0:
        for line in query_output.split('\n'):
            if 'qos_policy_id_%s' % str(policy_id) in line:
                exist = True
    return exist


def getLinesOfPolicy(policy_id, interface):
    # print(policy_id, interface)
    result = list()
    cmd = 'iptables -nvL POSTROUTING -t mangle --line-number'
    query = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    query_output = query.communicate()[0]
    if query.returncode == 0:
        for line in query_output.split('\n'):
            if 'qos_policy_id_%s' % str(policy_id) in line and str(interface) in line:
                result.append(int(line.split()[0]))
    return result


def checkIfAnIPSetExistAndNotEmpty(ipsetName):
    process = runProcess("ipset -L " + ipsetName)
    if process and not process.returncode:
        ipsetResult = process.communicate()[0]
        if ipsetResult:
            result = re.search("Members:\n\d+", ipsetResult, re.M)
            if not result:  # The set is empty
                return False
            else:
                return True  # The set is not empty!

        return False
    else:
        return False


def createIfbInterface():  # TODO in kar faghat bayad dafe aval anjam beshe
    removeExsitingIfbModule = "modprobe -r ifb"
    process = runProcess(removeExsitingIfbModule)
    if process.returncode == 0:
        logger.info('ifb remove ok!')
    else:
        logger.info('ifb init did\'nt remove!')
    upIfbInterfaces = "modprobe ifb numifbs=" + str(MAX_NUM_IFBS)
    process = runProcess(upIfbInterfaces)
    if process.returncode == 0:
        logger.info('ifb init ok!')
    else:
        logger.info('ifb init did\'nt ok!')


def checkedRemainBW(remain):
    '''
    this function check the reamin bandwith which parser sent. this number should be less than 4294967295.
    becouse TC stores sizes internally as 32-bit unsigned integer.
    note that remain unit which is send from parser is kilo bit per second
    '''
    if remain > 4294967295:
        remain = remain / 1000;
        unit = "mbit"
    else:
        unit = "kbit"
    return (str(remain) + unit)


def generalShapingConfiguration(conf):
    '''
    Note: root classes are not allowed to borrow, so there's really
     no point in specifying a ceil for them.

      we decide to set the rate(gbw) of root class to UI's max bandwidth. so we have guaranteed and max
      bandwidth in UI but in tc the rate and ceil of root class is even and equals to max bandwidth in UI.
      note that percent(%) of bandwidth for shapers are  calculated based on UI's guaranteed bandwidth.
    '''

    try:
        interface = conf[INTERFACE]
        if interface in conf['tuns']:
            interface = conf['tuns'][interface]
        # gbws and mbws are even and equal to max bandwidth in UI, if the user enter the max bandwidth, otherwise there are equal to guaranteed bandwidth!
        if (conf[DL_MAX_BW]):
            dl_gbw = conf[DL_MAX_BW]
        else:
            dl_gbw = conf[DL_GUARANTEED_BW]
        dl_mbw = conf[DL_MAX_BW]
        if (conf[UL_MAX_BW]):
            ul_gbw = conf[UL_MAX_BW]
        else:
            ul_gbw = conf[UL_GUARANTEED_BW]
        ul_mbw = conf[UL_MAX_BW]
        ifb = conf[IFB_INTERFACE]
        action = conf[CONFIG_ACTION]
    except Exception as e:
        logger.error('Can\'t parse config for %s' % str(e))
        return RLM_MODULE_FAIL

    if action == "add":
        # in rare conditions maybe multiple add in config recieved and for this problem we check if add happened before we dont add again
        checkClassExistance = TC + ' class show dev ' + str(interface)
        process = runProcess(checkClassExistance)
        exFlag = False
        result = None
        for line in iter(process.stdout.readline, b''):
            result = re.search("htb", line, re.M)
            break
        if result == None:
            exFlag = False
        else:
            exFlag = True
        if exFlag == True:
            clearConfig(interface, ifb)
            logger.info('interface config cleared for restarting service!')

        createRootQdisc = TC + ' qdisc ' + str(action) + ' dev ' + str(
            interface) + ' root handle 1:0 htb default ' + str(
            DEFAULT_POLICY_ID)
        process = runProcess(createRootQdisc)
        if process.returncode == 0:
            logger.info('root qdisc created on \'' + str(interface) + '\'')
        else:
            logger.error("Can't apply this config: " + createRootQdisc)
            fillErrors(process)
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL
        defalutClassBW = ul_gbw
        if ul_mbw:  # if we have max bandwidth we config qos based on it! else we config based on guaranteed bandwidth of interface!
            defalutClassBW = ul_mbw
            createRootClassAndConfigItWithMax = TC + ' class add dev ' + str(
                interface) + ' parent 1:0 classid 1:' + str(
                ROOT_CLASS_ID) + ' htb rate ' + str(ul_mbw) + ' ceil ' + str(ul_mbw)
            process = runProcess(createRootClassAndConfigItWithMax)
            if process.returncode == 0:
                logger.info('root class created and configured on \'' + str(interface) + '\'')
            else:
                logger.error("Can't apply this config: " + createRootClassAndConfigItWithMax)
                fillErrors(process)
                clearConfig(interface, ifb)
                return RLM_MODULE_FAIL
        else:
            createRootClassAndConfigItWithoutMax = TC + ' class add dev ' + str(
                interface) + ' parent 1:0 classid 1:' + str(
                ROOT_CLASS_ID) + ' htb rate ' + str(ul_gbw)
            process = runProcess(createRootClassAndConfigItWithoutMax)
            if process.returncode == 0:
                logger.info('root class created and configured on \'' + str(interface) + '\'')
            else:
                logger.error("Can't apply this config: " + createRootClassAndConfigItWithoutMax)
                fillErrors(process)
                clearConfig(interface, ifb)
                return RLM_MODULE_FAIL

        createIfbInterface = 'ip link set dev ' + str(ifb) + ' up'
        process = runProcess(createIfbInterface)
        if process.returncode == 0:
            logger.info('interface \'' + str(ifb) + '\' created for download traffic shaping')
        else:
            logger.error("Can't apply this config: " + createIfbInterface)
            fillErrors(process)
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL

        upIfbInterface = "ifconfig " + str(ifb) + " up"
        process = runProcess(upIfbInterface)
        if process.returncode == 0:
            logger.info('interface \'' + str(ifb) + '\' is up now')
        else:
            logger.error("check ifb module, Can't up interface ifb : " + upIfbInterface)
            fillErrors(process)
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL

        createIfbRootQdisc = TC + " qdisc add dev " + str(ifb) + ' root handle 1:0 htb default ' + str(
            DEFAULT_POLICY_ID)
        process = runProcess(createIfbRootQdisc)
        if process.returncode == 0:
            logger.info('root qdisc created on \'' + str(ifb) + '\'')
        else:
            logger.error("Can't apply this config: " + createIfbRootQdisc)
            fillErrors(process)
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL

        createIngressQdiscForInt = TC + ' qdisc add dev ' + str(interface) + ' handle ffff: ingress'
        process = runProcess(createIngressQdiscForInt)
        if process.returncode == 0:
            logger.info('ingress qdisc created on \'' + str(interface) + '\'')
        else:
            logger.error("Can't apply this config: " + createIngressQdiscForInt)
            fillErrors(process)
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL

        redirectIngressToIfbEgress = TC + ' filter add dev ' + \
                                     str(
                                         interface) + ' parent ffff: protocol ip u32 match u32 0 0 action connmark action mirred egress redirect dev ' + str(
            ifb)
        process = runProcess(redirectIngressToIfbEgress)
        if process.returncode == 0:
            logger.info(
                'filter for \'' + str(interface) + '\' ingress created on \'' + str(ifb) + '\'')
        else:
            logger.error("Can't apply this config: " + redirectIngressToIfbEgress)
            fillErrors(process)
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL
        defalutClassIfbBW = dl_gbw
        if dl_mbw:
            defalutClassIfbBW = dl_mbw
            createIfbRootClassAndConfigItWithMax = TC + ' class add dev ' + str(
                ifb) + ' parent 1:0 classid 1:' + str(ROOT_CLASS_ID) + ' htb rate ' + str(
                dl_mbw) + ' ceil ' + str(dl_mbw)
            process = runProcess(createIfbRootClassAndConfigItWithMax)
            if process.returncode == 0:
                logger.info('root class created and configured on \'' + str(ifb) + '\'')
            else:
                logger.error("Can't apply this config: " + createIfbRootClassAndConfigItWithMax)
                fillErrors(process)
                clearConfig(interface, ifb)
                return RLM_MODULE_FAIL
        else:
            createIfbRootClassAndConfigItWithoutMax = TC + ' class add dev ' + str(
                ifb) + ' parent 1:0 classid 1:' + str(ROOT_CLASS_ID) + ' htb rate ' + str(
                dl_gbw)
            process = runProcess(createIfbRootClassAndConfigItWithoutMax)
            if process.returncode == 0:
                logger.info('root class created and configured on \'' + str(ifb) + '\'')
            else:
                logger.error("Can't apply this config: " + createIfbRootClassAndConfigItWithoutMax)
                fillErrors(process)
                clearConfig(interface, ifb)
                return RLM_MODULE_FAIL

        DefaultPolicy = {'src': {'src_network': None}, 'enable': True, 'users': None, 'shaper_existed': [],
                         'policy_order': DEFAULT_POLICY_ID,
                         'reverse_shaper': {'apply_type': 'shared', 'priority': 7, 'parent_id': ROOT_CLASS_ID,
                                            'shaper_gbw': dl_gbw, 'shaper_id': DEFAULT_POLICY_ID, 'shaper_mbw': None},
                         'dst': {'dst_network': None}, 'schedule': None, 'ifb_int': ifb,
                         'shaper': {'apply_type': 'shared', 'priority': 7, 'parent_id': ROOT_CLASS_ID,
                                    'shaper_gbw': ul_gbw, 'shaper_id': DEFAULT_POLICY_ID, 'shaper_mbw': None},
                         'groups': [], 'services': {'l7': [], 'l4': []}, 'rvs_shaper_existed': [],
                         'interfaces': interface,
                         'policy_id': DEFAULT_POLICY_ID}
        if addShapingPolicy(DefaultPolicy) == RLM_MODULE_OK:
            logger.info("default policy added for unShaped traffics.")
        else:
            logger.error("Can't add default policy for unShaped traffics.")
            clearConfig(interface, ifb)
            return RLM_MODULE_FAIL
        if os.path.exists("/sys/module/sch_htb/parameters/htb_rate_est"):
            runProcess("echo 1 > /sys/module/sch_htb/parameters/htb_rate_est")
        else:
            logger.info("/sys/module/sch_htb/parameters/htb_rate_est  not exist!")

        shouldIaddDpiCheck = True
        re_pattern = r'\bprotocol.*?\b'
        process = runProcess(IPTABLES + ' -t mangle -nvL PREROUTING')
        for line in iter(process.stdout.readline, b''):
            # result = re.search("", line, re.M)
            result = re.findall(re_pattern, line)
            if result:
                shouldIaddDpiCheck = False
                break
        if shouldIaddDpiCheck:
            process = runProcess("iptables -t mangle -A PREROUTING -mndpi --dpi_check")
            if process.returncode != 0:
                fillErrors(process)
            process = runProcess("iptables -t mangle -A POSTROUTING -mndpi --dpi_check")
            if process.returncode != 0:
                fillErrors(process)



    elif action == "del":
        clearConfig(interface, ifb)

    elif action == "update":
        # upload
        if ul_mbw:
            updateUploadRootClassWithMax = TC + ' class change dev ' + str(interface) + ' parent 1:0 classid 1:' + str(
                ROOT_CLASS_ID) + ' htb rate ' + str(ul_gbw) + ' ceil ' + str(ul_mbw)
            process = runProcess(updateUploadRootClassWithMax)
            if process.returncode == 0:
                logger.info('upload bandwidth successfully updated on \'' + str(interface) + '\'')
            else:
                logger.error("Can't apply this update config: " + updateUploadRootClassWithMax)
                fillErrors(process)
                return RLM_MODULE_FAIL
        else:
            updateUploadRootClassWithoutMax = TC + ' class change dev ' + str(
                interface) + ' parent 1:0 classid 1:' + str(
                ROOT_CLASS_ID) + ' htb rate ' + str(ul_gbw)
            process = runProcess(updateUploadRootClassWithoutMax)
            if process.returncode == 0:
                logger.info('upload bandwidth successfully updated on \'' + str(interface) + '\'')
            else:
                logger.error("Can't apply this update config: " + updateUploadRootClassWithoutMax)
                fillErrors(process)
                return RLM_MODULE_FAIL
        # download
        if dl_mbw:
            updateDownloadRootClassWithMax = TC + ' class change dev ' + str(
                ifb) + ' parent 1:0 classid 1:' + str(ROOT_CLASS_ID) + ' htb rate ' + str(dl_gbw) + ' ceil ' + str(
                dl_mbw)
            process = runProcess(updateDownloadRootClassWithMax)
            if process.returncode == 0:
                logger.info('download bandwidth successfully updated on \'' + str(ifb) + '\'')
            else:
                logger.error("Can't apply this update config: " + updateDownloadRootClassWithMax)
                fillErrors(process)
                return RLM_MODULE_FAIL
        else:
            updateDownloadRootClassWithoutMax = TC + ' class change dev ' + str(
                ifb) + ' parent 1:0 classid 1:' + str(ROOT_CLASS_ID) + ' htb rate ' + str(dl_gbw)
            process = runProcess(updateDownloadRootClassWithoutMax)
            if process.returncode == 0:
                logger.info('download bandwidth successfully updated on \'' + str(ifb) + '\'')
            else:
                logger.error("Can't apply this update config: " + updateDownloadRootClassWithoutMax)
                fillErrors(process)
                return RLM_MODULE_FAIL

        newDefaultShaper = {'apply_type': 'shared', 'priority': 7, 'parent_id': ROOT_CLASS_ID,
                            'shaper_gbw': ul_gbw, 'shaper_id': DEFAULT_POLICY_ID, 'shaper_mbw': None}
        newDefaultReverseShaper = {'apply_type': 'shared', 'priority': 7, 'parent_id': ROOT_CLASS_ID,
                                   'shaper_gbw': dl_gbw, 'shaper_id': DEFAULT_POLICY_ID, 'shaper_mbw': None}
        if updateShaper(newDefaultShaper, interface) == RLM_MODULE_OK:
            logger.info("default upload shaper updated for unShaped traffics.")
        else:
            logger.error("Can't update default upload shaper for unShaped traffics.")
            return RLM_MODULE_FAIL
        if updateShaper(newDefaultReverseShaper, ifb) == RLM_MODULE_OK:
            logger.info("default download shaper updated for unShaped traffics.")
        else:
            logger.error("Can't update default download shaper for unShaped traffics.")
            return RLM_MODULE_FAIL

    else:
        logger.error("can\'t apply this action in general configuration : \'" + str(action) + "\'")
        return RLM_MODULE_FAIL

    return RLM_MODULE_OK


def addTempPolicy(newPolicy):
    '''
    As soon as adding a policy we add a temperorary policy for deleting exciting marks for exciting flows which should mark in new policy!
    (for applying shaping policies online)

    '''
    try:
        policy_id = newPolicy[POLICY_ID]

    except Exception as e:
        logger.error("Can't parse newPolicy for ", str(e))
        return RLM_MODULE_FAIL
    isAnyRulesApplyedSuccessfuly = True
    isThereAtLeastOneSuccessfulRule = False
    shouldIIgnoreTheChainCommands = False

    dst = newPolicy[POLICY_DST]
    src = newPolicy[POLICY_SRC]
    policyChainName = "qos_temp_id_" + str(policy_id)

    policyChainCommandsHeader = IPTABLES + " -t mangle -A qos_temp_id_" + str(policy_id)
    mainCommandsHeader = IPTABLES + " -t mangle -I POSTROUTING "
    srcProtocolList = []
    dstProtocolList = []
    srcNetworkSetList = []
    dstNetworkList = []
    srcInterfacesList = []
    dstInterfacesList = []

    if POLICY_SERVICES in list(newPolicy.keys()) and newPolicy[POLICY_SERVICES]:
        concatenableSrcPorts = {}
        concatenableDstPorts = {}
        if 'l4' in list(newPolicy[POLICY_SERVICES].keys()) and newPolicy[POLICY_SERVICES]['l4']:
            concatenableSrcPorts["tcp"] = ""
            concatenableSrcPorts["udp"] = ""
            concatenableDstPorts["tcp"] = ""
            concatenableDstPorts["udp"] = ""
            for l4protocol in newPolicy[POLICY_SERVICES]['l4']:
                if l4protocol['protocol']:
                    if l4protocol['protocol'].lower() == "tcp" or l4protocol['protocol'].lower() == "udp":
                        if (l4protocol['src_port']):
                            for port in l4protocol['src_port']:
                                if port.find(":") != -1:
                                    srcProtocolList.append("-p " + l4protocol['protocol'] + " --sport " + port)
                                else:
                                    concatenableSrcPorts[l4protocol['protocol'].lower()] += port + ","
                        if (l4protocol['dst_port']):
                            for port in l4protocol['dst_port']:
                                if port.find(":") != -1:
                                    dstProtocolList.append("-p " + l4protocol['protocol'] + " --dport " + port)
                                else:
                                    concatenableDstPorts[l4protocol['protocol'].lower()] += port + ","
                        if not l4protocol['dst_port'] and not l4protocol['src_port']:
                            logger.error("Can't set protocol without ports number!")
                            return RLM_MODULE_FAIL

            for proto in concatenableSrcPorts:
                if concatenableSrcPorts[proto]:
                    srcProtocolList.append("-p " + proto + " -mmultiport --sport " + concatenableSrcPorts[proto][:-1])
            for proto in concatenableDstPorts:
                if concatenableDstPorts[proto]:
                    dstProtocolList.append("-p " + proto + " -mmultiport --dport " + concatenableDstPorts[proto][:-1])

        if 'l7' in list(newPolicy[POLICY_SERVICES].keys()) and newPolicy[POLICY_SERVICES]['l7']:
            for proto in newPolicy[POLICY_SERVICES]['l7']:
                if proto.lower() == "icmp" or \
                                proto.lower() == "tcp" or \
                                proto.lower() == "tcp":
                    dstProtocolList.append("-p " + proto)
                else:
                    dstProtocolList.append("-mndpi --" + proto)

    if 'dst_network' in list(dst.keys()) and dst['dst_network']:
        concatenableIPs = ""
        for net in dst['dst_network']:
            if 'address_type' in list(net.keys()) and net['address_type']:
                if 'address_value' in list(net.keys()) and net['address_value']:
                    for addr in net['address_value']:
                        if net['address_type'] == 'v4' or net['address_type'] == 'v6':
                            if addr.find("-") == -1:
                                concatenableIPs += addr + ","
                            else:
                                dstNetworkList.append("-m iprange --dst-range " + addr)
                        elif net['address_type'] == 'mac':
                            logger.warning("The MAC for destination is illegal")
                            fillWarnings("The MAC for destination is illegal")
                        elif net['address_type'] == 'FQDN':  # TODO add this to web proxy policies
                            dstNetworkList.append("-d " + addr)
        if concatenableIPs:
            dstNetworkList.append("-d " + concatenableIPs[:-1])

    # if WAN_INT in newPolicy.keys() and newPolicy[WAN_INT]:
    #    dstInterfacesList.append("-o " + newPolicy[WAN_INT])
    if WAN_INT in list(newPolicy.keys()) and newPolicy[WAN_INT]:
        interface = newPolicy[WAN_INT]
        if policy_id != DEFAULT_POLICY_ID:
            if interface in newPolicy['tuns']:
                interface = newPolicy['tuns'][interface]
        dstInterfacesList.append("-o " + interface)

    if 'src_network' in list(src.keys()) and src['src_network']:
        concatenableIPs = ""
        for net in src['src_network']:
            if 'address_type' in list(net.keys()) and net['address_type']:
                if 'address_value' in list(net.keys()) and net['address_value']:
                    for addr in net['address_value']:
                        if net['address_type'] == 'v4' or net['address_type'] == 'v6':
                            if addr.find("-") == -1:
                                concatenableIPs += addr + ","
                            else:
                                srcNetworkSetList.append("-m iprange --src-range " + addr)
                        elif net['address_type'] == 'mac':
                            srcNetworkSetList.append("-m mac --mac-source " + addr)
                        elif net['address_type'] == 'FQDN':  # TODO add this to web proxy policies
                            srcNetworkSetList.append("-s " + addr)
        if concatenableIPs:
            srcNetworkSetList.append("-s " + concatenableIPs[:-1])

    # TODO
    # if 'src_interfaces' in list(src.keys()) and src['src_interfaces']:
    #     #concatenableInt = ""
    #     for intf in src['src_interfaces']:
    #         if intf in list(interfaceMap.keys()) and interfaceMap[intf]:
    #             intf = interfaceMap[intf]
    #         srcInterfacesList.append("-i " + intf)

    shouldIIgnoreThePolicy = True

    if POLICY_USERS in list(newPolicy.keys()) and newPolicy[POLICY_USERS]:
        users = newPolicy[POLICY_USERS]
        doYouFindAnySet = False
        for user in users:
            if checkIfAnIPSetExistAndNotEmpty("_" + user + "_USER_"):
                userSet = "_" + user + "_USER_"
                doYouFindAnySet = True
                srcNetworkSetList.append("-m set --match-set " + userSet + " src")

        if doYouFindAnySet:
            shouldIIgnoreThePolicy = False

    if POLICY_GROUPS in list(newPolicy.keys()) and newPolicy[POLICY_GROUPS]:
        groups = newPolicy[POLICY_GROUPS]
        doYouFindAnySet = False
        for group in groups:
            if checkIfAnIPSetExistAndNotEmpty("_" + group + "_GROUP_"):
                groupSet = "_" + group + "_GROUP_"
                doYouFindAnySet = True
                srcNetworkSetList.append("-m set --match-set " + groupSet + " src ")

        if doYouFindAnySet:
            shouldIIgnoreThePolicy = False

    if shouldIIgnoreThePolicy and not srcNetworkSetList \
            and (newPolicy[POLICY_USERS] or newPolicy[POLICY_GROUPS]):
        logger.warning("QOSMW is going to ignore this rule!")
        return RLM_MODULE_NOTFOUND

    schedule = ""
    weekday = ""

    if POLICY_SCHEDULE in list(newPolicy.keys()) and newPolicy[POLICY_SCHEDULE]:
        schedule = "-mtime"
        for key in newPolicy[POLICY_SCHEDULE]:
            dayResult = re.search("([a-z]+)_enable", key)
            if key == 'schedule_date_start':
                result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key])
                if result:
                    utcTime = convertTimeToUTC(result.group(1) + " " + result.group(2))
                    result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --datestart " + result.group(1) + "T" + result.group(2)
                else:
                    logger.error("Can't understand schedule_date_start format")
            elif key == 'schedule_date_stop':
                result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key])
                if result:
                    utcTime = convertTimeToUTC(result.group(1) + " " + result.group(2))
                    result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --datestop " + result.group(1) + "T" + result.group(2)
                else:
                    logger.error("Can't understand schedule_date_stop format")
            elif key == "schedule_time_start":
                result = re.search("^(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key], re.M)
                if result:
                    utcTime = convertTimeToUTC("2017-02-02 " + result.group(1))
                    result = re.search("\d+-\d+-\d+\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --timestart " + result.group(1)
                else:
                    logger.error("Can't understand schedule_time_start format")
            elif key == "schedule_time_stop":
                result = re.search("^(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key], re.M)
                if result:
                    utcTime = convertTimeToUTC("2017-02-02 " + result.group(1))
                    result = re.search("\d+-\d+-\d+\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --timestop " + result.group(1)
                else:
                    logger.error("Can't understand schedule_time_stop format")
            elif dayResult:
                if newPolicy[POLICY_SCHEDULE][key] == "True":
                    weekday += dayResult.group(1).capitalize() + ","
            else:
                logger.error("Can't understand %s" % (key,))
        if weekday:
            schedule += " --weekdays " + weekday[:-1]

    errors = ""
    warnings = ""

    if not shouldIIgnoreTheChainCommands:
        runProcess("iptables -t mangle -N " + policyChainName)
        policyChainCommands = []
        tcpProtocol = ""
        udpProtocol = ""

        for proto in srcProtocolList:
            if proto.find("-p tcp") != -1:
                tcpProtocol += " " + proto[len("-p tcp"):]
            elif proto.find("-p udp") != -1:
                udpProtocol += " " + proto[len("-p udp"):]
            else:
                policyChainCommands.append(policyChainCommandsHeader + " " + proto)

        for proto in dstProtocolList:
            if proto.find("-p tcp") != -1:
                tcpProtocol += " " + proto[len("-p tcp"):]
            elif proto.find("-p udp") != -1:
                udpProtocol += " " + proto[len("-p udp"):]
            else:
                policyChainCommands.append(policyChainCommandsHeader + " " + proto)
        if tcpProtocol:
            policyChainCommands.append(policyChainCommandsHeader + " -p tcp " + tcpProtocol)
        if udpProtocol:
            policyChainCommands.append(policyChainCommandsHeader + " -p udp " + udpProtocol)

        logger.info("policyChainCommands is:" + str(len(policyChainCommands)))
        if not len(policyChainCommands):  # Add action for empty chains
            policyChainCommands.append(policyChainCommandsHeader)

        for pol in policyChainCommands:
            process = runProcess(pol + ' -m mark ! --mark ' + str(policy_id) + " -j CONNMARK --set-mark 0")
            if process.returncode:
                isAnyRulesApplyedSuccessfuly = False
                logger.error("Can't apply this rule: " + pol + ' -m mark ! --mark ' + str(
                    policy_id) + " -j CONNMARK --set-mark 0")
                errors = fillErrors(process)

    if not srcNetworkSetList:
        srcNetworkSetList.append("")
    if not dstNetworkList:
        dstNetworkList.append("")
    if not srcInterfacesList:
        srcInterfacesList.append("")
    if not dstInterfacesList:
        dstInterfacesList.append("")

    policyMainTableCommand = []
    for srcList in srcNetworkSetList:
        for srcInt in srcInterfacesList:
            for dstInt in dstInterfacesList:
                for dstIP in dstNetworkList:
                    policyMainTableCommand.append(mainCommandsHeader + " " + \
                                                  srcInt + " " + srcList + " " + dstInt + " " + dstIP + " " + \
                                                  schedule + " -j qos_temp_id_" + str(policy_id))

    for pol in policyMainTableCommand:
        errors = ""
        warnings = ""
        process = runProcess(pol)
        if process.returncode:
            isAnyRulesApplyedSuccessfuly = False
            logger.error("Can't apply this rule: " + pol)
            errors = fillErrors(process)
        else:
            isThereAtLeastOneSuccessfulRule = True

    if isAnyRulesApplyedSuccessfuly:
        return RLM_MODULE_OK
    elif isThereAtLeastOneSuccessfulRule:
        return RLM_MODULE_INVALID
    else:
        return RLM_MODULE_FAIL


def delTempPolicy(tempPolicy, oldNamePrefix=""):
    '''
     this function delete the temprorary policy
    '''
    # try:
    #     policy_id = newPolicy[POLICY_ID]
    # except Exception as e:
    #     logger.error("Can\'t parse newPolicy for ", str(e))
    #     return RLM_MODULE_FAIL
    # process = runProcess(IPTABLES + ' -t mangle -D POSTROUTING 1')
    # if process.returncode == 0 :
    #     runProcess(IPTABLES + ' -t mangle -F qos_temp_id_' + str(policy_id))
    #     runProcess(IPTABLES + ' -t mangle -X qos_temp_id_' + str(policy_id))
    # else:
    #     fillErrors(process)
    #     logger.error('can\'t delete temp policy in POSTROUTING')
    #     return RLM_MODULE_FAIL

    removeChainCommand = []
    removeRulesCommand = []
    isAnyRulesApplyedSuccessfuly = True
    isThereAtLeastOneSuccessfulRule = False
    if POLICY_ID in list(tempPolicy.keys()) and tempPolicy[POLICY_ID]:
        removeChainCommand.append(IPTABLES + " -t mangle -F qos_temp_id_" + str(tempPolicy[POLICY_ID]) + oldNamePrefix)
        removeChainCommand.append(IPTABLES + " -t mangle -X qos_temp_id_" + str(tempPolicy[POLICY_ID]) + oldNamePrefix)

        mainPolicyes, chainPolicyes = findTheRelatedRulesInfo(str(tempPolicy[POLICY_ID]) + oldNamePrefix, True)
        if mainPolicyes:
            mainPolicyes.reverse()
            for info in mainPolicyes:
                removeRulesCommand.append(IPTABLES + " -t mangle -D POSTROUTING " + info['line-number'])

    if removeRulesCommand:
        for cmd in removeRulesCommand:
            process = runProcess(cmd)
            if process.returncode:
                fillErrors(process)
                isAnyRulesApplyedSuccessfuly = False
            else:
                isThereAtLeastOneSuccessfulRule = True

    if (removeChainCommand):
        for cmd in removeChainCommand:
            process = runProcess(cmd)
            if process.returncode:
                fillErrors(process)
                isAnyRulesApplyedSuccessfuly = False
            else:
                isThereAtLeastOneSuccessfulRule = True

    if isAnyRulesApplyedSuccessfuly:
        return RLM_MODULE_OK
    elif isThereAtLeastOneSuccessfulRule:
        return RLM_MODULE_INVALID
    else:
        return RLM_MODULE_FAIL


def addMarksForShapingPolicy(newPolicy):
    try:
        policy_id = newPolicy[POLICY_ID]
        logger.info("qos_policy_id is: %d" % (policy_id,))
        order = int(newPolicy[POLICY_ORDER])
    except Exception as e:
        logger.error("Can't parse newPolicy for ", str(e))
        return RLM_MODULE_FAIL

    isAnyRulesApplyedSuccessfuly = True
    isThereAtLeastOneSuccessfulRule = False
    nextPolicy = whereShouldIInsertMyPolicy(order, policy_id)

    if nextPolicy == None:
        logger.error("Can't calculate policy order")
        return RLM_MODULE_FAIL
    elif not len(nextPolicy):
        logger.warning("The nextPolicy in addPolicy is empty!")

    shouldIIgnoreTheChainCommands = False
    if str(policy_id) in list(nextPolicy.keys()):
        logger.warning("The id existed")
        interface = newPolicy[WAN_INT]
        if policy_id != DEFAULT_POLICY_ID:
            if interface in newPolicy['tuns']:
                interface = newPolicy['tuns'][interface]
        if nextPolicy["outint"] == interface:
            logger.error("Can't add two policy with same id!")
            return RLM_MODULE_FAIL
        else:
            # logger.error("shouldIIgnoreTheChainCommands")
            shouldIIgnoreTheChainCommands = True

    if (nextPolicy):
        try:
            (policy, calculatedOrder) = nextPolicy.popitem()
            if policy == "outint":
                (policy, calculatedOrder) = nextPolicy.popitem()
            # if policy == str(policy_id) and not shouldIIgnoreTheChainCommands:
            #     return RLM_MODULE_FAIL
            order = int(calculatedOrder)
        except KeyError:
            order = 1
    else:
        order = 1

    logger.info("Order is : %d" % (order,))

    # * src o dst ra dar miare. va yek chain ba name id aan policy misazad.
    dst = newPolicy[POLICY_DST]
    src = newPolicy[POLICY_SRC]
    policyChainName = "qos_policy_id_" + str(policy_id)
    if not policy_id:
        logger.error("Can't find policy id")
        return RLM_MODULE_FAIL
    if not order:
        logger.error("Can't find policy order")
        return RLM_MODULE_FAIL
    interfaceMap = {}
    if 'tuns' in list(newPolicy.keys()) and newPolicy['tuns']:
        interfaceMap = newPolicy['tuns']
    ifItHasNotMark = " -m mark --mark 0x0 "
    policyChainCommandsHeader = IPTABLES + " -t mangle -A qos_policy_id_" + str(policy_id)
    mainCommandsHeader = IPTABLES + " -t mangle -I POSTROUTING " + str(order) + ifItHasNotMark
    srcProtocolList = []
    dstProtocolList = []
    srcNetworkSetList = []
    dstNetworkList = []
    srcInterfacesList = []
    dstInterfacesList = []

    if POLICY_SERVICES in list(newPolicy.keys()) and newPolicy[POLICY_SERVICES]:
        concatenableSrcPorts = {}
        concatenableDstPorts = {}
        if 'l4' in list(newPolicy[POLICY_SERVICES].keys()) and newPolicy[POLICY_SERVICES]['l4']:
            concatenableSrcPorts["tcp"] = ""
            concatenableSrcPorts["udp"] = ""
            concatenableDstPorts["tcp"] = ""
            concatenableDstPorts["udp"] = ""
            for l4protocol in newPolicy[POLICY_SERVICES]['l4']:
                if l4protocol['protocol']:
                    if l4protocol['protocol'].lower() == "tcp" or l4protocol['protocol'].lower() == "udp":
                        if (l4protocol['src_port']):
                            for port in l4protocol['src_port']:
                                if port.find(":") != -1:
                                    srcProtocolList.append("-p " + l4protocol['protocol'] + " --sport " + port)
                                else:
                                    concatenableSrcPorts[l4protocol['protocol'].lower()] += port + ","
                        if (l4protocol['dst_port']):
                            for port in l4protocol['dst_port']:
                                if port.find(":") != -1:
                                    dstProtocolList.append("-p " + l4protocol['protocol'] + " --dport " + port)
                                else:
                                    concatenableDstPorts[l4protocol['protocol'].lower()] += port + ","
                        if not l4protocol['dst_port'] and not l4protocol['src_port']:
                            logger.error("Can't set protocol without ports number!")
                            return RLM_MODULE_FAIL

            for proto in concatenableSrcPorts:
                if concatenableSrcPorts[proto]:
                    srcProtocolList.append("-p " + proto + " -mmultiport --sport " + concatenableSrcPorts[proto][:-1])
            for proto in concatenableDstPorts:
                if concatenableDstPorts[proto]:
                    dstProtocolList.append("-p " + proto + " -mmultiport --dport " + concatenableDstPorts[proto][:-1])

        if 'l7' in list(newPolicy[POLICY_SERVICES].keys()) and newPolicy[POLICY_SERVICES]['l7']:
            for proto in newPolicy[POLICY_SERVICES]['l7']:
                if proto.lower() == "icmp" or \
                                proto.lower() == "tcp" or \
                                proto.lower() == "tcp":
                    dstProtocolList.append("-p " + proto)
                else:
                    dstProtocolList.append("-mndpi --" + proto)

    if 'dst_network' in list(dst.keys()) and dst['dst_network']:
        concatenableIPs = ""
        for net in dst['dst_network']:
            if 'address_type' in list(net.keys()) and net['address_type']:
                if 'address_value' in list(net.keys()) and net['address_value']:
                    for addr in net['address_value']:
                        if net['address_type'] == 'v4' or net['address_type'] == 'v6':
                            if addr.find("-") == -1:
                                concatenableIPs += addr + ","
                            else:
                                dstNetworkList.append("-m iprange --dst-range " + addr)
                        elif net['address_type'] == 'mac':
                            logger.warning("The MAC for destination is illegal")
                            fillWarnings("The MAC for destination is illegal")
                        elif net['address_type'] == 'FQDN':  # TODO add this to web proxy policies
                            dstNetworkList.append("-d " + addr)
        if concatenableIPs:
            dstNetworkList.append("-d " + concatenableIPs[:-1])

    if WAN_INT in list(newPolicy.keys()) and newPolicy[WAN_INT]:
        interface = newPolicy[WAN_INT]
        if policy_id != DEFAULT_POLICY_ID:
            if interface in newPolicy['tuns']:
                interface = newPolicy['tuns'][interface]
        dstInterfacesList.append("-o " + interface)

    if 'src_network' in list(src.keys()) and src['src_network']:
        concatenableIPs = ""
        for net in src['src_network']:
            if 'address_type' in list(net.keys()) and net['address_type']:
                if 'address_value' in list(net.keys()) and net['address_value']:
                    for addr in net['address_value']:
                        if net['address_type'] == 'v4' or net['address_type'] == 'v6':
                            if addr.find("-") == -1:
                                concatenableIPs += addr + ","
                            else:
                                srcNetworkSetList.append("-m iprange --src-range " + addr)
                        elif net['address_type'] == 'mac':
                            srcNetworkSetList.append("-m mac --mac-source " + addr)
                        elif net['address_type'] == 'FQDN':  # TODO add this to web proxy policies
                            srcNetworkSetList.append("-s " + addr)
        if concatenableIPs:
            srcNetworkSetList.append("-s " + concatenableIPs[:-1])

    if 'src_interfaces' in list(src.keys()) and src['src_interfaces']:
        # concatenableInt = ""
        for intf in src['src_interfaces']:
            if intf in list(interfaceMap.keys()) and interfaceMap[intf]:
                intf = interfaceMap[intf]
            srcInterfacesList.append("-i " + intf)
            # concatenableInt += intf + ","
            # if concatenableInt:
            # srcInterfacesList.append("-i " + concatenableInt)

    shouldIIgnoreThePolicy = True

    if POLICY_USERS in list(newPolicy.keys()) and newPolicy[POLICY_USERS]:
        users = newPolicy[POLICY_USERS]
        doYouFindAnySet = False
        for user in users:
            if checkIfAnIPSetExistAndNotEmpty("_" + user + "_USER_"):
                userSet = "_" + user + "_USER_"
                doYouFindAnySet = True
                srcNetworkSetList.append("-m set --match-set " + userSet + " src")

        if doYouFindAnySet:
            shouldIIgnoreThePolicy = False

    if POLICY_GROUPS in list(newPolicy.keys()) and newPolicy[POLICY_GROUPS]:
        groups = newPolicy[POLICY_GROUPS]
        doYouFindAnySet = False
        for group in groups:
            if checkIfAnIPSetExistAndNotEmpty("_" + group + "_GROUP_"):
                groupSet = "_" + group + "_GROUP_"
                doYouFindAnySet = True
                srcNetworkSetList.append("-m set --match-set " + groupSet + " src ")

        if doYouFindAnySet:
            shouldIIgnoreThePolicy = False

    if shouldIIgnoreThePolicy and not srcNetworkSetList \
            and (newPolicy[POLICY_USERS] or newPolicy[POLICY_GROUPS]):
        logger.warning("QOSMW is going to ignore this rule!")
        return RLM_MODULE_NOTFOUND

    schedule = ""
    weekday = ""

    if POLICY_SCHEDULE in list(newPolicy.keys()) and newPolicy[POLICY_SCHEDULE]:
        schedule = "-mtime"
        for key in newPolicy[POLICY_SCHEDULE]:
            dayResult = re.search("([a-z]+)_enable", key)
            if key == 'schedule_date_start':
                result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key])
                if result:
                    utcTime = convertTimeToUTC(result.group(1) + " " + result.group(2))
                    result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --datestart " + result.group(1) + "T" + result.group(2)
                else:
                    logger.error("Can't understand schedule_date_start format")
            elif key == 'schedule_date_stop':
                result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key])
                if result:
                    utcTime = convertTimeToUTC(result.group(1) + " " + result.group(2))
                    result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --datestop " + result.group(1) + "T" + result.group(2)
                else:
                    logger.error("Can't understand schedule_date_stop format")
            elif key == "schedule_time_start":
                result = re.search("^(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key], re.M)
                if result:
                    utcTime = convertTimeToUTC("2017-02-02 " + result.group(1))
                    result = re.search("\d+-\d+-\d+\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --timestart " + result.group(1)
                else:
                    logger.error("Can't understand schedule_time_start format")
            elif key == "schedule_time_stop":
                result = re.search("^(\d+:\d+:\d+)", newPolicy[POLICY_SCHEDULE][key], re.M)
                if result:
                    utcTime = convertTimeToUTC("2017-02-02 " + result.group(1))
                    result = re.search("\d+-\d+-\d+\s+(\d+:\d+:\d+)", utcTime)
                    schedule += " --timestop " + result.group(1)
                else:
                    logger.error("Can't understand schedule_time_stop format")
            elif dayResult:
                if newPolicy[POLICY_SCHEDULE][key] == "True":
                    weekday += dayResult.group(1).capitalize() + ","
            else:
                logger.error("Can't understand %s" % (key,))
        if weekday:
            schedule += " --weekdays " + weekday[:-1]

    doLog = False
    if POLICY_LOG in list(newPolicy.keys()) and newPolicy[POLICY_LOG]:
        doLog = True

    rule_id = 1
    doClean = True
    action = " MARK --set-mark "
    errors = ""
    warnings = ""

    if not shouldIIgnoreTheChainCommands:
        runProcess("iptables -t mangle -N " + policyChainName)
        policyChainCommands = []
        tcpProtocol = ""
        udpProtocol = ""

        for proto in srcProtocolList:
            if proto.find("-p tcp") != -1:
                tcpProtocol += " " + proto[len("-p tcp"):]
            elif proto.find("-p udp") != -1:
                udpProtocol += " " + proto[len("-p udp"):]
            else:
                policyChainCommands.append(policyChainCommandsHeader + " " + proto)

        for proto in dstProtocolList:
            if proto.find("-p tcp") != -1:
                tcpProtocol += " " + proto[len("-p tcp"):]
            elif proto.find("-p udp") != -1:
                udpProtocol += " " + proto[len("-p udp"):]
            else:
                policyChainCommands.append(policyChainCommandsHeader + " " + proto)
        if tcpProtocol:
            policyChainCommands.append(policyChainCommandsHeader + " -p tcp " + tcpProtocol)
        if udpProtocol:
            policyChainCommands.append(policyChainCommandsHeader + " -p udp " + udpProtocol)

        logger.info("policyChainCommands is:" + str(len(policyChainCommands)))
        if not len(policyChainCommands):  # Add action for empty chains
            policyChainCommands.append(policyChainCommandsHeader)

        for pol in policyChainCommands:
            if doLog:
                logger.info(pol + " -j " + "LOG --log-prefix=[ngfw_qos_policy_id_" + str(policy_id) + "] ")
                process = runProcess(
                    pol + ifItHasNotMark + " -j " + "LOG --log-prefix=[ngfw_qos_policy_id_" + str(policy_id) + "] ")
                if process.returncode:
                    isAnyRulesApplyedSuccessfuly = False
                    logger.error("Can't apply this rule: " + pol + " -j " + \
                                 "LOG --log-prefix=[ngfw_qos_policy_id_" + str(policy_id) + "] ")
                    fillErrors(process)
                else:
                    isThereAtLeastOneSuccessfulRule = True

            logger.info(pol + ifItHasNotMark + " -j " + action + str(policy_id))
            process = runProcess(pol + ifItHasNotMark + " -j " + action + str(policy_id))
            if process.returncode:
                isAnyRulesApplyedSuccessfuly = False
                logger.error("Can't apply this rule: " + pol + ifItHasNotMark + " -j " + action + str(policy_id))
                errors = fillErrors(process)
            else:
                isThereAtLeastOneSuccessfulRule = True
            updatePolicyFWMsgTable(policy_id, rule_id, pol, errors, warnings, doClean)
            doClean = False
            rule_id = rule_id + 1
        if isThereAtLeastOneSuccessfulRule:
            runProcess(IPTABLES + " -t mangle -I " + policyChainName + "  -j CONNMARK --restore-mark")
            runProcess(
                IPTABLES + " -t mangle -I " + policyChainName + "  -m connbytes --connbytes-dir both --connbytes-mode packets ! --connbytes " + str(
                    numberOfPacketsForNdpiDetection) + " -j RETURN")
            runProcess(
                IPTABLES + " -t mangle -I " + policyChainName + "  -m mark ! --mark " + str(FAKE_MARK) + " -j RETURN")
            runProcess(
                IPTABLES + " -t mangle -I " + policyChainName + ifItHasNotMark + " -j " + action + str(FAKE_MARK))
            runProcess(IPTABLES + " -t mangle -A " + policyChainName + " -m mark ! --mark " + str(
                FAKE_MARK) + " -j CONNMARK --save-mark")
    if not srcNetworkSetList:
        srcNetworkSetList.append("")
    if not dstNetworkList:
        dstNetworkList.append("")
    if not srcInterfacesList:
        srcInterfacesList.append("")
    if not dstInterfacesList:
        dstInterfacesList.append("")

    policyMainTableCommand = []
    for srcList in srcNetworkSetList:
        for srcInt in srcInterfacesList:
            for dstInt in dstInterfacesList:
                for dstIP in dstNetworkList:
                    policyMainTableCommand.append(mainCommandsHeader + " " + \
                                                  srcInt + " " + srcList + " " + dstInt + " " + dstIP + " " + \
                                                  schedule + " -j qos_policy_id_" + str(policy_id))

    logger.info("policyMainTableCommand is:")
    for pol in policyMainTableCommand:
        logger.info(pol)
        errors = ""
        warnings = ""
        process = runProcess(pol)
        # logger.error("I'm going to add connmark for" + pol)
        if process.returncode:
            isAnyRulesApplyedSuccessfuly = False
            logger.error("Can't apply this rule: " + pol)
            errors = fillErrors(process)
        else:
            isThereAtLeastOneSuccessfulRule = True
        updatePolicyFWMsgTable(policy_id, rule_id, pol, errors, warnings, doClean)
        doClean = False
        rule_id = rule_id + 1

    if isAnyRulesApplyedSuccessfuly:
        return RLM_MODULE_OK
    elif isThereAtLeastOneSuccessfulRule:
        return RLM_MODULE_INVALID
    else:
        return RLM_MODULE_FAIL


def addShaper(shaper, interface):
    try:
        shaper_id = shaper[SHAPER_ID]
        parent_id = shaper[PARENT_ID]
        gbw = shaper[SHAPER_GBW]
        mbw = shaper[SHAPER_MBW]
        priority = shaper[PRIORITY]  # TODO : priority ra hesab konam khodam ya az json mostaghim begiram!
    except Exception as e:
        logger.error("Can't parse shaper for : %s " % str(e))
        return RLM_MODULE_FAIL

    if mbw:
        addShaperCmd = TC + ' class add dev ' + str(interface) + ' parent 1:' + str(parent_id) + \
                       ' classid 1:' + str(shaper_id) + ' htb rate ' + str(gbw) + ' ceil ' + str(mbw) + ' prio ' + str(
            priority)
        process = runProcess(addShaperCmd)
        if process.returncode == 0:
            logger.info('shaper ' + str(shaper_id) + ' added on \'' + str(interface) + '\'')
        else:
            logger.error("Can't add this shaper: " + addShaperCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
        createSfqQdisc = TC + ' qdisc add dev ' + str(interface) + ' handle ' + str(shaper_id) + ':0 parent ' + \
                         str(ROOT_CLASS_ID) + ':' + str(shaper_id) + ' sfq perturb 10'
        process = runProcess(createSfqQdisc)
        if process.returncode == 0:
            logger.info(
                'qdisc ' + str(shaper_id) + ':0 added to shaper \'' + str(shaper_id) + '\' on \'' + str(interface))
        else:
            logger.error("Can't add this shaper: " + createSfqQdisc)
            fillErrors(process)
            return RLM_MODULE_FAIL
    else:
        addShaperCmd = TC + ' class add dev ' + str(interface) + ' parent 1:' + str(parent_id) + \
                       ' classid 1:' + str(shaper_id) + ' htb rate ' + str(gbw) + ' prio ' + str(
            priority)
        process = runProcess(addShaperCmd)
        if process.returncode == 0:
            logger.info('shaper ' + str(shaper_id) + ' added on \'' + str(interface) + '\'')
        else:
            logger.error("Can't add this shaper: " + addShaperCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
        createSfqQdisc = TC + ' qdisc add dev ' + str(interface) + ' handle ' + str(shaper_id) + ':0 parent ' + \
                         str(ROOT_CLASS_ID) + ':' + str(shaper_id) + ' sfq perturb 10'
        process = runProcess(createSfqQdisc)
        if process.returncode == 0:
            logger.info(
                'qdisc ' + str(shaper_id) + ':0 added to shaper \'' + str(shaper_id) + '\' on \'' + str(interface))
        else:
            logger.error("Can't add this shaper: " + createSfqQdisc)
            fillErrors(process)
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def updateShaper(shaper, interface):
    try:
        shaper_id = shaper[SHAPER_ID]
        parent_id = shaper[PARENT_ID]
        new_gbw = shaper[SHAPER_GBW]
        new_mbw = shaper[SHAPER_MBW]
        new_priority = shaper[PRIORITY]  # TODO : priority ra hesab konam khodam ya az json mostaghim begiram!
    except Exception as e:
        logger.error("Can't parse shaper for : %s " % str(e))
        return RLM_MODULE_FAIL
    if new_mbw:
        updateShaperCmd = TC + ' class change dev ' + str(interface) + ' parent 1:' + str(parent_id) + \
                          ' classid 1:' + str(shaper_id) + ' htb rate ' + str(new_gbw) + ' ceil ' + str(
            new_mbw) + ' prio ' + str(
            new_priority)
        process = runProcess(updateShaperCmd)
        if process.returncode == 0:
            logger.info('shaper ' + str(shaper_id) + ' on \'' + str(interface) + '\' updated')
        else:
            logger.error("Can't update this shaper: " + updateShaperCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    else:
        updateShaperCmd = TC + ' class change dev ' + str(interface) + ' parent 1:' + str(parent_id) + \
                          ' classid 1:' + str(shaper_id) + ' htb rate ' + str(new_gbw) + ' prio ' + str(
            new_priority)
        process = runProcess(updateShaperCmd)
        if process.returncode == 0:
            logger.info('shaper ' + str(shaper_id) + ' on \'' + str(interface) + '\' updated')
        else:
            logger.error("Can't update this shaper: " + updateShaperCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def deleteShaper(shaper, interface):
    # to delete a shaper class we need first delete all filters attach to this class and then we can delete the class
    # policy_ids: for delete all filters attach to this shaper we need list of policy ids that this shaper is used in them
    try:
        shaper_id = shaper[SHAPER_ID]
        parent_id = shaper[PARENT_ID]
        gbw = shaper[SHAPER_GBW]
        mbw = shaper[SHAPER_MBW]
        priority = shaper[PRIORITY]
    except Exception as e:
        logger.error("Can't parse shaper for : %s " % str(e))
        return RLM_MODULE_FAIL
    if mbw:
        deleteShaperCmd = TC + ' class del dev ' + str(interface) + ' parent 1:' + str(parent_id) + \
                          ' classid 1:' + str(shaper_id) + ' htb rate ' + str(gbw) + ' ceil ' + str(
            mbw) + ' prio ' + str(
            priority)
        process = runProcess(deleteShaperCmd)
        if process.returncode == 0:
            logger.info('shaper ' + str(shaper_id) + ' on \'' + str(interface) + '\' deleted')
        else:
            logger.error("Can't delete this shaper: " + deleteShaperCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    else:
        deleteShaperCmd = TC + ' class del dev ' + str(interface) + ' parent 1:' + str(parent_id) + \
                          ' classid 1:' + str(shaper_id) + ' htb rate ' + str(gbw) + ' prio ' + str(
            priority)
        process = runProcess(deleteShaperCmd)
        if process.returncode == 0:
            logger.info('shaper ' + str(shaper_id) + ' on \'' + str(interface) + '\' deleted')
        else:
            logger.error("Can't delete this shaper: " + deleteShaperCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def addParentShaper(shaper, interface):
    # parent for per policy shapers
    try:
        parent_id = shaper[PARENT_ID]
        gbw = shaper[SHAPER_GBW]
        mbw = shaper[SHAPER_MBW]
        priority = shaper[PRIORITY]  # TODO : priority ra hesab konam khodam ya az json mostaghim begiram!
    except Exception as e:
        logger.error("Can't parse shaper for ", str(e))
        return RLM_MODULE_FAIL
    if mbw:
        addParentCmd = TC + ' class add dev ' + str(interface) + ' parent 1:' + str(
            ROOT_CLASS_ID) + ' classid 1:' + str(parent_id) + ' htb rate ' + str(gbw) + ' ceil ' + str(
            mbw) + ' prio ' + str(priority)
        process = runProcess(addParentCmd)
        if process.returncode == 0:
            logger.info(
                'parent shaper ' + str(parent_id) + ' for per policy shaping added on \'' + str(interface) + '\'')
        else:
            logger.error("Can't add this parent shaper: " + addParentCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    else:
        addParentCmd = TC + ' class add dev ' + str(interface) + ' parent 1:' + str(
            ROOT_CLASS_ID) + ' classid 1:' + str(parent_id) + ' htb rate ' + str(gbw) + ' prio ' + str(priority)
        process = runProcess(addParentCmd)
        if process.returncode == 0:
            logger.info(
                'parent shaper ' + str(parent_id) + ' for per policy shaping added on \'' + str(interface) + '\'')
        else:
            logger.error("Can't add this parent shaper: " + addParentCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def updateParentShaper(shaper, interface, countOfExistance):
    try:
        parent_id = shaper[PARENT_ID]
        gbw = str(int(shaper[SHAPER_GBW][:-3]) * (countOfExistance + 1)) + 'bps'
        if shaper[SHAPER_MBW]:
            mbw = str(int(shaper[SHAPER_MBW][:-3]) * (countOfExistance + 1)) + 'bps'
        else:
            mbw = None
        priority = shaper[PRIORITY]  # TODO : priority ra hesab konam khodam ya az json mostaghim begiram!
    except Exception as e:
        logger.error("Can't parse shaper for %s" % str(e))
        return RLM_MODULE_FAIL
    if mbw:
        addParentCmd = TC + ' class change dev ' + str(interface) + ' parent 1:' + str(
            ROOT_CLASS_ID) + ' classid 1:' + str(
            parent_id) + ' htb rate ' + str(gbw) + ' ceil ' + str(mbw) + ' prio ' + str(priority)
        process = runProcess(addParentCmd)
        if process.returncode == 0:
            logger.info(
                'parent shaper ' + str(parent_id) + ' for per policy shaping updated on \'' + str(interface) + '\'')
        else:
            logger.error("Can't update this parent shaper: " + addParentCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    else:
        addParentCmd = TC + ' class change dev ' + str(interface) + ' parent 1:' + str(
            ROOT_CLASS_ID) + ' classid 1:' + str(
            parent_id) + ' htb rate ' + str(gbw) + ' prio ' + str(priority)
        process = runProcess(addParentCmd)
        if process.returncode == 0:
            logger.info(
                'parent shaper ' + str(parent_id) + ' for per policy shaping updated on \'' + str(interface) + '\'')
        else:
            logger.error("Can't update this parent shaper: " + addParentCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def addShaperToUploadShapingTreeAndApplyingFilter(policy_id, shaper, interface, shaperAlreadyExistOnThisInterfaces):
    # upload shaping : apply shaper for each interface
    try:
        shaper_type = shaper[APPLY_TYPE]
        shaper_id = shaper[SHAPER_ID]
    except Exception as e:
        logger.error("can\'t parse apply shaper type: " + str(e))
        return RLM_MODULE_FAIL
    if shaper_type == "shared":
        if not shaperAlreadyExistOnThisInterfaces:
            if addShaper(shaper, interface) == RLM_MODULE_OK:
                applyingFilter(policy_id, shaper_id, interface)
        else:
            interfaceOfSharedShaperExistInTheExsitedList = False
            for _tuple in shaperAlreadyExistOnThisInterfaces:
                if interface == _tuple[NAME]:
                    interfaceOfSharedShaperExistInTheExsitedList = True
                    applyingFilter(policy_id, shaper_id, interface)
            if not interfaceOfSharedShaperExistInTheExsitedList:
                if addShaper(shaper, interface) == RLM_MODULE_OK:
                    applyingFilter(policy_id, shaper_id, interface)

    elif shaper_type == "per":
        if not shaperAlreadyExistOnThisInterfaces:
            if addParentShaper(shaper, interface) == RLM_MODULE_OK:
                if addShaper(shaper, interface) == RLM_MODULE_OK:
                    applyingFilter(policy_id, shaper_id, interface)
            else:
                return RLM_MODULE_FAIL
        else:
            interfaceOfPerShaperExistInTheExsitedList = False
            for _tuple in shaperAlreadyExistOnThisInterfaces:
                if interface == _tuple[NAME]:
                    interfaceOfPerShaperExistInTheExsitedList = True
                    if updateParentShaper(shaper, interface, _tuple[COUNT]) == RLM_MODULE_OK:
                        if addShaper(shaper, interface) == RLM_MODULE_OK:
                            applyingFilter(policy_id, shaper_id, interface)
                    else:
                        return RLM_MODULE_FAIL
            if not interfaceOfPerShaperExistInTheExsitedList:
                if addParentShaper(shaper, interface) == RLM_MODULE_OK:
                    if addShaper(shaper, interface) == RLM_MODULE_OK:
                        applyingFilter(policy_id, shaper_id, interface)
                else:
                    return RLM_MODULE_FAIL
    else:
        logger.error("apply shaper type \'" + str(shaper_type) + "\' is wrong!")
        return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def addShaperToDownloadShapingTreeAndApplyingFilter(policy_id, reverse_shaper, ifb,
                                                    reverseShaperAlreadyExistOnThisIfbs):
    # download shaping : apply reverse shaper for each interface
    try:
        reverse_shaper_type = reverse_shaper[APPLY_TYPE]
        reverse_shaper_id = reverse_shaper[SHAPER_ID]
    except Exception as e:
        logger.error("can\'t parse apply reverse-shaper type: " + str(e))
        return RLM_MODULE_FAIL

    if reverse_shaper_type == "shared":
        if not reverseShaperAlreadyExistOnThisIfbs:
            if addShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                applyingFilter(policy_id, reverse_shaper_id, ifb)
        else:
            ifbOfSharedShaperExistInTheExsitedList = False
            for _tuple in reverseShaperAlreadyExistOnThisIfbs:
                if ifb == _tuple[NAME]:
                    ifbOfSharedShaperExistInTheExsitedList = True
                    applyingFilter(policy_id, reverse_shaper_id, ifb)
            if not ifbOfSharedShaperExistInTheExsitedList:
                if addShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                    applyingFilter(policy_id, reverse_shaper_id, ifb)

    elif reverse_shaper_type == "per":
        if not reverseShaperAlreadyExistOnThisIfbs:
            if addParentShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                if addShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                    applyingFilter(policy_id, reverse_shaper_id, ifb)
            else:
                return RLM_MODULE_FAIL
        else:
            ifbOfPerShaperExistInTheExsitedList = False
            for _tuple in reverseShaperAlreadyExistOnThisIfbs:
                if ifb == _tuple[NAME]:
                    ifbOfPerShaperExistInTheExsitedList = True
                    if updateParentShaper(reverse_shaper, ifb, _tuple[COUNT]) == RLM_MODULE_OK:
                        if addShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                            applyingFilter(policy_id, reverse_shaper_id, ifb)
                    else:
                        return RLM_MODULE_FAIL
            if not ifbOfPerShaperExistInTheExsitedList:
                if addParentShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                    if addShaper(reverse_shaper, ifb) == RLM_MODULE_OK:
                        applyingFilter(policy_id, reverse_shaper_id, ifb)
                else:
                    return RLM_MODULE_FAIL

    else:
        logger.error("apply shaper type \"" + str(reverse_shaper_type) + "\" is wrong!")
        return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def applyingFilter(policy_id, shaper_id, interface):
    filterCmd = TC + " filter add dev " + interface + " parent 1:0 protocol ip prio 1 handle " + str(
        policy_id) + " fw flowid 1:" + str(shaper_id)
    process = runProcess(filterCmd)
    if process.returncode == 0:
        logger.info('filter added on \'' + str(interface) + '\' for shaper \'' + str(shaper_id) + '\'')
    else:
        logger.error("Can't apply this filter: " + filterCmd)
        fillErrors(process)
        return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def updateDefaultShaper(interface, remain, interfaceMaxBW):
    updateCmd = TC + ' class change dev ' + str(interface) + ' parent 1:' + str(ROOT_CLASS_ID) + \
                ' classid 1:' + str(DEFAULT_POLICY_ID) + ' htb rate ' + str(remain) + ' ceil ' + str(
        interfaceMaxBW) + ' prio 7'
    process = runProcess(updateCmd)
    if process.returncode == 0:
        logger.info('default shaper ' + str(DEFAULT_POLICY_ID) + ' on \'' + str(interface) + '\' updated')
        return RLM_MODULE_OK
    else:
        logger.error("Can't update default shaper: " + updateCmd)
        fillErrors(process)
        return RLM_MODULE_FAIL


def addShapingPolicy(newShapingPolicy):
    # deletePolicy(newPolicy, "")
    shaper = None
    reverse_shaper = None
    try:
        policy_id = newShapingPolicy[POLICY_ID]
        ifb_int = newShapingPolicy[IFB_INT]
        interface = newShapingPolicy[WAN_INT]
        if policy_id != DEFAULT_POLICY_ID:
            if interface in newShapingPolicy['tuns']:
                interface = newShapingPolicy['tuns'][interface]
        shaperAlreadyExistOnThisInterfaces = newShapingPolicy[SHAPER_EXSITED]
        for _tuple in shaperAlreadyExistOnThisInterfaces:
            if newShapingPolicy[WAN_INT] == _tuple[NAME]:
                _tuple[NAME] = interface

        ReverseShaperIdAlreadyExistOnThisIfbs = newShapingPolicy[REVERSE_SHAPER_EXISTED]
        if SHAPER in list(newShapingPolicy.keys()) and newShapingPolicy[SHAPER]:
            shaper = newShapingPolicy[SHAPER]
        if REVERSE_SHAPER in list(newShapingPolicy.keys()) and newShapingPolicy[REVERSE_SHAPER]:
            reverse_shaper = newShapingPolicy[REVERSE_SHAPER]
    except Exception as e:
        logger.error("can't parse new shaping policy for: " + str(e))
        return RLM_MODULE_FAIL

    if addMarksForShapingPolicy(newShapingPolicy) == RLM_MODULE_OK:
        addTempPolicy(newShapingPolicy)
        time.sleep(1)
        delTempPolicy(newShapingPolicy)
        if shaper == None and reverse_shaper == None:
            logger.error('can\'t add policy without neither shaper nor reverse shaper!')
            return RLM_MODULE_FAIL
        if shaper != None and interface == None:
            logger.error('can\'t add policy for upload shaping without interface!')
            return RLM_MODULE_FAIL
        if reverse_shaper != None and ifb_int == None:
            logger.error('can\'t add policy for download shaping without ifb interface!')
            return RLM_MODULE_FAIL
        if shaper != None and interface != None:
            if addShaperToUploadShapingTreeAndApplyingFilter(policy_id, shaper, interface,
                                                             shaperAlreadyExistOnThisInterfaces) == RLM_MODULE_OK:
                logger.info("shaper added to upload shaping tree succesfully.")
                if policy_id != DEFAULT_POLICY_ID:
                    wRemain = newShapingPolicy[WAN_REMAINED_BW]
                    interfaceMaxBW = newShapingPolicy[WAN_MAX_BW]
                    if wRemain > 0:
                        interfaceRemain = checkedRemainBW(wRemain)
                        if updateDefaultShaper(interface, interfaceRemain, interfaceMaxBW) == RLM_MODULE_OK:
                            logger.info("default upload shaper updated successfully.")
                        else:
                            logger.error("can\'t update default upload shaper!")
                            return RLM_MODULE_FAIL
                    elif wRemain == 0:
                        interfaceRemain = '64kbit'
                        if updateDefaultShaper(interface, interfaceRemain, interfaceMaxBW) == RLM_MODULE_OK:
                            logger.info("default upload shaper updated successfully.")
                        else:
                            logger.error("can\'t update default upload shaper!")
                            return RLM_MODULE_FAIL
                    else:
                        logger.error('interface remain not exist!')
                        return RLM_MODULE_FAIL
            else:
                logger.error('can\'t add shaper to upload shaping tree of interface \'' + str(interface) + '\'')
                return RLM_MODULE_FAIL
        if reverse_shaper != None and ifb_int != None:
            if addShaperToDownloadShapingTreeAndApplyingFilter(policy_id, reverse_shaper, ifb_int,
                                                               ReverseShaperIdAlreadyExistOnThisIfbs) == RLM_MODULE_OK:
                logger.info("shaper added to download shaping tree succesfully.")
                if policy_id != DEFAULT_POLICY_ID:
                    iRemain = newShapingPolicy[IFB_REMAINED_BW]
                    ifbMaxBW = newShapingPolicy[IFB_MAX_BW]
                    if iRemain > 0:
                        ifbRemain = checkedRemainBW(iRemain)
                        if updateDefaultShaper(ifb_int, ifbRemain, ifbMaxBW) == RLM_MODULE_OK:
                            logger.info("default download shaper updated successfully.")
                        else:
                            logger.error("can\'t update default download shaper!")
                            return RLM_MODULE_FAIL
                    elif iRemain == 0:
                        ifbRemain = '64kbit'
                        if updateDefaultShaper(ifb_int, ifbRemain, ifbMaxBW) == RLM_MODULE_OK:
                            logger.info("default download shaper updated successfully.")
                        else:
                            logger.error("can\'t update default download shaper!")
                            return RLM_MODULE_FAIL
                    else:
                        logger.error('ifb remain not exist!')
                        return RLM_MODULE_FAIL
            else:
                logger.error('can\'t add shaper to download shaping tree of interface \'' + str(ifb_int) + '\'')
                return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def updateShapingPolicy(oldShapingPolicy, newShapingPolicy):
    if deleteShapingPolicy(oldShapingPolicy) == RLM_MODULE_OK:
        if addShapingPolicy(newShapingPolicy) == RLM_MODULE_OK:
            logger.info("update shaping policy was successfully.")
            return RLM_MODULE_OK
        else:
            return RLM_MODULE_FAIL
    else:
        addShapingPolicy(oldShapingPolicy)
        return RLM_MODULE_FAIL


def deleteFilter(shaper_id, interface, policy_id):
    deleteFilterCmd = TC + " filter del dev " + interface + " parent 1:0 protocol ip prio 1 handle " + str(
        policy_id) + " fw flowid 1:" + str(shaper_id)
    process = runProcess(deleteFilterCmd)
    if process.returncode == 0:
        logger.info('filter on shaper \'' + str(shaper_id) + '\' for policy \'' + str(policy_id) + '\' on \'' + str(
            interface) + '\' deleted')
    else:
        logger.error("Can't delete this filter: " + deleteFilterCmd)
        fillErrors(process)
        return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def deleteParentShaper(shaper, interface):
    try:
        parent_id = shaper[PARENT_ID]
        gbw = shaper[SHAPER_GBW]
        mbw = shaper[SHAPER_MBW]
        priority = shaper[PRIORITY]  # TODO : priority ra hesab konam khodam ya az json mostaghim begiram!
    except Exception as e:
        logger.error("Can't parse shaper for ", str(e))
        return RLM_MODULE_FAIL
    if mbw:
        delParentCmd = TC + ' class del dev ' + str(interface) + ' parent 1:' + str(
            ROOT_CLASS_ID) + ' classid 1:' + str(parent_id) + ' htb rate ' + str(gbw) + ' ceil ' + str(
            mbw) + ' prio ' + str(priority)
        process = runProcess(delParentCmd)
        if process.returncode == 0:
            logger.info('parent shaper ' + str(parent_id) + ' deleted from \'' + str(interface) + '\'')
        else:
            logger.error("Can't delete this parent shaper: " + delParentCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    else:
        delParentCmd = TC + ' class del dev ' + str(interface) + ' parent 1:' + str(
            ROOT_CLASS_ID) + ' classid 1:' + str(
            parent_id) + ' htb rate ' + str(gbw) + ' prio ' + str(priority)
        process = runProcess(delParentCmd)
        if process.returncode == 0:
            logger.info('parent shaper ' + str(parent_id) + ' deleted from \'' + str(interface) + '\'')
        else:
            logger.error("Can't delete this parent shaper: " + delParentCmd)
            fillErrors(process)
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def deleteShaperFromUploadShapingTreeAndRemoveFilters(policy_id, shaper, interface, shaperAlreadyExistOnThisInterfaces):
    try:
        shaper_type = shaper[APPLY_TYPE]
        shaper_id = shaper[SHAPER_ID]
        parent_id = shaper[PARENT_ID]
    except Exception as e:
        logger.error("can\'t parse shaper: " + str(e))
        return RLM_MODULE_FAIL
    if shaper_type == "shared":
        if not shaperAlreadyExistOnThisInterfaces:
            if deleteFilter(shaper_id, interface, policy_id) == RLM_MODULE_OK:
                deleteShaper(shaper, interface)
        else:
            interfaceOfSharedShaperExistInExistedList = False
            for _tuple in shaperAlreadyExistOnThisInterfaces:
                if interface == _tuple[NAME]:
                    interfaceOfSharedShaperExistInExistedList = True
                    deleteFilter(shaper_id, interface, policy_id)
            if not interfaceOfSharedShaperExistInExistedList:
                if deleteFilter(shaper_id, interface, policy_id) == RLM_MODULE_OK:
                    deleteShaper(shaper, interface)

    elif shaper_type == "per":
        if not shaperAlreadyExistOnThisInterfaces:
            if deleteFilter(shaper_id, interface, policy_id) == RLM_MODULE_OK:
                deleteShaper(shaper, interface)
                deleteParentShaper(shaper, interface)
        else:
            interfaceOfPerShaperExistInExistedList = False
            for _tuple in shaperAlreadyExistOnThisInterfaces:
                if interface == _tuple[NAME]:
                    interfaceOfPerShaperExistInExistedList = True
                    updateParentShaper(shaper, interface, _tuple[COUNT] - 1)
                    if deleteFilter(shaper_id, interface, policy_id) == RLM_MODULE_OK:
                        deleteShaper(shaper, interface)
            if not interfaceOfPerShaperExistInExistedList:
                if deleteFilter(shaper_id, interface, policy_id) == RLM_MODULE_OK:
                    deleteShaper(shaper, interface)
                    deleteParentShaper(shaper, interface)
    else:
        logger.error("apply shaper type \'" + str(shaper_type) + "\' is wrong!")
        return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def deleteShaperFromDownloadShapingTreeAndRemoveFilters(policy_id, reverse_shaper, ifb,
                                                        reverseShaperIdAlreadyExistOnThisIfbs):
    try:
        reverse_shaper_type = reverse_shaper[APPLY_TYPE]
        reverse_shaper_id = reverse_shaper[SHAPER_ID]
        parent_id = reverse_shaper[PARENT_ID]
    except Exception as e:
        logger.error("can\'t parse reverse shaper: " + str(e))
        return RLM_MODULE_FAIL
    if reverse_shaper_type == "shared":
        if not reverseShaperIdAlreadyExistOnThisIfbs:
            if deleteFilter(reverse_shaper_id, ifb, policy_id) == RLM_MODULE_OK:
                deleteShaper(reverse_shaper, ifb)
        else:
            ifbOfSharedShaperExistInExistedList = False
            for _tuple in reverseShaperIdAlreadyExistOnThisIfbs:
                if ifb == _tuple[NAME]:
                    ifbOfSharedShaperExistInExistedList = True
                    deleteFilter(reverse_shaper_id, ifb, policy_id)
            if not ifbOfSharedShaperExistInExistedList:
                if deleteFilter(reverse_shaper_id, ifb, policy_id) == RLM_MODULE_OK:
                    deleteShaper(reverse_shaper, ifb)

    elif reverse_shaper_type == "per":
        if not reverseShaperIdAlreadyExistOnThisIfbs:
            if deleteFilter(reverse_shaper_id, ifb, policy_id) == RLM_MODULE_OK:
                deleteShaper(reverse_shaper, ifb)
                deleteParentShaper(reverse_shaper, ifb)
        else:
            ifbOfPerShaperExistInExistedList = False
            for _tuple in reverseShaperIdAlreadyExistOnThisIfbs:
                if ifb == _tuple[NAME]:
                    ifbOfPerShaperExistInExistedList = True
                    updateParentShaper(reverse_shaper, ifb, _tuple[COUNT] - 1)
                    if deleteFilter(reverse_shaper_id, ifb, policy_id) == RLM_MODULE_OK:
                        deleteShaper(reverse_shaper, ifb)
            if not ifbOfPerShaperExistInExistedList:
                if deleteFilter(reverse_shaper_id, ifb, policy_id) == RLM_MODULE_OK:
                    deleteShaper(reverse_shaper, ifb)
                    deleteParentShaper(reverse_shaper, ifb)
    else:
        logger.error("reverse shaper apply type \'" + str(reverse_shaper_type) + "\' is wrong!")
        return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def deleteShapingPolicy(shapingPolicy):
    shaper = None
    reverse_shaper = None
    try:
        policy_id = shapingPolicy[POLICY_ID]
        ifb_int = shapingPolicy[IFB_INT]
        interface = shapingPolicy[WAN_INT]
        if interface in shapingPolicy['tuns']:
            interface = shapingPolicy['tuns'][interface]
        shaperAlreadyExistOnThisInterfaces = shapingPolicy[SHAPER_EXSITED]
        for _tuple in shaperAlreadyExistOnThisInterfaces:
            if shapingPolicy[WAN_INT] == _tuple[NAME]:
                _tuple[NAME] = interface

        ReverseShaperIdAlreadyExistOnThisIfbs = shapingPolicy[REVERSE_SHAPER_EXISTED]
        if SHAPER in list(shapingPolicy.keys()) and shapingPolicy[SHAPER]:
            shaper = shapingPolicy[SHAPER]
        if REVERSE_SHAPER in list(shapingPolicy.keys()) and shapingPolicy[REVERSE_SHAPER]:
            reverse_shaper = shapingPolicy[REVERSE_SHAPER]
    except Exception as e:
        logger.error("can't parse shaping policy for: " + str(e))
        return RLM_MODULE_FAIL
    deleteMarksForShapingPolicy(shapingPolicy, "")
    process = runProcess(
        IPTABLES + ' -t mangle -I POSTROUTING -m mark --mark ' + str(policy_id) + ' -j CONNMARK --set-mark 0x0')
    if process.returncode != 0:
        fillErrors(process)
        return RLM_MODULE_FAIL
    time.sleep(1)
    process = runProcess(
        IPTABLES + ' -t mangle -D POSTROUTING -m mark --mark ' + str(policy_id) + ' -j CONNMARK --set-mark 0x0')
    if process.returncode != 0:
        fillErrors(process)
        return RLM_MODULE_FAIL
    if shaper == None and reverse_shaper == None:
        logger.error('can\'t delete policy without neither shaper nor reverse shaper!')
        return RLM_MODULE_FAIL
    if shaper != None and interface == None:
        logger.error('can\'t delete policy for upload shaping without wan interface!')
        return RLM_MODULE_FAIL
    if reverse_shaper != None and ifb_int == None:
        logger.error('can\'t delete policy for download shaping without ifb interface!')
        return RLM_MODULE_FAIL
    if shaper != None and interface != None:
        if deleteShaperFromUploadShapingTreeAndRemoveFilters(policy_id, shaper, interface,
                                                             shaperAlreadyExistOnThisInterfaces) == RLM_MODULE_OK:
            logger.info("shaper deleted from upload shaping tree.")
            if policy_id != DEFAULT_POLICY_ID:
                wRemain = shapingPolicy[WAN_REMAINED_BW]
                interfaceMaxBW = shapingPolicy[WAN_MAX_BW]
                if wRemain > 0:
                    wanRemain = checkedRemainBW(wRemain)
                    if updateDefaultShaper(interface, wanRemain, interfaceMaxBW) == RLM_MODULE_OK:
                        logger.info("default upload shaper updated successfully.")
                    else:
                        logger.error("can\'t update default upload shaper!")
                        return RLM_MODULE_FAIL
                elif wRemain == 0:
                    wanRemain = '64kbit'
                    if updateDefaultShaper(interface, wanRemain, interfaceMaxBW) == RLM_MODULE_OK:
                        logger.info("default upload shaper updated successfully.")
                    else:
                        logger.error("can\'t update default upload shaper!")
                        return RLM_MODULE_FAIL
                else:
                    logger.error('wan remain not exist!')
                    return RLM_MODULE_FAIL
        else:
            logger.error('can\'t add shaper to upload shaping tree of interface \'' + str(interface) + '\'')
            return RLM_MODULE_FAIL

    if reverse_shaper != None and ifb_int != None:
        if deleteShaperFromDownloadShapingTreeAndRemoveFilters(policy_id, reverse_shaper, ifb_int,
                                                               ReverseShaperIdAlreadyExistOnThisIfbs) == RLM_MODULE_OK:
            logger.info("shaper deleted from download shaping tree.")
            if policy_id != DEFAULT_POLICY_ID:
                iRemain = shapingPolicy[IFB_REMAINED_BW]
                ifbMaxBW = shapingPolicy[IFB_MAX_BW]
                if iRemain > 0:
                    ifbRemain = checkedRemainBW(iRemain)
                    if updateDefaultShaper(ifb_int, ifbRemain, ifbMaxBW) == RLM_MODULE_OK:
                        logger.info("default download shaper updated successfully.")
                    else:
                        logger.error("can\'t update default download shaper!")
                        return RLM_MODULE_FAIL
                elif iRemain == 0:
                    ifbRemain = '64kbit'
                    if updateDefaultShaper(ifb_int, ifbRemain, ifbMaxBW) == RLM_MODULE_OK:
                        logger.info("default download shaper updated successfully.")
                    else:
                        logger.error("can\'t update default download shaper!")
                        return RLM_MODULE_FAIL
                else:
                    logger.error('ifb remain not exist!')
                    return RLM_MODULE_FAIL
        else:
            logger.error('can\'t add shaper to download shaping tree of interface \'' + str(ifb_int) + '\'')
            return RLM_MODULE_FAIL
    return RLM_MODULE_OK


def readDBInformation():
    database_details = {}

    with open('/etc/freeradius/mods-available/sql') as sql_file:
        content = sql_file.read()

        username = re.search(r'^\s*login\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
        host = re.search(r'^\s*server\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
        password = re.search(r'^\s*password\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
        port = re.search(r'^\s*port\s*=\s*(\d+)', content, re.M)
        database_name = re.search(r'^\s*radius_db\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
        if username:
            database_details['PostgreSQL_USERNAME'] = username.group(1)
        else:
            print("ERROR: I can't read postgresql username from /etc/freeradius/mods-available/sql")
            return {}

        if password:
            database_details['PostgreSQL_PASSWORD'] = password.group(1)
        else:
            print("ERROR: I can't read postgresql password from /etc/freeradius/mods-available/sql")
            return {}

        if database_name:
            database_details['PostgreSQL_DATABASE'] = database_name.group(1)
        else:
            print("ERROR: I can't read postgresql database name from /etc/freeradius/mods-available/sql")
            return {}

        if host:
            database_details['PostgreSQL_HOST'] = host.group(1)
        else:
            print("ERROR: I can't read postgresql host address from /etc/freeradius/mods-available/sql")
            return {}

        if port:
            database_details['PostgreSQL_PORT'] = port.group(1)
        else:
            print("ERROR: I can't read postgresql port from /etc/freeradius/mods-available/sql")
            return {}

    try:
        con = psycopg2.connect(user=database_details['PostgreSQL_USERNAME'], \
                               password=database_details['PostgreSQL_PASSWORD'], \
                               database=database_details['PostgreSQL_DATABASE'], \
                               host=database_details['PostgreSQL_HOST'], \
                               port=database_details['PostgreSQL_PORT'])
    except:
        print("ERROR: Can't create database connetion!")
    return database_details


def runProcess(cmd):
    '''
    finalCMD = []
    if type(cmd) == type([]):
        for c in cmd:
            t = c.split()
            finalCMD = finalCMD + t
    else:
        t = cmd.split()
        finalCMD = finalCMD + t
    '''

    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        return process
    except Exception as e:
        logger.error("Can't run <%s>\nThe exception is: %s" % (cmd, str(e)))
        return None


def whereShouldIInsertMyPolicy(myOrder, myPolicyID):
    policy = {}
    isItFirstPolicy = True
    policyNameCondition = ""
    lastLineNumber = 1
    resultPolicy = {}
    process = runProcess(IPTABLES + ' --line-number -t mangle -nvL POSTROUTING')
    for line in iter(process.stdout.readline, b''):

        result = re.search("^\s*(\d+)\s+\d+[KMG]*\s+\d+[KMG]*\s+qos_policy_id_(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)", line,
                           re.M)
        if result:
            if str(result.group(2)) not in policy:  # just consider the first line of a policy_id
                logger.info("policy[%s] = %s" % (str(result.group(2)), str(result.group(1)),))
                # The two lines below is for putting any rules above default rule(policy_id_9999)
                if str(result.group(2)) == str(DEFAULT_POLICY_ID):
                    if not str(DEFAULT_POLICY_ID) in list(resultPolicy.keys()):
                        resultPolicy[str(DEFAULT_POLICY_ID)] = result.group(1)

                policy[str(result.group(2))] = str(result.group(1))

                if (result.group(2) == str(myPolicyID)):
                    logger.warning("The imported policy id(%s) is exist" % (str(myPolicyID),))
                    policy = {}
                    policy[str(result.group(2))] = str(result.group(1))
                    policy["outint"] = str(result.group(3))
                    return policy

                if isItFirstPolicy:
                    isItFirstPolicy = False
                    policyNameCondition += " ("

                else:
                    policyNameCondition += " or "

                # if str(result.group(2)) != str(DEFAULT_POLICY_ID):
                policyNameCondition += "policy_id=" + str(result.group(2))

            lastLineNumber = result.group(1)
        elif not re.search("^num\s+pkts\s+bytes", line, re.M) and \
                not re.search("^Chain\s+", line, re.M):
            logger.warning("Wrong regular expression to detecting line and policy id for this row: \n%s" % (line,))

    if not isItFirstPolicy:
        policyNameCondition += ")"

    if not policy:  # Can't find any policy in iptables! return None
        return {}

    query = "select policy_id from policy_qos where " + POLICY_ORDER + " > %d " % (myOrder,)
    if policyNameCondition:
        query += "and %s " % (policyNameCondition,)
    query += "order by POLICY_ORDER limit 1"

    rows = None
    try:
        dbh, curDbh = next(connectToDB())
        if not dbh:
            logger.error("Can't connect to db and check policy orders!")
            return False
        curDbh.execute(query)
        row = curDbh.fetchone()
    except Exception as e:
        logger.error("Can't connect to database or can't execute the query. The reason:%s" % (e,))
        return {}

    if row:
        if row[0] and policy:
            resultPolicy = {}
            resultPolicy[row[0]] = policy[str(row[0])]
    else:
        resultPolicy["tempId"] = int(lastLineNumber) + 1

    return resultPolicy


def canIdeleteDefaultChain9999():
    process = runProcess(IPTABLES + ' --line-number -t mangle -nvL POSTROUTING')
    flag = True
    for line in iter(process.stdout.readline, b''):
        result = re.search("^\s*(\d+)\s+\d+[KMG]*\s+\d+[KMG]*\s+qos_policy_id_(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)", line,
                           re.M)
        if result:
            if str(result.group(2)) == str(DEFAULT_POLICY_ID):
                flag = False
    return flag


qosmw_warnings = []
qosmw_errors = []


def fillWarnings(msg):
    if not msg:
        return msg
    global qosmw_warnings
    qosmw_warnings.append(msg)
    return msg


def fillErrors(process):
    if not process:
        return ""
    global qosmw_errors

    if type(process) == type(""):
        msg = process
    else:
        stdout = process.communicate()
        msg = stdout[1]
    qosmw_errors.append(msg)
    return msg


def convertTimeToUTC(localTime):
    return time.strftime("%Y-%m-%d %H:%M:%S",
                         time.gmtime(time.mktime(time.strptime(localTime,
                                                               "%Y-%m-%d %H:%M:%S"))))


def connectToDB():
    dhb = None
    curDbh = None
    while True:
        if curDbh and not curDbh.closed:
            yield dbh, curDbh

        try:
            dbInfo = readDBInformation()
            dbh = psycopg2.connect(user=dbInfo['PostgreSQL_USERNAME'], \
                                   password=dbInfo['PostgreSQL_PASSWORD'], \
                                   database=dbInfo['PostgreSQL_DATABASE'], \
                                   host=dbInfo['PostgreSQL_HOST'], \
                                   port=dbInfo['PostgreSQL_PORT'])
            curDbh = dbh.cursor(cursor_factory=DictCursor)
        except Exception as e:
            logger.error("Can't connect to database. The reason:%s" % (e,))
            yield None, None
        yield dbh, curDbh


def updatePolicyFWMsgTable(policy_id, rule_id, rule_content, errors, warnings, doClean=False):
    dbh, curDbh = next(connectToDB())
    if not dbh:
        logger.error("Can't update errors and warnings!")
        return False

    j_errors = ""
    j_warnings = ""
    counter = 0
    if errors:
        errList = errors.split("\n")
        j_errors = json.dumps(errList)
    if warnings:
        warnList = re.split("\n")
        j_warnings = json.dumps(warnList)

    rule = {}
    rule['rule'] = rule_content
    rule_content = json.dumps(rule)
    if not j_errors:
        j_errors = '{}'
    if not j_warnings:
        j_warnings = '{}'

    try:
        if doClean:
            curDbh.execute("DELETE FROM qos_policy_msg WHERE policy_id=%s", (policy_id,))
        curDbh.execute("INSERT INTO qos_policy_msg \
        VALUES (%s, %s, %s, %s, %s)", (policy_id, rule_id, rule_content, j_errors, j_warnings))
        dbh.commit()
    except Exception as e:
        dbh.rollback()
        logger.error("Can't update qos_policy_msg. The reason:%s" % (e,))
        return False

    return True


def deleteMarksForShapingPolicy(oldPolicy, oldNamePrefix=""):
    removeChainCommand = []
    removeRulesCommand = []
    isAnyRulesApplyedSuccessfuly = True
    isThereAtLeastOneSuccessfulRule = False
    if POLICY_ID in list(oldPolicy.keys()) and oldPolicy[POLICY_ID]:
        removeChainCommand.append(IPTABLES + " -t mangle -F qos_policy_id_" + str(oldPolicy[POLICY_ID]) + oldNamePrefix)
        removeChainCommand.append(IPTABLES + " -t mangle -X qos_policy_id_" + str(oldPolicy[POLICY_ID]) + oldNamePrefix)

        mainPolicyes, chainPolicyes = findTheRelatedRulesInfo(str(oldPolicy[POLICY_ID]) + oldNamePrefix, False)
        if mainPolicyes:
            mainPolicyes.reverse()
            for info in mainPolicyes:
                removeRulesCommand.append(IPTABLES + " -t mangle -D POSTROUTING " + info['line-number'])

    logger.info("removeRulesCommand:")
    if removeRulesCommand:
        for cmd in removeRulesCommand:
            logger.info(cmd)
            process = runProcess(cmd)
            if process.returncode:
                fillErrors(process)
                isAnyRulesApplyedSuccessfuly = False
            else:
                isThereAtLeastOneSuccessfulRule = True

    logger.info("removeChainCommnd:")
    if (removeChainCommand):
        for cmd in removeChainCommand:
            logger.info(cmd)
            process = runProcess(cmd)
            if process.returncode:
                fillErrors(process)
                isAnyRulesApplyedSuccessfuly = False
            else:
                isThereAtLeastOneSuccessfulRule = True

    if isAnyRulesApplyedSuccessfuly:
        return RLM_MODULE_OK
    elif isThereAtLeastOneSuccessfulRule:
        return RLM_MODULE_INVALID
    else:
        return RLM_MODULE_FAIL


def findTheRelatedRulesInfo(myPolicyID, temp, iptables_nvL=None):
    mainLines = []
    chainLines = []
    if (temp == True):
        process = runProcess(IPTABLES + ' -t mangle -nvL qos_temp_id_' + str(myPolicyID))
    else:
        process = runProcess(IPTABLES + ' -t mangle -nvL qos_policy_id_' + str(myPolicyID))

    if not process.returncode:
        regX = "^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(.+)\n"
        for line in iter(process.stdout.readline, b''):
            policyInfo = {}
            result = re.search(regX, line, re.M)
            if (result):
                policyInfo['pkts'] = str(result.group(1))
                policyInfo['bytes'] = str(result.group(2))
                policyInfo['content'] = result.group(3)
                chainLines.append(policyInfo)

    if not iptables_nvL:
        process = runProcess(IPTABLES + ' --line-number -t mangle -nvL POSTROUTING')
        if not process.returncode:
            iptables_nvL = process.communicate()[0].split("\n")
    if (temp == True):
        regX = "^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(\d+[KMG]*)\s+qos_temp_id_" + str(myPolicyID) + "\s*(.*)"
    else:
        regX = "^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(\d+[KMG]*)\s+qos_policy_id_" + str(myPolicyID) + "\s*(.*)"

    if iptables_nvL:
        for line in iptables_nvL:
            policyInfo = {}
            result = re.search(regX, line, re.M)
            if (result):
                policyInfo['line-number'] = str(result.group(1))
                policyInfo['pkts'] = str(result.group(2))
                policyInfo['bytes'] = str(result.group(3))
                policyInfo['content'] = result.group(4)
                mainLines.append(policyInfo)

    return mainLines, chainLines


def updateMarksForShapingPolicy(oldPolicy, newPolicy):
    if POLICY_ID in list(oldPolicy.keys()) and oldPolicy[POLICY_ID]:
        # rename the policy!
        renamePolicyCommand = IPTABLES + " -t mangle -E qos_policy_id_" + str(oldPolicy[POLICY_ID]) \
                              + " qos_policy_id_" + str(oldPolicy[POLICY_ID]) + OLD_NAME_PREFIX
        logger.info("renamePolicyCommand:" + renamePolicyCommand)
        runProcess(renamePolicyCommand)

    addReturnVal = addMarksForShapingPolicy(newPolicy)
    delReturnVal = deleteMarksForShapingPolicy(oldPolicy, OLD_NAME_PREFIX)
    if (addReturnVal != RLM_MODULE_OK):
        return addReturnVal
    if (delReturnVal != RLM_MODULE_OK):
        return delReturnVal

    return RLM_MODULE_OK


setLoggingConfigs()
