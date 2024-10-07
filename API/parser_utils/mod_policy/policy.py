import collections
import logging
import os
import re
import sys
import time
from builtins import getattr

from django.forms import model_to_dict

from api.settings import IS_TEST, BACKUP_DIR, POLICY_BACK_POSTFIX
from auth_app.utils import get_client_ip
from firewall_app.models import PolicyCommandsForTest
from parser_utils.mod_policy import l7_mapper
from parser_utils.mod_resource.utils import get_map_tun_interfaces, get_pppoe_interfaces_map
from qos_utils.utils import apply_qos_policy
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner
from utils.config_files import RTABLE_FILE
from utils.log import log
from utils.utils import print_if_debug

RLM_MODULE_FAIL = 1
RLM_MODULE_OK = 2
RLM_MODULE_INVALID = 4
RLM_MODULE_NOT_FOUND = 6

OLD_NAME_PREFIX = "_old"
FIRST_PRIORITY_NUMBER = 31002

logger = logging.getLogger('firewall')

process_result = collections.namedtuple("process_result", ['returncode', 'stdout', 'stderr'])


def find_related_rules_info(policy_id, iptables_nvl=None, table_name=None, chain_name="FORWARD"):
    main_lines = []
    chain_lines = []
    policy_name = 'policy_id_{}'.format(policy_id)
    table_command = ""
    if table_name:
        table_command = " -t " + table_name
        policy_name = 'nat_id_{}'.format(policy_id)

    cmd = 'iptables -w -nvL ' + policy_name + table_command
    status, result = sudo_runner(cmd)
    if status:
        regex = "^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(.+)\n"
        for line in str(result).split('\n'):
            policy_info = {}
            result = re.search(regex, line, re.M)
            if result:
                policy_info['pkts'] = str(result.group(1))
                policy_info['bytes'] = str(result.group(2))
                policy_info['content'] = result.group(3)
                chain_lines.append(policy_info)

    if not iptables_nvl:
        cmd = 'iptables -w --line-number -nvL ' + chain_name + table_command
        status, result = sudo_runner(cmd)
        if status:
            iptables_nvl = str(result).split("\n")

    regex = "^\s*(\d+[KMG]*)\s+(\d+[KMG]*)\s+(\d+[KMG]*)\s+" + policy_name + "\s+(.*)"
    if iptables_nvl:
        for line in iptables_nvl:
            policy_info = {}
            result = re.search(regex, line, re.M)
            if result:
                policy_info['line-number'] = str(result.group(1))
                policy_info['pkts'] = str(result.group(2))
                policy_info['bytes'] = str(result.group(3))
                policy_info['content'] = result.group(4)
                main_lines.append(policy_info)

    return main_lines, chain_lines


def where_should_insert_policy(policy, table_name=None, chain_name="FORWARD"):
    policy_dict = {}  # This dictionary contains the last line number of each existed policy id
    # in iptable -nvL --line-numbers output
    is_it_first_policy = True
    policy_name_condition = ""
    table_command = ""
    policy_id_condition = []
    last_line_number = 1
    head_rule_line = 0
    if table_name:
        table_command = " -t " + table_name

    cmd = 'iptables -w --line-number -nvL ' + chain_name + table_command
    status, result = sudo_runner(cmd)
    if status:
        output = str(result).strip()
    else:
        print_if_debug("Can't get current policies status." + str(result))
        return None, None

    for line in output.split('\n'):
        if not head_rule_line:
            result = re.search("^\s*(\d+)\s+\d+[KMG]*\s+\d+[KMG]*\s+head_rules", line, re.M)
            if result:
                head_rule_line = int(result.group(1))

        if table_name == 'nat':
            result = re.search("^\s*(\d+)\s+\d+[KMG]*\s+\d+[KMG]*\s+nat_id_(\d+)\s+", line, re.M)
        else:
            result = re.search("^\s*(\d+)\s+\d+[KMG]*\s+\d+[KMG]*\s+policy_id_(\d+)\s+", line, re.M)

        if result:
            if str(result.group(2)) not in policy_dict:  # just consider the first line of a policy_id
                policy_dict[str(result.group(2))] = str(result.group(1))
                # Check if the current iptables status is contained this policy or not
                if result.group(2) == str(policy.id):
                    print_if_debug("The imported policy id(%s) is exist!" % (str(policy.id),))
                    policy_dict = dict()
                    policy_dict[str(result.group(2))] = str(result.group(1))
                    return policy_dict, head_rule_line
                if is_it_first_policy:
                    is_it_first_policy = False
                    policy_name_condition += " ("
                else:
                    policy_name_condition += " or "
                if table_name == 'nat':
                    policy_name_condition += "nat_id=" + str(result.group(2))
                else:
                    policy_name_condition += "policy_id=" + str(result.group(2))
                policy_id_condition.append(int(result.group(2)))
            last_line_number = result.group(1)
        elif not re.search("^num\s+pkts\s+bytes", line, re.M) and \
                not re.search("^Chain\s+", line, re.M):
            print_if_debug("Wrong regular expression to detecting line and policy id for this row: \n%s" % (line,))

    if not is_it_first_policy:
        policy_name_condition += ")"

    if not policy_dict:  # Can't find any policy in iptables! return None
        return {}, head_rule_line

    result_policy = dict()

    # iterate the link list of next_policies to find the first one that was applied in iptables. In this case, we will
    # find the best position that follows the policies order to insert the current policy
    while True:
        if not policy.next_policy:  # if there isn't exist any policy in iptables -nvL, return last possible line number
            # (after head rules or any other known things)
            result_policy["tempId"] = int(last_line_number) + 1
            return result_policy, head_rule_line

        if policy.next_policy.id in policy_id_condition:  # if the next_policy exists in iptables -nvL output return
            # the next_policy's last line that was applied in iptables -nvL
            result_policy[policy.next_policy.id] = policy_dict[str(policy.next_policy.id)]
            return result_policy, head_rule_line

        policy = policy.next_policy

    return None, None


def convert_time_to_utc(local_time):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.mktime(time.strptime(local_time, "%Y-%m-%d %H:%M:%S"))))


def check_ipset_exist_and_not_empty(ipset_name):
    cmd = "ipset -L " + ipset_name
    status, result = sudo_runner(cmd)
    if status:
        ipset_result = str(result)
        if ipset_result:
            result = re.search("Members:\n\d+", ipset_result, re.M)
            if not result:  # The set is empty
                return False
            else:
                return True  # The set is not empty!

    return False


def get_service_list(data, temp_service_list=None, not_ports=False):
    protocol_list = []
    all_services = {
        'tcp': list(),
        'udp': list()
    }
    nat_map_ports = set()
    if temp_service_list:
        for service in temp_service_list:
            # service['protocol'] should be something like these samples:
            # {'tcp': {'src': ['8432'], 'dst': ['13243']}}
            # {'tcp': {'dst': ['1283']}}
            # {'tcp': {'src': ['natport'], 'dst': ['5005']}} # This sample said that there is dst port related
            #                                                   to NAT's mapped IP
            service_ports = {
                'tcp': {
                    'src': set(),
                    'dst': set()
                },
                'udp': {
                    'src': set(),
                    'dst': set()
                }
            }
            if "tcp" in service['protocol'] or \
                    "udp" in service['protocol']:
                for proto in service['protocol']:
                    proto_ports = service['protocol'][proto]
                    if not proto_ports:  # Empty proto list related to all_tcp or all_udp
                        service_ports[proto]['src'].add("")
                        service_ports[proto]['dst'].add("")
                        continue

                    if 'src' in proto_ports.keys():
                        # print("proto_ports['src']:{}".format(proto_ports['src']))
                        for port in proto_ports['src']:
                            # port_type = "normal"
                            # if 'dst' in proto_ports and proto_ports['dst'] and proto_ports['dst'][0] == 'natport':
                            #     port_type = "nat"  # This port is a mapping port that should be open in forward chain
                            if port == 'natport':
                                continue

                            if port:
                                if port.find("-") != -1:
                                    port = str.replace(port, '-', ':')

                                if 'dst' in proto_ports and proto_ports['dst'] and proto_ports['dst'][0] == 'natport':
                                    nat_map_ports.add(port)
                                else:
                                    service_ports[proto]['src'].add(port)

                    if 'dst' in proto_ports.keys():
                        for port in proto_ports['dst']:
                            if port == 'natport':
                                continue

                            if port:
                                if port.find("-") != -1:
                                    port = str.replace(port, '-', ':')
                                if 'src' in proto_ports and proto_ports['src'] and proto_ports['src'][0] == 'natport':
                                    nat_map_ports.add(port)
                                else:
                                    service_ports[proto]['dst'].add(port)

            elif "icmp" in service['protocol']:
                icmp_type = ""
                if 'type' in service['protocol']['icmp'].keys():
                    icmp_type = " --icmp-type {}".format(service['protocol']['icmp']['type'])
                    if 'code' in service['protocol']['icmp'].keys():
                        icmp_type += "/{}".format(service['protocol']['icmp']['code'])
                icmp_commands = "-p icmp " + icmp_type
                protocol_list.append({"rule": icmp_commands, "type": "normal"})
            elif "ip" in service['protocol']:
                if 'protocol_number' in service['protocol']['ip'].keys():
                    protocol_list.append({"rule": "-p {} ".format(service['protocol']['ip']['protocol_number']),
                                          "type": "normal"})

            all_services['tcp'].append(service_ports['tcp'])
            all_services['udp'].append(service_ports['udp'])
            # else:
            #     protocol_list.append({"rule": "-mndpi --" + service['protocol'], "type": "normal"})
        if len(nat_map_ports):
            nat_map_ports = nat_map_ports.pop()
        for proto in ["tcp", "udp"]:
            for service in all_services[proto]:
                src_port = ""
                dst_port = ""
                port_type = "normal"
                if not_ports:
                    src_port = "!"
                    dst_port = "!"
                for src in service['src']:
                    src_port += src + ","
                if src_port == "!":
                    src_port = ""

                if len(nat_map_ports):
                    port_type = "mapped_port"

                for dst in service['dst']:
                    if port_type != "normal":
                        port_type = "just_for_nat"
                    dst_port += dst + ","
                if dst_port == "!":
                    dst_port = ""

                if src_port:
                    if src_port[:-1]:
                        src_port = "-mmultiport --sport {}".format(src_port[:-1])
                    else:
                        src_port = " "
                if dst_port:
                    if dst_port[:-1]:
                        dst_port = "-mmultiport --dport {}".format(dst_port[:-1])
                    else:
                        dst_port = " "
                if src_port or dst_port:
                    protocol_list.append(
                        {"rule": "-p {} {} {}".format(proto, src_port, dst_port), "type": port_type})
                # if there is a nat port, just add it as destination port in forward and ignore it in nat
                # There is not require to do below code for src ports because we don't support src port nat!
                # After this function three type of port is come up:
                # 1. mapped_port to use in forward chain
                # 2. normal to use in forward and nat chain
                # 3. just_for_nat to only use in nat chains
                # Note: it is assumed that there is only one nat port!
                if len(nat_map_ports):
                    nat_dst_port = " -mmultiport --dport " + nat_map_ports
                    port_type = "mapped_port"
                    if src_port or dst_port:
                        protocol_list.append(
                            {"rule": "-p {} {} {}".format(proto, src_port, nat_dst_port), "type": port_type})

    # if hasattr(data.source_destination, 'application_list') and data.source_destination.application_list:
    #     for application in data.source_destination.application_list.all():
    #         if application.protocol in ['icmp', 'tcp', 'udp']:
    #             protocol_list.append({"rule": "-p " + application.protocol, "type": "normal"})
    #         else:
    #             protocol_list.append({"rule": "-mndpi --" + application.protocol, "type": "normal"})

    # print("protocol_list:{}".format(protocol_list))
    return protocol_list


def get_dst_network_list(policy):
    dst_ip_list = []
    dst_mac_fqdn_list = []
    if policy.source_destination.dst_network_list:
        for net in policy.source_destination.dst_network_list.all():
            if net.type and net.value_list:
                for addr in net.value_list:
                    if net.type == 'ip':
                        dst_ip_list.append(addr)
                    elif net.type == 'mac':
                        print_if_debug("The MAC for destination is illegal")
                    elif net.type == 'fqdn':  # TODO add this to web proxy policies
                        dst_mac_fqdn_list.append({"net": "-d " + addr, "type": "normal"})

    return dst_mac_fqdn_list, dst_ip_list


def get_dst_interface_list(data, tuns):
    dst_interfaces_list = []

    if data.source_destination.dst_interface_list.all():
        for interface in data.source_destination.dst_interface_list.all():
            interface = interface.name
            if interface in tuns and tuns[interface]:
                interface = tuns[interface]
            dst_interfaces_list.append(interface)
    return dst_interfaces_list


def create_ip_rule_table(interface_name, interface_id):
    cmd = 'cat {}'.format(RTABLE_FILE)
    status, result = sudo_runner(cmd)

    if status:
        if result.find(interface_name) == -1:
            cmd = 'echo {0} {1}.out >> {2}'.format(interface_id + 1000, interface_name, RTABLE_FILE)
            sudo_runner(cmd)


def get_src_network_list(data, pbr=None):
    src_ip_list = []
    src_mac_fqdn_list = []
    pbr_commands = []
    if data.source_destination.src_network_list:
        for net in data.source_destination.src_network_list.all():
            if net.type and net.value_list:
                for addr in net.value_list:
                    if net.type == 'ip':
                        if pbr:
                            if addr.find("-") == -1:
                                if (
                                        data.source_destination.dst_interface_list and
                                        len(data.source_destination.dst_interface_list) == 1
                                ):
                                    pbr_commands.append("ip rule add from {} lookup {}.out prio {}"
                                                        .format(addr,
                                                                data.source_destination.dst_interface_list[0].name,
                                                                str(FIRST_PRIORITY_NUMBER + int(data['order'])))
                                                        )
                                    create_ip_rule_table(
                                        data.source_destination.dst_interface_list[0].name,
                                        data.source_destination.dst_interface_list[0].id
                                    )
                                else:
                                    # TODO: validate this in serializer
                                    print_if_debug("PBR can set with exactly one output interface.")
                        else:
                            # TODO: validate this in serializer
                            print_if_debug("Can't have pbr for ip range! (%s)" % (addr,))
                        src_ip_list.append(addr)
                    elif net.type == 'mac':
                        src_mac_fqdn_list.append({"net": "-m mac --mac-source " + addr, "type": "normal"})
                    elif net.type == 'fqdn':  # TODO add this to web proxy policies
                        src_mac_fqdn_list.append({"net": "-s " + addr, "type": "normal"})

    return src_mac_fqdn_list, src_ip_list, pbr_commands


def get_src_interface_list(data, tuns):
    src_interfaces_list = []
    if data.source_destination.src_interface_list:
        for interface in data.source_destination.src_interface_list.all():
            interface = interface.name
            if interface in tuns and tuns[interface]:
                interface = tuns[interface]
            src_interfaces_list.append(interface)

    return src_interfaces_list


def get_user_list(data):
    output = []
    ignore_policy = None
    if hasattr(data.source_destination, 'user_list') and data.source_destination.user_list:
        do_you_find_any_set = False
        for user in data.source_destination.user_list.all():
            if check_ipset_exist_and_not_empty("_" + user + "_USER_"):
                user_set = "_" + user + "_USER_"
                do_you_find_any_set = True
                output.append({"net": "-m set --match-set " + user_set + " src", "type": "normal"})

        if do_you_find_any_set:
            ignore_policy = False

    return ignore_policy, output


def get_group_list(data):
    output = []
    ignore_policy = None
    if hasattr(data.source_destination, 'group_list') and data.source_destination.group_list:
        do_you_find_any_set = False
        for group in data.source_destination.group_list.all():
            if check_ipset_exist_and_not_empty("_" + group + "_GROUP_"):
                group_set = "_" + group + "_GROUP_"
                do_you_find_any_set = True
                output.append({"net": "-m set --match-set " + group_set + " src ", "type": "normal"})

        if do_you_find_any_set:
            ignore_policy = False

    return ignore_policy, output


def get_schedule(data):
    schedule = "-mtime"
    weekday = ""
    if not data.schedule:
        return ""
    if data.schedule.start_date:
        result = re.search("(\d+-\d+-\d+)\s*(\d+:\d+:\d+)?", str(data.schedule.start_date))
        if result:
            date_start = result.group(1)
            if not result.group(2):
                time_start = "00:00:00"
            else:
                time_start = result.group(2)
            utc_time = convert_time_to_utc(date_start + " " + time_start)
            result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", utc_time)
            if result:
                schedule += " --datestart " + result.group(1) + "T" + result.group(2)
            else:
                print_if_debug("Wrong UTC time format!")
        else:
            print_if_debug("Can't understand schedule_date_start format")

    if data.schedule.end_date:
        result = re.search("(\d+-\d+-\d+)\s*(\d+:\d+:\d+)?", str(data.schedule.end_date))
        if result:
            date_stop = result.group(1)
            if not result.group(2):
                time_stop = "23:59:59"
            else:
                time_stop = result.group(2)
            utc_time = convert_time_to_utc(date_stop + " " + time_stop)
            result = re.search("(\d+-\d+-\d+)\s+(\d+:\d+:\d+)", utc_time)
            if result:
                schedule += " --datestop " + result.group(1) + "T" + result.group(2)
            else:
                print_if_debug("Wrong UTC time format!")
        else:
            print_if_debug("Can't understand schedule_date_stop format")

    if data.schedule.start_time:
        result = re.search("^(\d+:\d+:\d+)", str(data.schedule.start_time), re.M)
        if result:
            utc_time = convert_time_to_utc("2017-02-02 " + result.group(1))  # The date is not important here!
            result = re.search("\d+-\d+-\d+\s+(\d+:\d+:\d+)", utc_time)
            schedule += " --timestart " + result.group(1)
        else:
            print_if_debug("Can't understand schedule_time_start format")

    if data.schedule.end_time:
        result = re.search("^(\d+:\d+:\d+)", str(data.schedule.end_time), re.M)
        if result:
            utc_time = convert_time_to_utc("2017-02-02 " + result.group(1))  # The date is not important here!
            result = re.search("\d+-\d+-\d+\s+(\d+:\d+:\d+)", utc_time)
            schedule += " --timestop " + result.group(1)
        else:
            print_if_debug("Can't understand schedule_time_stop format")

    if data.schedule.days_of_week:
        for day in data.schedule.days_of_week:
            if data.schedule.days_of_week[day]:
                weekday += day.capitalize() + ','

    if weekday:
        schedule += " --weekdays " + weekday[:-1]

    if schedule in ["-mtime", "-m time"]:  # remove -mtime from empty schedule
        schedule = ""

    return schedule


def create_ipsec_commands(cmd, ipsec_cmd_list):
    cmd_list = []
    if ipsec_cmd_list:
        for ipsec_cmd in ipsec_cmd_list:
            cmd_list.append(cmd + ipsec_cmd)
    else:
        cmd_list.append(cmd)
    return cmd_list


def run_policy_command(cmd):
    print_if_debug("trying to run: " + cmd)

    return sudo_runner(cmd)


def add_to_test_db(policy_commands, command_name, policy_id):
    if IS_TEST and "--debug-mode" not in sys.argv:
        p_temp = PolicyCommandsForTest.objects.filter(policy_id=policy_id)
        if not p_temp:
            p_temp = PolicyCommandsForTest.objects.create(policy_id=policy_id)
        else:
            p_temp = p_temp[0]
        # print("Trying to set {} for {}".format(policy_commands[command_name], command_name))
        setattr(p_temp, command_name, policy_commands[command_name])
        p_temp.save()
        return True
    return False


# This function will convert list to a set and remove extra spaces!
# for example:
# "iptables -I INPUT        -j ACCEPT"   ===>
# {'iptables', '-I INPUT', '-j ACCEPT'}
#
# "iptables -I    INPUT    -p tcp --dport 3040          -j ACCEPT"   ===>
# {'iptables', '-I INPUT', '-p tcp', '-j ACCEPT', '--dport 3040'}
def convert_str_to_set(spaced_str):
    s2 = ' '.join([item for item in spaced_str.split(' ') if item])
    s3 = s2.replace(' -', '  -').split('  ')
    return set(s3)


def is_this_two_iptables_rule_are_equal(p, exp):
    p = p.replace('--log-prefix=', '--log-prefix ')
    exp = exp.replace('--log-prefix=', '--log-prefix ')
    p = p.replace('--to-destination', '--to')
    exp = exp.replace('--to-destination', '--to')
    p = p.replace('--to-source', '--to')
    exp = exp.replace('--to-source', '--to')

    p_set = convert_str_to_set(p)
    exp_set = convert_str_to_set(exp)

    if p_set == exp_set:
        return True
    elif len(p_set - exp_set) > 0:
        for item in list(p_set - exp_set):
            if item[2:10] == 'weekdays' or '-cc' in item or '-country' in item:  # ignore weekdays and goeip check
                return True
    return False


def check_expected_policy_result_in_db(policy_expected_commands, policy_id):
    p_temp = PolicyCommandsForTest.objects.filter(policy_id=policy_id)
    if not p_temp:
        print("Can't find policy object!")
        return False
    p_temp = p_temp[0]

    command_names = ['create_chains', 'chain_commands', 'main_rule_commands', 'nat_rule_commands']

    for cn in command_names:
        print_if_debug("Trying to check {}".format(cn))
        added_policy_commands = getattr(p_temp, cn)
        if not added_policy_commands:
            if policy_expected_commands[cn]:
                print("Can't find any added_policy in PolicyCommandForTest db!")
                return False
            else:
                continue
        else:
            print_if_debug("expected_commands for {} is:{} and we expected: {}".format(cn, added_policy_commands,
                                                                                       policy_expected_commands[cn]))
        for exp_p in policy_expected_commands[cn]:
            do_you_find = False
            for added_p in added_policy_commands:
                if is_this_two_iptables_rule_are_equal(added_p, exp_p):
                    do_you_find = True
                    break

            if not do_you_find:
                print("Can't find expected rule: {}".format(exp_p))
                return False

    return True


def policy_create_chains(policy, policy_commands, request_username=None):
    command_name = 'create_chains'
    if not add_to_test_db(policy_commands, command_name, policy.id):
        for cmd in policy_commands[command_name]:
            cmd = "iptables -w {}".format(cmd)
            status, result = run_policy_command(cmd)
            if not status:
                if 'Chain already exists' in str(result):
                    print_if_debug("Chain {} already exists".format(cmd))
                else:
                    print_if_debug(
                        "Can't create chain {} for policy {} because of {}".format(cmd, policy.id, str(result)))
                    # log(logger_name='firewall', item='policy', operation='add', status='fail',
                    #     username=request_username,
                    #     details="Can't create chain {} for"
                    #             " policy {} because of {}".format(cmd, policy.id, str(result)))
                    # create_notification(source='policy', item={'id': policy.id, 'name': policy.name},
                    #                     message=str('Error in applying policy rules(service section)'), severity='e',
                    #                     details=str(result), request_username=request_username)
                    return False
    return True


def policy_apply_chain_commands(policy, policy_commands, request_username=None):
    is_any_chain_rules_apply_successfully = True
    command_name = 'chain_commands'
    if not add_to_test_db(policy_commands, command_name, policy.id):
        for cmd in policy_commands[command_name]:
            status, result = run_policy_command("iptables -w -I " + cmd)
            if not status:
                is_any_chain_rules_apply_successfully = False
                print_if_debug("Can't create chain {} for policy {} because of {}".format(cmd, policy.id, str(result)))
                # log(logger_name='firewall', item='policy', operation='add', status='fail', username=request_username,
                #     details="Can't run command %s, because of: %s" % (cmd, str(result)))
                # create_notification(source='policy', item={'id': policy.id, 'name': policy.name},
                #                     message=str('Error in applying policy rules(service section)'), severity='e',
                #                     details=str(result), request_username=request_username)

    return is_any_chain_rules_apply_successfully


def policy_apply_main_tables_commands(policy, policy_commands, request_username=None):
    is_any_rules_applied_successfully = True
    if policy.action or policy.is_log_enabled:
        command_name = 'main_rule_commands'
        if not add_to_test_db(policy_commands, command_name, policy.id):
            for cmd in policy_commands['main_rule_commands']:
                status, result = run_policy_command(
                    "iptables -w -I FORWARD {} {}".format(str(policy_commands['main_order']), cmd))
                if not status:
                    is_any_rules_applied_successfully = False
                    print_if_debug(
                        "Can't create chain {} for policy {} because of {}".format(cmd, policy.id, str(result)))
                    # log(logger_name='firewall', item='policy', operation='add', status='fail', username=request_username,
                    #     details="Can't run command %s, because of: %s" % (cmd, str(result)))
                    # create_notification(source='policy', item={'id': policy.id, 'name': policy.name},
                    #                     message=str('Error in applying policy rules(forward section)'), severity='e',
                    #                     details=str(result), request_username=request_username)

    return is_any_rules_applied_successfully


def policy_apply_nat_tables_commands(policy, policy_commands, request_username=None):
    is_any_rules_applied_successfully = True
    if policy.nat:
        nat_chain = "PREROUTING "
        if policy.nat and policy.nat.nat_type == "SNAT":
            nat_chain = "POSTROUTING "

        command_name = 'nat_rule_commands'
        if not add_to_test_db(policy_commands, command_name, policy.id):
            for cmd in policy_commands['nat_rule_commands']:
                status, result = run_policy_command("iptables -w -t nat -I " + nat_chain + \
                                                    str(policy_commands['nat_order']) + " " + cmd)
                if not status:
                    is_any_rules_applied_successfully = False
                    print_if_debug(
                        "Can't create chain {} for policy {} because of {}".format(cmd, policy.id, str(result)))
                    # log(logger_name='firewall', item='policy', operation='add', status='fail', username=request_username,
                    #     details="Can't run command %s, because of: %s" % (cmd, str(result)))
                    # create_notification(source='policy', item={'id': policy.id, 'name': policy.name},
                    #                     message=str('Error in applying policy rules(nat section)'), severity='e',
                    #                     details=str(result), request_username=request_username)
    return is_any_rules_applied_successfully


def policy_apply_pbr_commands(policy, policy_commands, request_username=None):
    # 'pbr_commands': policy_pbr_command_list
    # policy_commands['pbr_commands']
    return True


def create_related_ipsets_to_policy(policy, policy_commands):
    all_cmd = []
    if not add_to_test_db(policy_commands, 'dst_ip_list', policy.id):
        if policy_commands['dst_ip_list'] and not any('0.0.0.0' in item for item in policy_commands['dst_ip_list']):
            all_cmd.extend(create_ip_ipset(policy.id, policy_commands['dst_ip_list'], 'dst'))

    if not add_to_test_db(policy_commands, 'src_ip_list', policy.id):
        if policy_commands['src_ip_list'] and not any('0.0.0.0' in item for item in policy_commands['src_ip_list']):
            all_cmd.extend(create_ip_ipset(policy.id, policy_commands['src_ip_list'], 'src'))

    # Save all require cmds to create all related ipset for this policy in a file to let restart policies work fine!
    sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))

    cmd = 'echo "{}" > {}'.format('\n'.join(all_cmd), os.path.join(BACKUP_DIR, '{}/policy_{}_ipsets.backup'.format(
        POLICY_BACK_POSTFIX, policy.id)))
    sudo_runner(cmd)

    return True


def remove_related_ipsets_to_policy(policy_id):
    remove_ip_ipset(policy_id, direction='src')
    remove_ip_ipset(policy_id, direction='dst')
    cmd = 'rm {} '.format(os.path.join(BACKUP_DIR, '{}/policy_{}_ipsets.backup'.format(POLICY_BACK_POSTFIX, policy_id)))
    sudo_runner(cmd)


def apply_policy_commands(policy, policy_commands, request_username=None):
    if not create_related_ipsets_to_policy(policy, policy_commands):
        return False

    if not policy_create_chains(policy, policy_commands, request_username):
        return False
    if not policy_apply_chain_commands(policy, policy_commands, request_username):
        return False

    if not policy_apply_main_tables_commands(policy, policy_commands, request_username):
        return False
    if not policy_apply_nat_tables_commands(policy, policy_commands, request_username):
        return False

    if not policy_apply_pbr_commands(policy, policy_commands, request_username):
        return False

    return True


def add_policy(policy, operation, request_username=None, request=None, changes=None, is_update=False):
    policy_commands = create_policy_commands(policy)
    log_operation = operation
    # The policy_commands[main_order] can be one of this choices:
    # > 0 It's OK!
    #
    # -1 Ignore Add and return Fail....> For some reasons the policy order can't calculated!
    #
    # -2 Update Policy....> The policy id is exists, but it has some user and group set,
    # may be some users are login just now.
    #
    # -3 Ignore Add and return OK....> The policy is exists right now or for some reasons should ignore.

    if policy_commands['main_order'] == -1:
        create_notification(source='policy', item={'id': policy.id, 'name': policy.name},
                            message="Can't calculate policy order",
                            severity='e', request_username=request_username)
        if not is_update:
            log('firewall', 'policy', log_operation, 'fail',
                username=request_username, ip=get_client_ip(request), details=changes)
        return -1  # Fail

    elif policy_commands['main_order'] == -2:
        log('firewall', 'policy', log_operation, 'fail',
            username=request_username, ip=get_client_ip(request), details="The policy id exists, but it has some "
                                                                          "user/group set(s)")
        update_policy(policy, policy, request_username, request, changes)
        if not is_update:
            log('firewall', 'policy', log_operation, 'success',
                username=request_username, ip=get_client_ip(request), details=changes)
        return 0  # Don't set status!

    elif policy_commands['main_order'] == -3:
        print_if_debug("Can't add two policy with the same id!")
        if not is_update:
            log('firewall', 'policy', log_operation, 'success',
                username=request_username, ip=get_client_ip(request), details=changes)
        return 1  # Successful

    if not apply_policy_commands(policy, policy_commands, request_username):
        if not is_update:
            log('firewall', 'policy', log_operation, 'fail',
                username=request_username, ip=get_client_ip(request), details=changes)
        delete_policy(policy, should_create_notification=True, is_update=False)
        return -1  # Fail

    if policy.is_enabled and policy.qos:
        policy.qos.status = 'pending'
        policy.qos.save()
        if not apply_qos_policy(policy, 'add'):
            policy.qos.status = 'failed'
            policy.qos.save()
            apply_qos_policy(policy, 'delete')
        else:
            policy.qos.status = 'succeeded'
            policy.qos.save()


    sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
    cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
    s, o = sudo_runner(cmd)
    if not s:
        policy.status = 'succeeded'
        policy.save()
        if not is_update:
            log('firewall', 'policy', log_operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(o)})
        return 1  # Successful

    if not is_update:
        log('firewall', 'policy', log_operation, 'success',
            username=request_username, ip=get_client_ip(request), details=changes)

    return 1  # Successful


def check_chain_commands(policy_commands):
    main_chain_s_result = []
    nat_chain_s_result = []
    for chain_command in policy_commands['create_chains']:
        chain_name = [item for item in chain_command.split() if '_id_' in item]
        table_name = ""
        if chain_name:
            chain_name = chain_name[0]
            if 'nat' in chain_name:
                table_name = '-t nat'
        else:
            print_if_debug("The policy has no chain name with standard format(..._id_...)")
            return False

        cmd = 'iptables -w -S {} {}'.format(chain_name, table_name)
        status, result = sudo_runner(cmd)
        if not status:
            print_if_debug("Can't retrieve iptables status for {}".format(chain_name))
            return False
        if 'nat' in chain_command:
            nat_chain_s_result = result.split('\n')
        else:
            main_chain_s_result = result.split('\n')

    for cmd in policy_commands['chain_commands']:
        is_match = False

        # find the name of table!
        re_result = re.search('\s*((?:nat|policy)_id_\d+).+(multiport)?.*', cmd)
        if re_result:

            # find all --dports or --sports and their values
            applied_result = main_chain_s_result
            if re_result.group(1)[:3] == 'nat':
                applied_result = nat_chain_s_result

            cmd_without_port = re.sub('(-m?\s*multiport)?\s*(--(?:dports?|sports?)\s*[\d,-]+)', '', cmd)
            cmd_without_port = cmd_without_port.replace('-t nat', '')
            for ar in applied_result:
                dash_s_result_without_port = re.sub('(-m?\s*multiport)?\s*(--(?:dports?|sports?)\s*[\d,-]+)', '', ar)
                dash_s_result_without_port = dash_s_result_without_port.replace('-N', '')
                dash_s_result_without_port = dash_s_result_without_port.replace('-A', '')

                # Check this two rules are equal
                if is_this_two_iptables_rule_are_equal(dash_s_result_without_port, cmd_without_port):
                    # Check if multi-ports are equal
                    right = {'dport': set(),
                             'sport': set()
                             }
                    left = {'dport': set(),
                            'sport': set()
                            }
                    multi_res = re.findall('multiport\s+--((?:dports?|sports?)\s+[\d,-]+)', cmd)
                    # It is expected that there is just exactly one sport and one dport in a rule!
                    for mr in multi_res:
                        right[mr[:5]] = set(re.sub('{}s?\s+'.format(mr[:5]), '', mr).split(','))

                    multi_res = re.findall('multiport\s+--((?:dports?|sports?)\s+[\d,-]+)', ar)
                    # It is expected that there is just exactly one sport and one dport in a rule!
                    for mr in multi_res:
                        left[mr[:5]] = set(re.sub('{}s?\s+'.format(mr[:5]), '', mr).split(','))

                    # compare two expected and real ports
                    if right['dport'] == left['dport'] and right['sport'] == left['sport']:
                        is_match = True
                        break

            if not is_match:
                print_if_debug("Can't find any match for {}".format(cmd))
                return False
        else:
            cmd = 'iptables -w -C ' + cmd
            status, result = sudo_runner(cmd)
            if not status:
                print_if_debug("The policy is not found running {}".format(cmd))
                return False
    return True


def check_main_table_commands(policy_commands):
    for cmd in policy_commands['main_rule_commands']:
        cmd = 'iptables -w -C FORWARD ' + cmd
        status, result = sudo_runner(cmd)

        if not status:
            return False
    return True


def check_nat_table_commands(policy_commands, nat_chain):
    for cmd in policy_commands['nat_rule_commands']:
        cmd = 'iptables -w -t nat -C ' + nat_chain + cmd
        status, result = sudo_runner(cmd)

        if not status:
            return False
    return True


def is_policy_applied(policy, policy_commands=None):
    if not policy.is_enabled:
        return False
    has_set = True
    if not policy_commands:
        policy_commands = create_policy_commands(policy)

    # TODO check pbr
    nat_chain = "PREROUTING "
    if policy.nat and policy.nat.nat_type == "SNAT":
        nat_chain = "POSTROUTING "

    if not check_chain_commands(policy_commands):
        has_set = False

    elif not check_nat_table_commands(policy_commands, nat_chain):
        has_set = False

    elif not check_main_table_commands(policy_commands):
        has_set = False

    return has_set


def generate_ipset_name(policy_id, direction):
    return "polset_{}_{}".format(policy_id, direction)


def create_ip_ipset(policy_id, ip_list, direction='src'):
    setname = generate_ipset_name(policy_id, direction)
    cmd_to_save = []
    try:
        sudo_runner("ipset -F {}".format(setname))
        sudo_runner("ipset -X {}".format(setname))
        cmd = "ipset -N -exist {} nethash".format(setname)
        cmd_to_save.append(cmd)
        sudo_runner(cmd)

    except Exception as e:
        print("exception!:{}".format(e))
        pass

    for ip in ip_list:
        cmd = "ipset -A -exist {} {}".format(setname, ip)
        cmd_to_save.append(cmd)
        sudo_runner(cmd)

    return cmd_to_save


def remove_ip_ipset(policy_id, direction='src'):
    setname = generate_ipset_name(policy_id, direction)
    sudo_runner("ipset -F {}".format(setname))
    sudo_runner("ipset -X {}".format(setname))


def create_policy_commands(policy):
    policy_pbr_command_list = list()
    policy_forward_main_table_command_list = list()
    policy_nat_table_command_list = list()
    policy_forward_chain_command_list = list()
    policy_nat_chain_command_list = list()
    policy_chain_create_commands_list = list()
    policy_log_command_list = list()
    pbr = False
    nat_type = ''
    nat_map_ip = ''
    nat_map_port = ''
    nat_chain = None
    nat_order = None
    nat_action = None
    nat_to_port = None

    temp_service_list = [model_to_dict(service) for service in policy.source_destination.service_list.all()]

    if policy.pbr and policy.pbr.is_enabled:
        pbr = True

    if policy.nat and policy.nat.is_enabled:
        nat_type = policy.nat.nat_type
        nat_chain = "POSTROUTING" if nat_type == "SNAT" else "PREROUTING"
        nat_map_ip = policy.nat.ip
        nat_map_port = policy.nat.port
        nat_order = policy.nat.next_policy
        nat_action = policy.nat.nat_type
        nat_to_port = ""
        nat_action += " --to "

        if nat_type == "SNAT":  # Port is not supported in SNAT
            nat_map_port = ""

        if nat_map_ip:
            nat_action += nat_map_ip

        if nat_map_port:
            nat_to_port += ":" + nat_map_port
            # Now add this port to all protocols to let it to pass forward policies
            fill_proto = {'tcp': 0, 'udp': 0}
            if not policy.source_destination.service_list:
                policy.source_destination.service_list = None
            new_proto = {}

            for service in policy.source_destination.service_list.all():
                for proto in service.protocol.keys():
                    if proto.lower() not in ["tcp", "udp"]:
                        continue
                    if fill_proto['tcp'] and fill_proto['udp']:
                        break

                    if fill_proto[proto.lower()]:
                        continue
                    fill_proto[proto.lower()] = 1

                    if nat_type == "SNAT":
                        new_port = {'src': [nat_map_port], 'dst': ['natport']}
                    else:
                        new_port = {'src': ['natport'], 'dst': [nat_map_port]}
                    new_proto = {proto: new_port}

            temp_service_list.append({"protocol": new_proto})

        if nat_type == "SNAT" and policy.nat.snat_type == "interface_ip":
            nat_action = nat_map_ip = "MASQUERADE"

        if not nat_map_ip and not nat_map_port:
            nat_type = ""
    action = None
    if policy.action:
        action = policy.action.upper()

    next_policy, head_rule_line = where_should_insert_policy(policy)
    order = -1
    if next_policy is None:
        order = -1  # Next Policy is None
    elif not len(next_policy):
        pass
        # logger.debug("The nextPolicy in addPolicy is empty!")
    if next_policy:
        try:
            (result_policy, calculated_order) = next_policy.popitem()
            order = int(calculated_order)
            if str(result_policy) == str(policy.id):
                if policy.source_destination.user_list or policy.source_destination.group_list:
                    order = -2  # The policy id exists, but it has some user/group set(s), so update it
                else:
                    order = -3  # Can't add two policy with the same id!

        except Exception as e:
            # TODO fix this: ('SourceDestination' object has no attribute 'user_list')
            # logger.error("The nextPolicy is empty (%s)" % (str(e),))
            if head_rule_line:
                order = head_rule_line + 1
            else:
                # logger.error("Can't find dpi_check!!")
                order = 1
    else:
        if head_rule_line:
            order = head_rule_line + 1
        else:
            order = 1

    if nat_type:
        next_policy, head_rule_line = where_should_insert_policy(policy, "nat", nat_chain)
        if next_policy:
            try:
                (result_policy, calculated_order) = next_policy.popitem()
                nat_order = int(calculated_order)
                if str(result_policy) == str(policy.nat.id):
                    if policy.source_destination.user_list or policy.source_destination.group_list:
                        order = -2  # The policy id is exist, but it has some user/group set(s) so update it
                    else:
                        order = -3  # Can't add two policy with the same id!

            except Exception as e:
                # TODO fix this: ('SourceDestination' object has no attribute 'user_list')
                # logger.error("The nextPolicy is empty (%s)" % (str(e),))
                if head_rule_line:
                    nat_order = head_rule_line + 1
                else:
                    # logger.error("Can't find dpi_check!!")
                    nat_order = 1
        else:
            if head_rule_line:
                nat_order = head_rule_line + 1
            else:
                nat_order = 1

    policy_chain_name = "policy_id_" + str(policy.id)
    policy_chain_commands_header = "policy_id_" + str(policy.id) + " "
    main_commands_header = ""  # ""FORWARD " + str(order)
    nat_chain_commands_header = None

    main_nat_commands_header = None
    nat_chain_name = None
    if policy.nat:
        nat_chain_name = "nat_id_" + str(policy.nat.id)
        nat_chain_commands_header = nat_chain_name + " "
        main_nat_commands_header = ""  # nat_chain + " -t nat " + str(nat_order)

    if not order:
        order = -1  # Can't find policy order

    # if policy.nat and policy.nat.is_enabled and policy.nat.ip and not policy.nat.port and \
    #         not policy.source_destination.service_list.all():
    #     protocol_list = get_service_list(policy, temp_service_list, not_ports=True)
    # else:
    protocol_list = get_service_list(policy, temp_service_list, not_ports=False)

    # Delete PBR policies related to this policy and add them again
    # TODO: is it required always????
    # delete_pbr_policy(policy)

    tuns = get_map_tun_interfaces()
    pppoe_map = get_pppoe_interfaces_map()
    if pppoe_map is not None:
        tuns.update(pppoe_map)

    dst_network_list = []
    dst_mac_fqdn_list, dst_ip_list = get_dst_network_list(policy)
    dst_network_list.extend(dst_mac_fqdn_list)

    dst_interfaces_list = get_dst_interface_list(policy, tuns)

    src_network_list = []
    src_mac_fqdn_list, src_ip_list, pbr_commands_list = get_src_network_list(policy, pbr)
    src_network_list.extend(src_mac_fqdn_list)

    if pbr_commands_list:
        policy_pbr_command_list.extend(pbr_commands_list)

    src_interfaces_list = get_src_interface_list(policy, tuns)

    should_ignore_policy = True
    ignore_policy, output = get_user_list(policy)
    if output:
        src_network_list.extend(output)
    if ignore_policy:
        should_ignore_policy = ignore_policy

    ignore_policy, output = get_group_list(policy)
    if output:
        src_network_list.extend(output)
    if ignore_policy:
        should_ignore_policy = ignore_policy

    if should_ignore_policy and not src_network_list \
            and ((hasattr(policy.source_destination, 'user_list') and policy.source_destination.user_list)
                 or
                 (hasattr(policy.source_destination, 'group_list') and policy.source_destination.group_list)):
        # This policy shouldn't be added because the user (as the only source network) is not login yet!
        order = -3  # Firewall policy is going to ignore this rule!

    schedule = get_schedule(policy)
    if policy.action or policy.is_log_enabled:
        policy_chain_create_commands_list.append("-N " + policy_chain_name)
    if policy.nat:
        policy_chain_create_commands_list.append("-t nat -N " + nat_chain_name)

    do_log = False
    if policy.is_log_enabled:
        do_log = True

    policy_chain_commands = []

    for proto in protocol_list:
        if policy.nat and proto['type'] != 'mapped_port':
            policy_chain_commands.append({"rule": nat_chain_commands_header + proto['rule'], "type": "just_for_nat"})
        if proto['type'] != 'just_for_nat':
            policy_chain_commands.append({"rule": policy_chain_commands_header + proto['rule'], "type": "normal"})

    # TODO: these two conditions should be changed?
    if not policy_chain_commands:  # Add action for empty chains
        if policy.nat:
            policy_chain_commands.append({"rule": nat_chain_commands_header, "type": "empty_chain_nat"})
        policy_chain_commands.append({"rule": policy_chain_commands_header, "type": "empty_chain_normal"})
    elif policy_chain_commands[0]["type"] == "just_for_nat" and len(policy_chain_commands) == 1 and policy.nat:
        policy_chain_commands.append({"rule": nat_chain_commands_header, "type": "nat"})

    ipsec_cmd_list = list()
    if policy.is_ipsec:
        ipsec_cmd_list.append(' -m policy --dir in --pol ipsec ')
        ipsec_cmd_list.append(' -m policy --dir out --pol ipsec ')

    geoip_src_cmd = None
    if policy.source_destination.src_geoip_country_list.all():
        geoip_src = ",".join(geoip_src.code for geoip_src in policy.source_destination.src_geoip_country_list.all())
        geoip_src_cmd = ' -m geoip --src-cc ' + geoip_src

    geoip_dst_cmd = None
    if policy.source_destination.dst_geoip_country_list.all():
        geoip_dst = ",".join(geoip_dst.code for geoip_dst in policy.source_destination.dst_geoip_country_list.all())
        geoip_dst_cmd = ' -m geoip --dst-cc ' + geoip_dst

    for pol in policy_chain_commands:
        if geoip_src_cmd:
            pol['rule'] = pol['rule'] + geoip_src_cmd

        if geoip_dst_cmd:
            pol['rule'] = pol['rule'] + geoip_dst_cmd

        if do_log and pol['type'] != "just_for_nat" and pol['type'] != "empty_chain_nat":
            log_condition = " -m state ! --state ESTABLISHED -m conntrack ! --ctstatus CONFIRMED "
            ndpi_log_prefix = ""
            re_result = re.search("-m\s*ndpi\s+--(\S+)", pol['rule'], re.M)
            if re_result and re_result.group(1) in l7_mapper.SERVICES.keys():
                ndpi_log_prefix = ",app:" + str(l7_mapper.SERVICES[re_result.group(1)])
                log_condition = " --dpi_detected "
            action_for_log = policy.action[0] if policy.action else 'n'
            log_statement = '{}{} -j LOG --log-prefix="[f:{}{},{},{}]"' \
                .format(pol['rule'], log_condition, str(policy.id), ndpi_log_prefix, policy.name, action_for_log)

            policy_log_command_list.extend(create_ipsec_commands(log_statement, ipsec_cmd_list))

        if action and pol['type'] != "just_for_nat" and pol['type'] != "empty_chain_nat":
            cmd = pol['rule'] + " -j " + action
            # logger.info("if action and pol['type'] != just_for_nat:" + cmd)
            policy_forward_chain_command_list.extend(create_ipsec_commands(cmd, ipsec_cmd_list))

        if policy.nat and pol['type'] in ["just_for_nat", "empty_chain_nat"]:
            cmd = pol['rule'] + " -j " + nat_action
            if nat_map_port and nat_action != "MASQUERADE":
                if re.match(".*tcp|.*udp", pol['rule']):
                    cmd += nat_to_port
            cmd += " -t nat "
            policy_nat_chain_command_list.append(cmd)

    policy_nat_type = "normal"
    # This if is specially for DNAT. In DNAT it is required to have different rule for main and nat!
    if policy.nat and nat_map_ip and nat_type != "SNAT" and nat_map_ip != "MASQUERADE":
        policy_nat_type = "just_for_nat"

    if dst_ip_list and not any('0.0.0.0' in item for item in dst_ip_list):
        # if there is a DNAT on mapped-IP, don't use dst set in main (forward) chain.
        dst_set_rule = {"net": "-m set --set {} {}".format(generate_ipset_name(policy.id, 'dst'), 'dst'),
                        "type": policy_nat_type}
        dst_network_list.append(dst_set_rule)
        if policy_nat_type != "normal" and policy.nat.nat_type != "SNAT":  # Add a rule to accept the traffics to mapped-ip.
            dst_normal_rule = {"net": "-d {}".format(nat_map_ip), "type": "normal"}
            dst_network_list.append(dst_normal_rule)
    if src_ip_list and not any('0.0.0.0' in item for item in src_ip_list):
        src_ip_rule = {"net": "-m set --set {} {}".format(generate_ipset_name(policy.id, 'src'), 'src'),
                       "type": "normal"}
        src_network_list.append(src_ip_rule)

    if not src_network_list:
        src_network_list.append({"net": "", "type": "normal"})
    if not dst_network_list:
        dst_network_list.append({"net": "", "type": "normal"})
    if not src_interfaces_list:
        src_interfaces_list.append("")
    if not dst_interfaces_list:
        dst_interfaces_list.append("")

    main_table_command = list()
    for src_list in src_network_list:
        for src_int in src_interfaces_list:
            if src_int:
                src_int = " -i " + src_int
            elif nat_type != "SNAT":
                src_int = " ! -i lo"
            for dst_int in dst_interfaces_list:
                if dst_int:
                    dst_int = " -o " + dst_int
                elif nat_type == "SNAT":
                    src_int = " ! -o lo"
                for dst_ip in dst_network_list:
                    policy_type = "normal"
                    if dst_ip['type'] != "normal" or src_list['type'] != "normal":
                        policy_type = "nat"
                    # Add any normal main rule to nat main chain
                    if policy_type == 'normal' and nat_type == "SNAT":
                        main_table_command.append({"rule": "{} {} {} {} {}"
                                                  .format(src_int, src_list['net'], dst_int, dst_ip['net'],
                                                          schedule),
                                                   "type": 'just_for_nat'})

                    main_table_command.append({"rule": "{} {} {} {} {}"
                                              .format(src_int, src_list['net'], dst_int, dst_ip['net'],
                                                      schedule),
                                               "type": policy_type})

    for pol in main_table_command:
        if policy.nat and pol['type'] in ["just_for_nat", "nat"]:
            if (nat_type == "SNAT" and re.search(".*-i.*", pol['rule'])) or \
                    (nat_type == "DNAT" and re.search(".*-o.*", pol['rule'])):
                # TODO: should we prevent these??
                # logger.warning("Wrong nat rule (SNAT with output interface or DNAT with input interface)")
                print_if_debug("Wrong nat rule (SNAT with output interface or DNAT with input interface)")
                continue
            nat_pol = "{} {} -j {}".format(main_nat_commands_header, pol['rule'], nat_chain_name)
            policy_nat_table_command_list.append(nat_pol)

        if (policy.action or policy.is_log_enabled) and pol['type'] != "just_for_nat" and pol[
            'type'] != "empty_chain_nat" and pol['type'] != 'nat':
            pol['rule'] = "{} {} -j {}".format(main_commands_header, pol['rule'], policy_chain_name)
            policy_forward_main_table_command_list.append(pol['rule'])

    # for pol in policy_pbr_command_list:
    #
    #     logger.info(pol)
    #
    #     status, result = run_policy_command(pol)
    #     if status:
    #         is_there_at_least_one_successful_rule = True
    #         is_there_at_least_one_successful_nat_table_rule = True
    #     else:
    #         is_any_rules_applied_successfully = False
    #         errors.append({'command': pol, 'error': str(result)})
    #         # errors = fillErrors(str(result))

    # if not is_there_at_least_one_successful_main_table_rule:  # there is not exist any successful rule, so remove chain!
    #     logger.warning("Can't set any main rules, so trying to remove chain rules")
    #     cmd = "iptables -F " + policy_chain_name
    #     run_policy_command(cmd)
    #     cmd = "iptables -X " + policy_chain_name
    #     run_policy_command(cmd)
    # if nat_type and not is_there_at_least_one_successful_nat_table_rule:
    #     # there is not exist any successful rule, so remove chain!
    #     logger.warning("Can't set any nat rules, so trying to remove chain rules")
    #     cmd = "iptables -t nat -F " + pofree -licy_chain_name
    #     run_policy_command(cmd)
    #     cmd = "iptables -t nat -X " + policy_chain_name
    #     run_policy_command(cmd)

    chain_commands_list = policy_nat_chain_command_list
    chain_commands_list.extend(policy_forward_chain_command_list)
    chain_commands_list.extend(policy_log_command_list)
    # print_if_debug({'pbr_commands': policy_pbr_command_list,
    #                 'create_chains': policy_chain_create_commands_list,
    #                 'chain_commands': chain_commands_list,
    #                 'main_rule_commands': policy_forward_main_table_command_list,
    #                 'nat_rule_commands': policy_nat_table_command_list,
    #                 'dst_ip_list': dst_ip_list,
    #                 'src_ip_list': src_ip_list,
    #                 'main_order': order,
    #                 'nat_order': nat_order})

    return {'pbr_commands': policy_pbr_command_list,
            'create_chains': policy_chain_create_commands_list,
            'chain_commands': chain_commands_list,
            'main_rule_commands': policy_forward_main_table_command_list,
            'nat_rule_commands': policy_nat_table_command_list,
            'dst_ip_list': dst_ip_list,
            'src_ip_list': src_ip_list,
            'main_order': order,
            'nat_order': nat_order}


# def delete_pbr_policy(old_policy):
#     remove_ip_rules_command = []
#
#     if not old_policy.source_destination.src_network_list:
#         return
#
#     for address in old_policy.source_destination.src_network_list.all():
#         if address.type != 'ip':
#             continue
#
#         for value in address.value_list:
#
#             if value.find("-") != -1:  # ip range
#                 # ip range could not set with ip rules
#                 pass
#             else:  # single ip
#                 if old_policy.source_destination.dst_interface_list.count() == 1:
#                     remove_ip_rules_command.append(
#                         "ip rule del from {} lookup {}.out prio {}".format(
#                             value, old_policy.source_destination.dst_interface_list.all()[0].name,
#                             str(FIRST_PRIORITY_NUMBER + int(old_policy['order']))))
#                 else:
#                     pass
#                     logger.error("PBR can set with exactly one output interface.")
#
#     if remove_ip_rules_command:
#         for cmd in remove_ip_rules_command:
#             logger.info(cmd)
#             status, result = sudo_runner(cmd)
#             if not status:
#                 logger.error("Can't remove this rule (%s)" % (cmd,))


def delete_policy(policy,
                  name_prefix='',
                  delete_from_db=False,
                  request_username=None,
                  should_create_notification=False,
                  request=None,
                  changes=None,
                  is_update=False):
    remove_chain_command = []
    remove_rules_command = []
    Notification.objects.filter(source='policy', item={'id': policy.id, 'name': policy.name}).delete()
    remove_chain_command.append('iptables -w -F policy_id_{0}{1}'.format(policy.id, name_prefix))
    remove_chain_command.append('iptables -w -X policy_id_{0}{1}'.format(policy.id, name_prefix))
    is_policy_deleted_from_db = False
    policy_id = policy.id
    policy_name = policy.name
    errors = list()

    try:
        main_policies, chain_policies = find_related_rules_info(str(policy.id) + name_prefix)
        if main_policies:
            main_policies.reverse()
            for info in main_policies:
                remove_rules_command.append('iptables -w -D FORWARD {}'.format(info['line-number']))

        if policy.nat:
            remove_chain_command.append('iptables -w -t nat -F nat_id_{0}{1}'.format(policy.nat.id, name_prefix))
            remove_chain_command.append('iptables -w -t nat -X nat_id_{0}{1}'.format(policy.nat.id, name_prefix))

            nat_chain = 'POSTROUTING' if policy.nat.nat_type == 'SNAT' else 'PREROUTING'
            main_nat_policies, chain_nat_policies = find_related_rules_info(str(policy.nat.id) + name_prefix, None,
                                                                            'nat',
                                                                            nat_chain)

            if main_nat_policies:
                main_nat_policies.reverse()
                for info in main_nat_policies:
                    remove_rules_command.append('iptables -w -t nat -D {0} {1}'.format(nat_chain, info['line-number']))

        # if policy.pbr and policy.pbr.is_enabled:
        #     if name_prefix == '':
        #         # don't do it for update
        #         delete_pbr_policy(policy)



        if remove_rules_command:
            for cmd in remove_rules_command:
                status, result = run_policy_command(cmd)
                if not status:
                    errors.append({'command': cmd, 'error': str(result)})

        if remove_chain_command:
            for cmd in remove_chain_command:
                status, result = run_policy_command(cmd)
                if not status:
                    if 'No chain/target/match by that name' in str(result):
                        print_if_debug('during running {} we got {}'.format(cmd, result))
                    else:
                        errors.append({'command': cmd, 'error': str(result)})

        if not name_prefix:
            remove_related_ipsets_to_policy(policy.id)

        if policy.is_enabled and policy.qos:
            policy.qos.status = 'pending'
            policy.qos.save()
            if not apply_qos_policy(policy, 'delete'):
                policy.qos.status = 'failed'
                policy.qos.save()
                errors.append({'command': '', 'error': 'delete qos policy failed for some reason!'})
            else:
                policy.qos.status = 'succeeded'
                policy.qos.save()


        if delete_from_db:
            policy.delete()
            is_policy_deleted_from_db = True
            if not is_update:
                log('firewall', 'policy', 'delete', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)

        sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
        cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
        s, o = sudo_runner(cmd)
        if not s:
            if not is_update:
                errors.append({'command': cmd, 'error': str(o)})

    except Exception as e:
        if not is_update:
            errors.append({'command': 'In exception!', 'error': str(e)})
        if not is_policy_deleted_from_db:
            policy.status = 'failed'
            policy.save()

    if errors:
        print_if_debug('during removing policy {} we got {}'.format(policy_id, errors))
        if not should_create_notification:
            create_notification(source='policy', item={'id': policy_id, 'name': policy_name},
                                message=str('Error in deleting policy rules'), severity='e',
                                details=errors, request_username=request_username)
        if not is_policy_deleted_from_db:
            policy.status = 'failed'
            policy.save()
        if not is_update:
            log('firewall', 'policy', 'delete', 'fail',
                username=request_username, ip=get_client_ip(request), details=changes)

        return False

    return True


def update_policy(old_policy, new_policy, request_username=None, request=None, changes=None):
    Notification.objects.filter(source='policy', item__id=old_policy.id).delete()

    # delete_pbr_policy(old_policy)
    ret = -1
    delete_policy(
        old_policy, "", delete_from_db=False, request_username=request_username, request=request, is_update=True)
    if new_policy.is_enabled:
        try:
            ret = add_policy(
                new_policy, operation="update", request_username=request_username, request=request, is_update=True)
            if ret > 0:
                new_policy.status = 'succeeded'
                new_policy.save()
            else:
                new_policy.status = 'failed'
                new_policy.save()
        except Exception as e:
            print_if_debug("There is some exception occurred in add during update process: {}".format(str(e)))
            new_policy.status = 'failed'
            new_policy.save()

    return ret
