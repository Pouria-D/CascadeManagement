import re

from firewall_app.models import Policy
from root_runner.sudo_utils import sudo_runner
from utils.utils import print_if_debug

DEFAULT_CLASS_ID = 9999
DOWNLOAD_IFB = 'ifb0'
NUM_IFBS = 20
LAN_HTB_ROOT_ID = 1111 # this used for the trick that documented in senario.md
UDP_PROTO_NUM = 17
TCP_PROTO_NUM = 6
MIN_CLASS_ID = 2
MAX_CLASS_ID = 9998
LEAST_TRAFFIC_PRIORITY = 7
IFB_BANDWIDTH = 10000000 #we consider a very big number for ifb bandwidth and use what admin enters for validating policies

def config_ifb_module():
    is_any_rules_applied_successfully = True
    status, result = sudo_runner('lsmod | grep ifb')
    if not status:
        cmd = 'modprobe ifb numifbs={}'.format(NUM_IFBS)
        status, result = sudo_runner(cmd)
        if status:
            print_if_debug('Qos: {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
            is_any_rules_applied_successfully = False
    return is_any_rules_applied_successfully


def up_ifb_link(ifb_name):
    is_any_rules_applied_successfully = True
    cmd = 'ip link set dev {} up'.format(ifb_name)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('QOS: {}'.format(cmd))
        cmd = 'ifconfig {} up'.format(ifb_name)
        s, o = sudo_runner(cmd)
        if s:
            print_if_debug('QOS: {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
            is_any_rules_applied_successfully = False
    else:
        print_if_debug('Qos: fail to run : {}'.format(cmd))
        is_any_rules_applied_successfully = False
    return is_any_rules_applied_successfully


def config_root_interface_class(interface_name, bandwidth, action):
    is_any_rules_applied_successfully = True
    if action == 'add':
        cmd = 'tc qdisc add dev {dev} root handle 1:0 htb default {id}'.format(dev=interface_name, id=DEFAULT_CLASS_ID)
        status, result = sudo_runner(cmd)
        if status:
            print_if_debug('Qos: {}'.format(cmd))
            cmd = 'tc class add dev {dev} parent 1:0 classid 1:1 htb rate {bw}kbps ceil {bw}kbps prio 1' \
                .format(dev=interface_name, bw=bandwidth)
            s, o = sudo_runner(cmd)
            if s:
                print_if_debug('Qos: {}'.format(cmd))
            else:
                print_if_debug('Qos: fail to run : {}'.format(cmd))
                is_any_rules_applied_successfully = False
    elif action == 'update':
        cmd = 'tc class change dev {dev} parent 1:0 classid 1:1 htb rate {bw}kbps ceil {bw}kbps prio 1' \
            .format(dev=interface_name, bw=bandwidth)
        s, o = sudo_runner(cmd)
        if s:
            print_if_debug('Qos: {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
            is_any_rules_applied_successfully = False
    elif action == 'delete':
        cmd = 'tc qdisc del dev {} root handle 1:0'.format(interface_name)
        s, o = sudo_runner(cmd)
        if s:
            print_if_debug('Qos: {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
            is_any_rules_applied_successfully = False
    return is_any_rules_applied_successfully


def mark_for_incoming_interface(interface_name, mark, action):
    from config_app.utils import iptables_insert

    mark_in_iptables = int(mark) + 1  # because interface names start from ETH0 -> we need the plus one
    if action == 'add':
        cmd = 'FORWARD -i {dev} -j MARK --set-mark {mark} -t mangle'.format(dev=interface_name, mark=mark_in_iptables)
        s, r = iptables_insert(cmd)
        if s:
            print_if_debug('Qos: iptables -A {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : iptables -A {}'.format(cmd))
    elif action == 'delete':
        cmd = 'iptables -w -t mangle -D FORWARD -i {dev} -j MARK --set-mark {mark}'.format(dev=interface_name,
                                                                                           mark=mark_in_iptables)
        s, o = sudo_runner(cmd)
        if s:
            print_if_debug('Qos: {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
    return None


def sw_prio(argument):
    switcher = {
        "high" :'1',
        "medium" :'2',
        "low" :'3',
        "default": '7'
    }
    return switcher.get(argument)


def add_tc_class(interface_name, class_id, rate, ceil, priority, shape_type='per_session'):
    is_any_rules_applied_successfully = True
    prio = sw_prio(priority)
    if ceil > 0:
        cmd = 'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}'\
            .format(dev=interface_name, id=class_id, rate=rate, ceil=ceil, priority=prio)
    else:
        cmd = 'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps prio {priority}'\
            .format(dev=interface_name, id=class_id, rate=rate, priority=prio)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
        cmd1 = 'tc qdisc add dev {dev} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
            dev=interface_name, id=class_id)
        s, o = sudo_runner(cmd1)
        if s:
            print_if_debug('Qos: {}'.format(cmd1))
            if shape_type == 'per_ip':
                cmd2 = 'tc filter add dev {dev} parent {id}: handle {id} flow hash keys dst divisor 1024' \
                    .format(dev=interface_name, id=class_id)
                st, re = sudo_runner(cmd2)
                if st:
                    print_if_debug('Qos: {}'.format(cmd2))
                else:
                    print_if_debug('Qos: fail to run : {}'.format(cmd2))
                    is_any_rules_applied_successfully = False
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd1))
            is_any_rules_applied_successfully = False
    else:
        print_if_debug('Qos: fail to run : {}'.format(cmd))
        is_any_rules_applied_successfully = False
    return is_any_rules_applied_successfully


def update_tc_class(interface_name, class_id, rate, ceil, priority):
    prio = sw_prio(priority)
    updated_successfully = False
    cmd = 'tc class change dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio {priority}'\
        .format(dev=interface_name, id=class_id, rate=rate, ceil=ceil, priority=prio)
    s, o = sudo_runner(cmd)
    if s:
        print_if_debug('Qos: {}'.format(cmd))
        updated_successfully = True
    else:
        print_if_debug('Qos: fail to run: {}'.format(cmd))
    return updated_successfully


def check_interface_qdisc_existance(interface_name):
    cmd = 'tc qdisc show dev {}'.format(interface_name)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
        if 'htb' in result:
            return True
    return False


def convert_to_kbps(bandwidth, unit):
    res = bandwidth
    unit = unit.lower()
    if 'bit' in unit:
        res = bandwidth/8
    if unit.startswith('b'):
        res = res/1000
    elif unit.startswith('m'):
        res = res*1000
    elif unit.startswith('g'):
        res = res*1000000
    elif unit.startswith('t'):
        res = res*1000000000
    return res


def check_root_class_bandwidth(interface):
    import re
    cmd = 'tc class show dev {}'.format(interface.name)
    status, result = sudo_runner(cmd)
    if status:
        tmp = re.search('\w*\s*class\s*htb\s*1:1\s*root\s*rate\s*(\d*)(\S*)', result, re.M)
        if tmp and tmp.group(1) and tmp.group(2):
            bw = tmp.group(1)
            bw_unit = tmp.group(2)
            if convert_to_kbps(int(bw), bw_unit) == interface.upload_bandwidth:
                return True
    return False

def check_interface_upload_tree(interface):
    cmd = 'tc class show dev {}'.format(interface.name)
    status, result = sudo_runner(cmd)
    if status:
        if 'class htb 1:1 root' not in result:
            delete_interface_qdisc(interface.name)
            config_interface_upload_bandwidth(interface, False)
        elif 'class htb 1:9999 parent 1:1' not in result:
            add_tc_class(interface.name, DEFAULT_CLASS_ID, interface.upload_bandwidth, interface.upload_bandwidth, 'default')
    else:
        config_interface_upload_bandwidth(interface, False)

def check_ifb_download_tree():
    cmd = 'tc class show dev {}'.format(DOWNLOAD_IFB)
    status, result = sudo_runner(cmd)
    if status:
        if 'class htb 1:1 root' not in result or 'class htb 1:9999 parent 1:1' not in result:
            delete_interface_qdisc(DOWNLOAD_IFB)
            config_ifb_bandwidth()
    else:
        config_ifb_module()
        up_ifb_link(DOWNLOAD_IFB)
        config_ifb_bandwidth()


def redirect_lan_traffic_to_ifb_filter(interface_name):
    is_any_rules_applied_successfully = True
    cmd = 'tc qdisc show dev {}'.format(interface_name)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
        if 'qdisc htb {}: root'.format(LAN_HTB_ROOT_ID) not in result:
            cmd = 'tc qdisc add dev {} root handle {}: htb'.format(interface_name, LAN_HTB_ROOT_ID)
            status, result = sudo_runner(cmd)
            if status:
                print_if_debug('Qos: {}'.format(cmd))
            if not status:
                print_if_debug('Qos: fail to run: {}'.format(cmd))
                is_any_rules_applied_successfully = False
    else:
        print_if_debug('Qos: fail to run: {}'.format(cmd))

    cmd = 'tc filter show dev {}'.format(interface_name)
    status, result = sudo_runner(cmd)
    if status:
        if '(Egress Redirect to device ifb0)' not in result:
            cmd = 'tc filter add dev {} parent {}: protocol ip u32 match u32 0 0 action mirred egress redirect dev {}' \
                .format(interface_name, LAN_HTB_ROOT_ID, DOWNLOAD_IFB)
            s, o = sudo_runner(cmd)
            if s:
                print_if_debug('Qos: {}'.format(cmd))
            else:
                print_if_debug('Qos: fail to run: {}'.format(cmd))
                is_any_rules_applied_successfully = False
    else:
        print_if_debug('Qos: fail to run: {}'.format(cmd))
        is_any_rules_applied_successfully = False

    return is_any_rules_applied_successfully


def delete_redirect_lan_traffic_to_ifb_filter(interface_name):
    cmd = 'tc qdisc del dev {} root handle {}:'.format(interface_name, LAN_HTB_ROOT_ID)
    s, o = sudo_runner(cmd)
    if s:
        print_if_debug('Qos: {}'.format(cmd))
    return None


def create_service_match(service_list , service_type):
    src_srv_match_list = []
    dst_srv_match_list = []
    service_match_list = []
    if service_type == 'tcp':
        proto_num = TCP_PROTO_NUM
    elif service_type == 'udp':
        proto_num = UDP_PROTO_NUM
    else:
        return None

    for service in service_list:
        if service['source_destination__service_list__protocol'] and \
                service_type in service['source_destination__service_list__protocol'] and \
                service['source_destination__service_list__protocol'][service_type]:
            if 'src' in service['source_destination__service_list__protocol'][service_type] and \
                    service['source_destination__service_list__protocol'][service_type]['src']:
                for src in service['source_destination__service_list__protocol'][service_type]['src']:
                    src_srv_match_list.append(
                        'match ip protocol {} 0xff match ip sport {} 0xffff'.format(proto_num, src))

            if 'dst' in service['source_destination__service_list__protocol'][service_type] and \
                    service['source_destination__service_list__protocol'][service_type]['dst']:
                for dst in service['source_destination__service_list__protocol'][service_type]['dst']:
                    dst_srv_match_list.append(
                        'match ip protocol {} 0xff match ip dport {} 0xffff'.format(proto_num, dst))

    if src_srv_match_list and dst_srv_match_list:
        for src in src_srv_match_list:
            for dst in dst_srv_match_list:
                service_match_list.append('{} {}'.format(src, dst))
    elif dst_srv_match_list:
        service_match_list = dst_srv_match_list
    elif src_srv_match_list:
        service_match_list = src_srv_match_list
    return service_match_list


def create_filter_match(policy):
    udp_match_list = []
    tcp_match_list = []
    src_net_match_list = []
    dst_net_match_list = []

    if policy.values('source_destination__service_list__protocol'):
        service_list = policy.values('source_destination__service_list__protocol')
        udp_match_list = create_service_match(service_list, 'udp')
        tcp_match_list = create_service_match(service_list, 'tcp')

    src_net_list = policy.values('source_destination__src_network_list__value_list')
    for src_net in src_net_list:
        if src_net['source_destination__src_network_list__value_list']:
            for value in src_net['source_destination__src_network_list__value_list']:
                src_net_match_list.append('match ip src {}'.format(value.strip()))
        else:
            src_net_match_list.append('match ip src any')
            break

    dst_net_list = policy.values('source_destination__dst_network_list__value_list')
    for dst_net in dst_net_list:
        if dst_net['source_destination__dst_network_list__value_list']:
            for value in dst_net['source_destination__dst_network_list__value_list']:
                dst_net_match_list.append('match ip dst {}'.format(value.strip()))
        else:
            dst_net_match_list.append('match ip dst any')
            break

    net_match_list = []
    for src in src_net_match_list:
        for dst in dst_net_match_list:
            net_match_list.append('{} {}'.format(src,dst))

    match_list = []
    if udp_match_list and udp_match_list.__len__():
        for net in net_match_list:
            for srv in udp_match_list:
                match_list.append('{} {}'.format(net, srv))
    if tcp_match_list and tcp_match_list.__len__():
        for net in net_match_list:
            for srv in tcp_match_list:
                match_list.append('{} {}'.format(net, srv))
    if not udp_match_list.__len__() and not tcp_match_list.__len__():
        match_list = net_match_list
    return match_list


def add_tc_filter(interface_name, priority, policy, interface_num, class_id):
    mark = int(interface_num) + 1
    cmd = 'sh -c \''
    match_list = create_filter_match(policy)
    for match in match_list:
        cmd += 'tc filter add dev {interface} protocol ip parent 1:0 prio {prio} u32 {criteria} match mark {interface_mark} 0xffff flowid 1:{class_id} && ' \
            .format(interface=interface_name, prio=priority, criteria=match, interface_mark=mark, class_id=class_id)
    if cmd.strip().endswith('&&'):
        cmd = cmd.strip()[:-3] + '\''
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
    else:
        print_if_debug('Qos: fail to run: {}'.format(cmd))
    return status


def del_tc_filter(interface_name, priority):
    cmd = 'tc filter del dev {interface} protocol ip parent 1:0 prio {prio}'\
        .format(interface=interface_name, prio=priority)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
    else:
        print_if_debug('Qos: fail to run: {}'.format(cmd))
    return status


def del_tc_class(interface_name, class_id):
    cmd = 'tc class del dev {} parent 1:1 classid 1:{}'.format(interface_name, class_id)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
    else:
        print_if_debug('Qos: fail to run: {}'.format(cmd))
    return status


def find_tc_filter_priority(interface_name, class_id):
    cmd = 'tc filter show dev {}'.format(interface_name)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
        for line in result.splitlines():
            if line.__contains__('flowid 1:{}'.format(class_id)):
                reg = re.search(r'.*pref\s*(\d*)\s*', line, re.M)
                if reg:
                    return reg.group(1)
    return None


def config_ifb_bandwidth():
    configed_successfully = False
    cmd = 'tc qdisc add dev {dev} root handle 1:0 htb default {id}'.format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID)
    status, result = sudo_runner(cmd)
    if status:
        print_if_debug('Qos: {}'.format(cmd))
        cmd = 'tc class add dev {dev} parent 1:0 classid 1:1 htb rate {bw}kbps ceil {bw}kbps prio 1' \
            .format(dev=DOWNLOAD_IFB, bw=IFB_BANDWIDTH)
        s, o = sudo_runner(cmd)
        if s:
            print_if_debug('Qos: {}'.format(cmd))
            cmd = 'tc class add dev {dev} parent 1:1 classid 1:{id} htb rate {rate}kbps ceil {ceil}kbps prio 7' \
                .format(dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID, rate=IFB_BANDWIDTH, ceil=IFB_BANDWIDTH)
            status, result = sudo_runner(cmd)
            if status:
                print_if_debug('Qos: {}'.format(cmd))
                cmd = 'tc qdisc add dev {dev} parent 1:{id} handle {id}: sfq perturb 10 divisor 1024'.format(
                    dev=DOWNLOAD_IFB, id=DEFAULT_CLASS_ID)
                s, o = sudo_runner(cmd)
                if s:
                    print_if_debug('Qos: {}'.format(cmd))
                    configed_successfully = True
                else:
                    print_if_debug('Qos: fail to run : {}'.format(cmd))
            else:
                print_if_debug('Qos: fail to run : {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
    return configed_successfully


def delete_interface_qdisc(interface_name):
    cmd = 'tc qdisc show dev {dev}'.format(dev=interface_name)
    status, result = sudo_runner(cmd)
    if 'qdisc htb' in result:
        cmd = 'tc qdisc del dev {dev} root'.format(dev=interface_name)
        status, result = sudo_runner(cmd)
        if status:
            print_if_debug('Qos: {}'.format(cmd))
        else:
            print_if_debug('Qos: fail to run : {}'.format(cmd))
            return False
    return True


def config_interface_upload_bandwidth(interface, interface_already_has_qdisc):
    configed_successfully = False
    if interface.type == 'WAN':
        if not interface_already_has_qdisc:
            if config_root_interface_class(interface.name, interface.upload_bandwidth, 'add'):
                if add_tc_class(interface.name, DEFAULT_CLASS_ID, interface.upload_bandwidth, interface.upload_bandwidth, 'default'):
                    configed_successfully = True
        else:
            if config_root_interface_class(interface.name, interface.upload_bandwidth, 'update'):
                if update_tc_class(interface.name, DEFAULT_CLASS_ID, interface.upload_bandwidth, interface.upload_bandwidth, 'default'):
                    configed_successfully = True
    return configed_successfully


def apply_qos_policy(policy, action):
    dl_rate = policy.qos.download_guaranteed_bw if policy.qos.download_guaranteed_bw else 0
    dl_ceil = policy.qos.download_max_bw if policy.qos.download_max_bw else 0
    dl_prio = policy.qos.traffic_priority
    class_id = policy.qos.class_id
    shape_type = policy.qos.shape_type

    is_any_rules_applied_successfully = True

    policy_list = Policy.objects.filter(qos_id__isnull=False, is_enabled=True)
    sorted_policy_id_list = sort_qos_policy_list(policy_list)
    if action == 'add':
        status = add_tc_class(DOWNLOAD_IFB, class_id, dl_rate, dl_ceil, dl_prio, shape_type)
        apply_tc_filters(DOWNLOAD_IFB, policy_list, sorted_policy_id_list)
        if not status:
            is_any_rules_applied_successfully = False
    elif action == 'delete':
        if delete_tc_filter(DOWNLOAD_IFB, policy):
            status = del_tc_class(DOWNLOAD_IFB, class_id)
            if not status:
                    is_any_rules_applied_successfully = False
        else:
            is_any_rules_applied_successfully = False

    return is_any_rules_applied_successfully


def sort_qos_policy_list(policy_list):
    sorted_list = []
    for policy in policy_list:
        policy_id = policy.id
        next_policy_id = policy.next_policy_id
        if not sorted_list:
            sorted_list.append(policy_id)
            if not next_policy_id:
                sorted_list.append(0) # to specify this is the last policy in list
            else:
                sorted_list.append(next_policy_id)
        else:
            if not next_policy_id:
                if not policy_id in sorted_list:
                    sorted_list.append(policy_id)
                sorted_list.append(0)
            elif next_policy_id in sorted_list:
                if not policy_id in sorted_list:
                    pos = sorted_list.index(next_policy_id)
                    sorted_list.insert(pos, policy_id)
            else:
                if 0 in sorted_list:
                    pos = sorted_list.index(0)
                    sorted_list.insert(pos-1, policy_id)
                    sorted_list.insert(pos, next_policy_id)
                else:
                    if policy_id in sorted_list:
                        pos = sorted_list.index(policy_id) + 1
                        sorted_list.insert(pos, next_policy_id)
                    else:
                        sorted_list.append(policy_id)
                        sorted_list.append(next_policy_id)
    if sorted_list.__contains__(0):
        sorted_list.remove(0)
    return sorted_list


def delete_tc_filter(interface_name, policy):
    is_any_rules_applied_successfully = True
    filter_prio = find_tc_filter_priority(interface_name, policy.qos.class_id)
    if filter_prio:
        status = del_tc_filter(interface_name, filter_prio)
        if not status:
            is_any_rules_applied_successfully = False
    return is_any_rules_applied_successfully


def apply_tc_filters(interface_name, policy_list, sorted_policy_id_list):
    is_any_rules_applied_successfully = True
    cmd = 'tc filter del dev {}'.format(interface_name)
    s, o = sudo_runner(cmd)
    if s:
        print_if_debug('Qos: removing all filters -> {}'.format(cmd))

        for policy_id in sorted_policy_id_list:
            policy = policy_list.filter(id=policy_id)
            if policy:
                class_id = policy.values('qos__class_id')[0]['qos__class_id']

                for interface in policy.values('source_destination__dst_interface_list'):
                    interface_id = interface['source_destination__dst_interface_list']
                    interface_num = re.findall(r'\d+', interface_id)[0]
                    status = add_tc_filter(interface_name, sorted_policy_id_list.index(policy_id) + 1, policy,
                                           interface_num, class_id)
                    if not status:
                        is_any_rules_applied_successfully = False
    else:
        print_if_debug('Qos: fail to run: removing all filters -> {}'.format(cmd))
        is_any_rules_applied_successfully = False

    return is_any_rules_applied_successfully