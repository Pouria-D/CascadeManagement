import os
from time import sleep

from rest_framework import serializers

from api.settings import BACKUP_DIR, POLICY_BACK_POSTFIX
from config_app.models import Setting, HighAvailability
from firewall_input_app.models import InputFirewall, Apply, Source
from parser_utils.mod_policy.policy import create_ip_ipset
from root_runner.sudo_utils import sudo_runner
from utils.utils import run_thread
from vpn_app.models import VPN


def apply_rule(self, request, *args, **kwargs):
    ###########################################################
    https_instace = Setting.objects.get(key='https-port')
    http_instace = Setting.objects.get(key='http-port')
    ssh_instace = Setting.objects.get(key='ssh-port')
    ###########################################################

    try:
        all_input_policy = InputFirewall.objects.all()

    except:
        raise serializers.ValidationError('you must have at least one input policy , Add policy and try again ')
    pass

    create_primary_policy()
    create_default_policy()

    for obj in all_input_policy:

        if obj.is_enabled:

            ip_set = set()
            interface_set = []

            try:
                interface_set = set(src_interface.name for src_interface in obj.source.src_interface_list.all())

                for src_network in obj.source.src_network_list.all():
                    for src in src_network.value_list:
                        ip_set.add(src)

                    if '0.0.0.0/0' in src_network.value_list:
                        ip_set = set()
                        break
            except:
                pass
            create_ip_ipset(obj.id, ip_set, 'inpsrc')

            if interface_set and ip_set:

                for interface in interface_set:
                    if obj.permission == 'admin':
                        for service in obj.service_list:
                            if service == 'cli':
                                s, o = iptables_input_insert(
                                    '   -i {1} -p tcp --dport {0}   -m set --set polset_{2}_inpsrc src -j ACCEPT '.format(
                                        ssh_instace.data["value"], interface, obj.id))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i {1} -p tcp --dport {0}   -m set --set polset_{2}_inpsrc src -j LOG --log-prefix "[f:{2},{3},Input,a]"'.format(
                                            ssh_instace.data["value"], interface, obj.id, obj.name))

                            if service == 'web':

                                iptables_input_insert(
                                    '   -i {1} -p tcp --match multiport --dport {0},{3}   -m set --set polset_{2}_inpsrc src -j ACCEPT '.format(
                                        https_instace.data["value"], interface, obj.id, http_instace.data['value']))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i {1} -p tcp --match multiport --dport {0},{4}  -m set --set polset_{2}_inpsrc src -j LOG --log-prefix "[f:{2},{3},Input,a]"'.format(
                                            https_instace.data["value"], interface, obj.id, obj.name,
                                            http_instace.data['value']))

                            if service == 'ping':

                                s, o = iptables_input_insert(
                                    '   -i {0} -p icmp   -m set --set polset_{1}_inpsrc src -j ACCEPT '.format(
                                        interface, obj.id))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i {0}  -p icmp   -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{1},{2},Input,a]"'.format(
                                            interface, obj.id, obj.name))

                            if service == 'ipsec':
                                iptables_input_insert(
                                    '   -i{0} -p AH  -m set --set polset_{1}_inpsrc src -j ACCEPT'.format(
                                        interface, obj.id))

                                iptables_input_insert(
                                    '   -i{0} -p ESP -m set --set polset_{1}_inpsrc src -j ACCEPT'.format(
                                        interface, obj.id))

                                iptables_input_insert(
                                    '   -i {0} -p udp  --match multiport  --dport 4500,500 -m set --set polset_{1}_inpsrc src -j ACCEPT'.format(
                                        interface, obj.id))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i{0} -p AH  -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{1},{2},Input,a]" '.format(
                                            interface, obj.id, obj.name))

                                    iptables_input_insert(
                                        '   -i{0} -p ESP -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{1},{2},Input,a]" '.format(
                                            interface, obj.id, obj.name))

                                    iptables_input_insert(
                                        '   -i {0} -p udp  --match multiport  --dport 4500,500 -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{1},{2},Input,a]" '.format(
                                            interface, obj.id, obj.name))



                    elif obj.permission == 'system' or obj.permission == 'hidden':
                        iptables_input_insert(
                            '  -p {1} --dport {0} -j ACCEPT'.format(obj.protocol,
                                                                    obj.port))
            elif not interface_set and ip_set:

                if obj.permission == 'admin':
                    for service in obj.service_list:

                        if service == 'cli':
                            s, o = iptables_input_insert(
                                '    -p tcp --dport {0}   -m set --set polset_{1}_inpsrc src -j ACCEPT '.format(
                                    ssh_instace.data["value"], obj.id))

                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p tcp --dport {0}   -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{1},{2},Input,a]"'.format(
                                        ssh_instace.data["value"], obj.id, obj.name))

                        if service == 'web':

                            iptables_input_insert(
                                '    -p tcp --match multiport --dport {0},{2}   -m set --set polset_{1}_inpsrc src -j ACCEPT '.format(
                                    https_instace.data["value"], obj.id, http_instace.data['value']))
                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p tcp --match multiport --dport {0},{3} -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{1},{2},Input,a]"'.format(
                                        https_instace.data["value"], obj.id, obj.name, http_instace.data['value']))

                        if service == 'ping':
                            iptables_input_insert(
                                '   -p icmp   -m set --set polset_{0}_inpsrc src -j ACCEPT '.format(
                                    obj.id))
                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p icmp   -m set --set polset_{0}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]"'.format(
                                        obj.id, obj.name))

                        if service == 'ipsec':
                            iptables_input_insert(
                                '     -p AH  -m set --set polset_{0}_inpsrc src -j ACCEPT'.format(
                                    obj.id))

                            iptables_input_insert(
                                '    -p ESP -m set --set polset_{0}_inpsrc src -j ACCEPT'.format(
                                    obj.id))

                            iptables_input_insert(
                                '    -p udp  --match multiport  --dport 4500,500 -m set --set polset_{0}_inpsrc src -j ACCEPT'.format(
                                    obj.id))

                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p AH  -m set --set polset_{0}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]" '.format(
                                        obj.id, obj.name))

                                iptables_input_insert(
                                    '    -p ESP -m set --set polset_{0}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]" '.format(
                                        obj.id, obj.name))

                                iptables_input_insert(
                                    '    -p udp  --match multiport  --dport 4500,500 -m set --set polset_{0}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]" '.format(
                                        obj.id, obj.name))





                elif obj.permission == 'system' or obj.permission == 'hidden':
                    iptables_input_insert(
                        '  -p {1} --dport {0} -j ACCEPT'.format(obj.protocol, obj.port))





            elif interface_set and not ip_set:

                for interface in interface_set:
                    if obj.permission == 'admin':

                        for service in obj.service_list:

                            if service == 'cli':
                                s, o = iptables_input_insert(
                                    '   -i {1} -p tcp --dport {0}   -j ACCEPT '.format(
                                        ssh_instace.data["value"], interface))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i {1} -p tcp --dport {0}   -j LOG --log-prefix "[f:{2},{3},Input,a]"'.format(
                                            ssh_instace.data["value"], interface, obj.id, obj.name))

                            if service == 'web':
                                s, o = iptables_input_insert(
                                    '   -i {1} -p tcp --match multiport --dport {0},{2}   -j ACCEPT '.format(
                                        https_instace.data["value"], interface, http_instace.data["value"]))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i {1} -p tcp --match multiport --dport {0},{4}   -j LOG --log-prefix "[f:{2},{3},Input,a]"'.format(
                                            https_instace.data["value"], interface, obj.id, obj.name,
                                            http_instace.data['value']))

                            if service == 'ping':
                                iptables_input_insert(
                                    '   -i {0}  -p icmp   -j ACCEPT '.format(
                                        interface))
                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i {0}  -p icmp  -j LOG --log-prefix "[f:{1},{2},Input,a]"'.format(
                                            interface, obj.id, obj.name))

                            if service == 'ipsec':
                                iptables_input_insert(
                                    '   -i{0} -p AH  -j ACCEPT'.format(
                                        interface))

                                iptables_input_insert(
                                    '   -i{0} -p ESP  -j ACCEPT'.format(
                                        interface))

                                iptables_input_insert(
                                    '   -i {0} -p udp  --match multiport  --dport 4500,500 -j ACCEPT'.format(
                                        interface))

                                if (obj.is_log_enabled):
                                    iptables_input_insert(
                                        '   -i{0} -p AH -j LOG --log-prefix "[f:{1},{2},Input,a]" '.format(
                                            interface, obj.id, obj.name))

                                    iptables_input_insert(
                                        '   -i{0} -p ESP  -j LOG --log-prefix "[f:{1},{2},Input,a]" '.format(
                                            interface, obj.id, obj.name))

                                    iptables_input_insert(
                                        '   -i {0} -p udp  --match multiport  --dport 4500,500  -j LOG --log-prefix "[f:{1},{2},Input,a]" '.format(
                                            interface, obj.id, obj.name))




                    elif obj.permission == 'system' or obj.permission == 'hidden':

                        ################this block used for HA to sync DB
                        if 'cli' in obj.service_list:
                            s, o = iptables_input_insert(
                                '   -i {1} -p tcp --dport {0}   -j ACCEPT '.format(
                                    ssh_instace.data["value"], interface))
                        ##################

                        iptables_input_insert(
                            '  -p {1} --dport {0} -j ACCEPT'.format(obj.protocol,
                                                                    obj.port))




            elif not interface_set and not ip_set:

                if obj.permission == 'admin':
                    for service in obj.service_list:
                        if service == 'cli':
                            s, o = iptables_input_insert(
                                '    -p tcp --dport {0}   -j ACCEPT '.format(
                                    ssh_instace.data["value"]))

                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p tcp --dport {0}  -j LOG --log-prefix "[f:{1},{2},Input,a]"'.format(
                                        ssh_instace.data["value"], obj.id, obj.name))

                        if service == 'web':

                            iptables_input_insert(
                                '    -p tcp  --match multiport --dport {0},{1}   -j ACCEPT '.format(
                                    https_instace.data["value"], http_instace.data["value"]))
                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p tcp --match multiport --dport {0},{3}  -j LOG --log-prefix "[f:{1},{2},Input,a]"'.format(
                                        https_instace.data["value"], obj.id, obj.name, http_instace.data['value']))

                        if service == 'ping':

                            iptables_input_insert(
                                '-p icmp   -j ACCEPT ')
                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '     -p icmp   -j LOG --log-prefix "[f:{0},{1},Input,a]"'.format(
                                        obj.id, obj.name))

                        if service == 'ipsec':
                            iptables_input_insert(
                                '    -p AH -j ACCEPT')

                            iptables_input_insert(
                                '    -p ESP -j ACCEPT')

                            iptables_input_insert(
                                '   -p udp  --match multiport  --dport 4500,500 -j ACCEPT')

                            if (obj.is_log_enabled):
                                iptables_input_insert(
                                    '    -p AH  -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]" '.format(
                                        obj.id, obj.name))

                                iptables_input_insert(
                                    '    -p ESP -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]" '.format(
                                        obj.id, obj.name))

                                iptables_input_insert(
                                    '    -p udp  --match multiport  --dport 4500,500 -m set --set polset_{1}_inpsrc src -j LOG --log-prefix "[f:{0},{1},Input,a]" '.format(
                                        obj.id, obj.name))


                elif obj.permission == 'system' or obj.permission == 'hidden':

                    iptables_input_insert(
                        '-p {0} --dport {1} -j ACCEPT'.format(obj.protocol, obj.port))

            obj.status = 'succeeded'
            obj.save()

    sudo_runner('iptables -A INPUT   -j DROP')
    sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
    cmd = 'iptables-save > {}'.format(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
    s, o = sudo_runner(cmd)

    disabled_policy = InputFirewall.objects.filter(status='unapplied')
    disabled_policy.update(status='disabled')

    try:
        apply = Apply.objects.last()
        apply.status = 'succeeded'
        apply.save()
    except:
        pass

    return None


import time


def wait_until(timeout, period=0.25, *args, **kwargs):
    mustend = time.time() + timeout
    while time.time() < mustend:

        try:
            apply = Apply.objects.last()
            if apply.status == 'succeeded':
                return True

        except:
            pass

        time.sleep(period)
    return False


def create_default_policy():
    # dns default on
    # sudo_runner('iptables -I    -p udp --dport 53 -j ACCEPT')
    # sudo_runner('iptables -I    -p tcp --dport 53 -j ACCEPT')
    # sudo_runner('iptables -I    -p tcp --dport 123 -j ACCEPT')
    if not InputFirewall.objects.filter(service_list__contains=['dns']):
        try:
            InputFirewall.objects.create(
                name='dns 2',
                is_log_enabled='False',
                is_enabled='True',
                permission='system',
                protocol='tcp',
                port='53',
                service_list='{dns}')
        except:
            pass

        try:
            InputFirewall.objects.create(
                name='dns 1',
                is_log_enabled='False',
                is_enabled='True',
                permission='system',
                protocol='udp',
                port='53',
                service_list='{dns}')
        except:
            pass

    # for HA
    # iptables_input_insert('INPUT -p tcp --dport 2224  -j ACCEPT ')
    # iptables_input_insert('INPUT -p tcp --dport 3121  -j ACCEPT ')
    # iptables_input_insert('INPUT -p tcp --dport 21064  -j ACCEPT ')
    # iptables_input_insert('INPUT -p udp --dport 5405  -j ACCEPT ')

    try:
        if not InputFirewall.objects.filter(service_list__contains=['cli']):
            source = Source.objects.create()
            InputFirewall.objects.create(
                name='default-cli',
                is_log_enabled='False',
                is_enabled='True',
                permission='admin',
                service_list='{cli}',
                source=source)
    except:
        pass

    try:
        if not InputFirewall.objects.filter(service_list__contains=['web']):
            source = Source.objects.create()
            InputFirewall.objects.create(
                name='default-web',
                is_log_enabled='False',
                is_enabled='True',
                permission='admin',
                service_list='{web}',
                source=source)
    except:
        pass

    try:
        if not InputFirewall.objects.filter(service_list__contains=['ping']):
            source = Source.objects.create()
            InputFirewall.objects.create(
                name='default-ping',
                is_log_enabled='False',
                is_enabled='True',
                permission='admin',
                service_list='{ping}',
                source=source)
    except:
        pass

    if not InputFirewall.objects.filter(service_list__contains=['ipsec']) and VPN.objects.filter(is_enabled=True):
        try:
            source = Source.objects.create()
            InputFirewall.objects.create(
                name='default-ipsec',
                is_log_enabled='False',
                is_enabled='True',
                permission='admin',
                service_list='{ipsec}',
                source=source)

        except:
            pass

    if HighAvailability.objects.filter(is_enabled=True):
        try:
            if not InputFirewall.objects.filter(port__exact='2224'):
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='HA1',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='tcp',
                    port='2224',
                    service_list='{ha}',
                    source=source
                )
        except:
            pass

        try:
            if not InputFirewall.objects.filter(port__exact='3121'):
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='HA2',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='tcp',
                    port='3121',
                    service_list='{ha}',
                    source=source
                )
        except:
            pass

        try:

            if not InputFirewall.objects.filter(port__exact='21064'):
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='HA3',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='tcp',
                    port='21064',
                    service_list='{ha}',
                    source=source
                )
        except:
            pass

        try:
            if not InputFirewall.objects.filter(port__exact='5405'):
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='HA4',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='udp',
                    port='5405',
                    service_list='{ha}',
                    source=source
                )
        except:
            pass


def create_primary_policy():
    sudo_runner('iptables -F INPUT')  # todo should remove
    sudo_runner('sudo iptables -I  INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
    sudo_runner('iptables -I INPUT 2 -i lo -j ACCEPT')
    try:
        apply = Apply.objects.last()

        if apply.is_log_enabled:
            import datetime
            now = datetime.datetime.utcnow()
            run_thread(target=delete_drop_log_polices, name='delete_drop_log_polices',
                       args=(apply.time * 60, apply.id,))
            s, o = sudo_runner(
                'iptables -I INPUT 3 -m time --timestart {0}:{1}  --timestop {3}:{2} -j LOG --log-prefix "[f:{4},DropLog,Input,d]"'.format(
                    now.hour, now.minute, (int(now.minute) + int(apply.time)) % 60,
                                          now.hour + int((int(now.minute) + int(apply.time)) / 60), apply.id))

            print(o)
    except:
        pass

def iptables_input_insert(cmd):
    check_cmd = 'iptables -w -C INPUT {}'.format(cmd)
    status, result = sudo_runner(check_cmd)

    if not status:
        return sudo_runner('iptables -w -I INPUT 3 {}'.format(cmd))

    return True, ""


def delete_drop_log_polices(time, apply):
    sleep(time)
    if Apply.objects.filter(id=apply):
        Apply.objects.filter(id=apply).delete()
        s, o = sudo_runner("sudo iptables -nvL INPUT  --line-numbers | grep 'f:{},DropLog'  | cut -c1-9".format(apply))
        if o:
            sudo_runner('sudo iptables -D INPUT {}'.format(o))
