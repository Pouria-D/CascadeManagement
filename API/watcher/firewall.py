import os
from time import sleep

from rest_framework import serializers

from api.settings import BACKUP_DIR, POLICY_BACK_POSTFIX
from config_app.models import Setting, HighAvailability, Snmp, NTPConfig, DHCPServerConfig
from config_app.utils import check_and_ignore_our_ports_from_nat, iptables_insert, iptables_append
from firewall_input_app.models import InputFirewall, Source
from firewall_input_app.utils import iptables_input_insert, apply_rule
from parser_utils.mod_policy.policy import is_policy_applied, update_policy
from root_runner.sudo_utils import sudo_runner
from utils.log import watcher_log
from utils.utils import get_thread_status, run_thread, print_if_debug
from vpn_app.models import VPN
from watcher.base import AbstractWatcher


class FirewallWatcher(AbstractWatcher):
    def check_pending_policies(self, pending_interval):
        from firewall_app.models import Policy
        while True:
            policy_list = Policy.objects.filter(status='pending')
            for policy in policy_list:
                print_if_debug("....................we found some pending policy")
                if not get_thread_status("policy_{}".format(policy.id)):
                    print_if_debug("....................It terminated unexpec...")
                    if is_policy_applied(policy):
                        print_if_debug("Trying to set succeeded")
                        policy.status = "succeeded"
                    else:
                        print_if_debug("Trying to set failed")
                        policy.status = "failed"
                    policy.save()
                    watcher_log('Policy', policy.name)
            sleep(pending_interval)

    def run(self, interval, pending_interval):
        from firewall_app.models import Policy
        from parser_utils.mod_policy.policy import add_policy

        cmd = 'iptables -S FORWARD'
        status, iptables_content = sudo_runner(cmd)
        if status and 'policy_id_' not in iptables_content:  # if there is no policy in iptables (The boot-up time)
            # Create all require ipsets
            sudo_runner('for file in {}/policy_*_ipsets*; do bash "$file"; done'.format(
                os.path.join(BACKUP_DIR, POLICY_BACK_POSTFIX)))
            if os.path.exists(os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX))):
                cmd = 'iptables-restore {}'.format(
                    os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX)))
                sudo_runner(cmd)

        run_thread(target=self.check_pending_policies, name="firewall_watcher", args=(pending_interval,))

        while True:
            try:
                self.allow_input_rules()
                self.set_default_action_iptables("INPUT", "ACCEPT")
                self.set_default_action_iptables("OUTPUT", "ACCEPT")
                self.set_default_action_iptables("FORWARD", "DROP")
                self.allow_head_rules_iptables()
                self.allow_tail_rules_iptables()
            except Exception as e:
                print_if_debug("There is some exception in firewall watcher:{}".format(e))

            try:
                self.add_prevention_rules()
                self.ignore_our_ports_from_nat_tables()
            except Exception as e:
                print_if_debug("There is some exception in firewall watcher(prevention_rule):{}".format(e))

            # self.allow_input_established_iptables()
            # self.set_end_rule_input()

            cmd = 'iptables -S'
            status, iptables_content = sudo_runner(cmd)

            cmd = 'iptables -S -t nat'
            nat_status, nat_iptables_content = sudo_runner(cmd)

            policies = Policy.objects.filter(is_enabled=True)

            for policy in policies:
                if policy.last_operation == "delete":
                    continue
                if not policy.is_enabled:
                    continue

                # TODO: check if it is user or group policy
                if ('policy_id_{}'.format(policy.id) not in iptables_content and
                        ((policy.nat and 'nat_id_{}'.format(
                            policy.nat.id) not in nat_iptables_content) or not policy.nat)
                        and policy.status != "pending"):
                    # print("Trying to add_policy!.....")
                    try:
                        policy.status = 'pending'
                        policy.save()
                        ret = add_policy(policy, "add")
                        if ret > 0:
                            policy.status = 'succeeded'
                            policy.save()
                        else:
                            policy.status = 'failed'
                            policy.save()
                        watcher_log('Policy', policy.name)
                    except Exception as e:
                        print_if_debug("There is some exception occurred in firewall watcher: {}".format(str(e)))
                        policy.status = 'failed'
                        policy.save()
                elif not is_policy_applied(policy) and policy.status != "pending":
                    print_if_debug("is_policy_applied is not ok!, trying to update it")
                    try:
                        policy.status = 'pending'
                        policy.save()
                        ret = update_policy(policy, policy)
                        if ret > 0:
                            policy.status = 'succeeded'
                            policy.save()
                        else:
                            policy.status = 'failed'
                            policy.save()
                        watcher_log('Policy', policy.name)
                    except Exception as e:
                        print_if_debug("There is some exception occurred in firewall watcher2: %s".format(str(e)))
                        policy.status = 'failed'
                        policy.save()
                    # else:
                    #     print("is_policy_applied is ok! and state is: {}".format(policy.status))

            sleep(interval)

    def allow_head_rules_iptables(self):
        chain = "head_rules"

        cmd = "iptables -w -N " + chain
        sudo_runner(cmd)

        iptables_insert("FORWARD -j {}".format(chain))
        iptables_insert("{} -m state --state established,related -j ACCEPT".format(chain))
        # iptables_insert("{} -mndpi --google".format(chain))

    def allow_tail_rules_iptables(self):
        chain = "tail_rules"

        cmd = "iptables -w -N " + chain
        sudo_runner(cmd)

        iptables_append("FORWARD -j {}".format(chain))
        iptables_insert("{} -m state --state established,related -j ACCEPT".format(chain))
        # iptables_insert("{} -mndpi --google".format(chain))

    def add_prevention_rules(self):
        """
        This function will add some policy rules to log spoof attacks
        This function is added base on Firewall Protection Profile requirements
        :return:
        """
        chain = "protection_rules"

        is_protection_log_enabled = Setting.objects.get(key="protection-log").data['value']

        if is_protection_log_enabled:
            sudo_runner("iptables -w -N {}".format(chain))
            iptables_append('FORWARD -j {}'.format(chain))
            # TODO add this ips to ipset
            iptables_append(
                '{} -s 169.254.0.0/16 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -s 169.254.0.0/16 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -s 127.0.0.0/8 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -s 224.0.0.0/4 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -d 224.0.0.0/4 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -s 240.0.0.0/5 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -d 240.0.0.0/5 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -s 0.0.0.0/8 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -d 0.0.0.0/8 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -d 239.255.255.0/24 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))
            iptables_append(
                '{} -d 255.255.255.255 -j LOG --log-prefix "[log:fw_policy:spoof,d]"'.format(chain))

            iptables_append('{} -p tcp ! --syn -m conntrack --ctstate NEW '
                            '-j LOG --log-prefix "[log:fw_policy:badsyn,d]"'.format(chain))
            iptables_append('{} -p tcp ! --syn -m conntrack --ctstate NEW -j DROP'.format(chain))

            iptables_append('{} --fragment -p ICMP -j LOG'
                            ' --log-prefix "[log:fw_policy:fragmentedICMP,d]"'.format(chain))
            iptables_append('{} --fragment -p ICMP -j DROP'.format(chain))

    #
    #  Ignore system ports such as 80, 22, ...
    #
    def ignore_our_ports_from_nat_tables(self):
        check_and_ignore_our_ports_from_nat()

    def allow_input_established_iptables(self):
        iptables_append("INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    def set_default_action_iptables(self, chain, action):
        cmd = "iptables -w -P {chain} {action}".format(chain=chain, action=action)
        s, o = sudo_runner(cmd)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t add firewall default actions!'})

    def allow_input_rules(self):

        iptables_input_insert('-i lo -j ACCEPT')

        if not InputFirewall.objects.filter(service_list__contains=['ssh']):
            iptables_input_insert('-p tcp --dport {} -j ACCEPT'.format(
                Setting.objects.get(key='ssh-port').data['value']))
        if not InputFirewall.objects.filter(service_list__contains=['https']):
            iptables_input_insert(' -p tcp --match multiport --dport {1},{0} -j ACCEPT'.format(
                Setting.objects.get(key='http-port').data['value'],
                Setting.objects.get(key='https-port').data['value']))

        if not InputFirewall.objects.filter(service_list__contains=['ping']):
            iptables_input_insert(' -p icmp -j ACCEPT')

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

            apply_rule(None, None)


        # if HA enable
        if HighAvailability.objects.filter(is_enabled=True) and InputFirewall.objects.filter(port=2224).exists():
            iptables_input_insert(' -p tcp --dport 2224  -j ACCEPT ')
            iptables_input_insert(' -p tcp --dport 3121  -j ACCEPT ')
            iptables_input_insert(' -p tcp --dport 21064  -j ACCEPT ')
            iptables_input_insert(' -p udp --dport 5405  -j ACCEPT ')

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
            apply_rule(None, None)

        if not InputFirewall.objects.filter(service_list__contains=['snmp']) and Snmp.objects.filter(is_enabled=True):
            try:
                InputFirewall.objects.create(
                    name='snmp',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='udp',
                    port='161',
                    service_list='{snmp}')
            except:
                pass

            apply_rule(None, None)

        if not InputFirewall.objects.filter(service_list__contains=['ntp']) and NTPConfig.objects.filter(
                is_enabled=True):
            try:

                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='ntp',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='tcp',
                    port='123',
                    service_list='{ntp}',
                    source=source
                )
            except:
                pass
            apply_rule(None, None)

        if not InputFirewall.objects.filter(service_list__contains=['dhcp']) and DHCPServerConfig.objects.filter(
                is_enabled=True):

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



    def set_end_rule_input(self):
        iptables_append('INPUT -j DROP')
