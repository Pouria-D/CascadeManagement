# class PolicyWatcherTest(APITransactionTestCase):
#
#     def setUp(self):
#         pass
#
#     def tearDown(self):
#         pass
#
#     def check_iptables_rule(self, cmd):
#         check_cmd = 'iptables -w -C {}'.format(cmd)
#         status, result = sudo_runner(check_cmd)
#
#         if not status:
#             return False
#         return True
#
#     def test_protection_log_rules(self):
#         """
#         This test will test two conditions for protections rules: when log is enabled and when it is not!
#         :return:
#         """
#         chain = "protection_rules"
#         check_protection_log_rules = list()
#         check_protection_log_rules.append('FORWARD -j {}'.format(chain))
#         check_protection_log_rules.append(
#             '{} -s 169.254.0.0/16 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -s 169.254.0.0/16 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -s 127.0.0.0/8 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -s 224.0.0.0/4 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -d 224.0.0.0/4 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -s 240.0.0.0/5 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -d 240.0.0.0/5 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -s 0.0.0.0/8 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -d 0.0.0.0/8 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -d 239.255.255.0/24 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#         check_protection_log_rules.append(
#             '{} -d 255.255.255.255 -j LOG --log-prefix "[log:fw_policy:spoof,action:DROP]"'.format(chain))
#
#         check_protection_log_rules.append('{} -p tcp ! --syn -m conntrack --ctstate NEW '
#                                           '-j LOG --log-prefix "[log:fw_policy:badsyn,action:DROP]"'.format(chain))
#         check_protection_log_rules.append('{} -p tcp ! --syn -m conntrack --ctstate NEW '
#                                           '-j DROP'.format(chain))
#
#         check_protection_log_rules.append('{} --fragment -p ICMP -j LOG'
#                                           ' --log-prefix "[log:fw_policy:fragmentedICMP,action:DROP]"'.format(chain))
#         check_protection_log_rules.append('{} --fragment -p ICMP -j DROP'.format(chain))
#         # Enable all logs
#         protection_logs = Setting.objects.filter(key="protection-log")
#         if not protection_logs:
#             protection_logs.create(key="protection-log", value="True")
#         else:
#             protection_logs.update(key="protection-log", value="True")
#
#         FirewallWatcher().add_prevention_rules()
#         for rule in check_protection_log_rules:
#             self.assertTrue(self.check_iptables_rule(rule), "The protection-log({}) rules do not exists".format(rule))
#
#         # Disable log
#         # Clean every thing
#         sudo_runner("iptables -w -D FORWARD -j {}".format(chain))
#         sudo_runner("iptables -w -F {}".format(chain))
#         sudo_runner("iptables -w -X {}".format(chain))
#         Setting.objects.filter(key="protection-log").update(value="False")
#
#         FirewallWatcher().add_prevention_rules()
#         for rule in check_protection_log_rules:
#             self.assertFalse(self.check_iptables_rule(rule), "One or more protection-log rules exist, that should not")
