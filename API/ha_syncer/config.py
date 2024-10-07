import os
from time import sleep

from django.core.management import call_command

from api.settings import BACKUP_DIR, POLICY_BACK_POSTFIX
from config_app.models import Setting, HighAvailability
from config_app.utils import this_system_is_master, get_slave_ip_address, ha_read_status, TIMEOUT_DURATION_FOR_SSH
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner
from root_runner.utils import command_runner
from utils.config_files import API_PATH
from utils.utils import print_if_debug
from watcher.base import AbstractWatcher


def sync_db_ha(slave_ip_address, ssh_port, https_port, user='ngfw'):
    dump_file_path = '/tmp/dumpdata.json'
    try:
        call_command('dumpdata', exclude=[
            'diagnosis_app.Diagnosis',
            'config_app.Hostname',
            'config_app.Update',
            'config_app.Backup',
            'config_app.Interface',
            'report_app.Notification',
            'auth_app.AdminLoginLock',
            'auth_app.Token',
            'sessions.Session',
            'auth.permission',
            'contenttypes'
        ], output=dump_file_path)

        cmd = 'timeout --foreground {duration} scp -P {ssh_port} {path} {user}@{ip}:/tmp/'.format(path=dump_file_path,
                                                                                                  user=user,
                                                                                                  ip=slave_ip_address,
                                                                                                  ssh_port=ssh_port,
                                                                                                  duration=TIMEOUT_DURATION_FOR_SSH)
        status, result = command_runner(cmd)
        if status:
            print_if_debug("HA: {}".format(cmd))
            cmd = 'timeout --foreground {duration} ssh -t {user}@{ip} -p {ssh_port} "/opt/narin/.env/bin/python ' \
                  '/opt/narin/api/manage.py syncdata {path}"'.format(
                user=user, ip=slave_ip_address, path=dump_file_path, ssh_port=ssh_port,
                duration=TIMEOUT_DURATION_FOR_SSH)
            status, result = command_runner(cmd)
            print_if_debug(result)
            if status:
                cmd = 'curl -X "POST" -k ' \
                      'https://127.0.0.1:{}/api/config/highavailability/ha_sync_db_assurance'.format(https_port)
                cmd2 = 'timeout --foreground {duration} ssh -t {user}@{ip_address} -p {ssh_port} "{cmd}"'.format(
                    duration=TIMEOUT_DURATION_FOR_SSH, user=user, ip_address=slave_ip_address, ssh_port=ssh_port,
                    cmd=cmd)
                command_runner(cmd2)
                print_if_debug("HA: database {} successfully synced!".format(slave_ip_address))
                return True
        raise Exception
    except Exception as e:
        print_if_debug("HA: sync database with {} failed for this exception: {}!".format(slave_ip_address, e))
        return False


def sync_files(slave_ip_address, ssh_port, user='ngfw', password='ngfw'):
    tmp_path = '/tmp/HA_for_sync_files'
    sudo_runner(
        'timeout --foreground {duration} rsync -aSvcz -e "ssh -p {ssh_port}" --rsh="/usr/bin/sshpass -p {passwd} ssh'
        ' -p {ssh_port} -o StrictHostKeyChecking=no -l root" '
        '--recursive --delete-after --files-from={api_path}ha_syncer/ha_sync_files / {user}@{slave_ip}:{tmp_path}'
        .format(user=user, passwd=password, ssh_port=ssh_port, api_path=API_PATH, slave_ip=slave_ip_address,
                tmp_path=tmp_path, duration=TIMEOUT_DURATION_FOR_SSH))

    rsync_cmd = 'sudo -S rsync -aSvcz --recursive --delete-after '.format(passwd=password,
                                                                          slave_ip=slave_ip_address, user=user)
    status, result = command_runner(
        'timeout --foreground {duration} ssh -t {user}@{slave_ip}  -p {ssh_port} "echo {passwd} | '
        '{rsync} -d {tmp_path}/etc/ipsec.conf /etc/ ; '
        '{rsync} -d {tmp_path}/etc/ipsec.secrets /etc/ ; '
        '{rsync} -d {tmp_path}/etc/gre/ /etc/gre ;  '
        '{rsync} -d {tmp_path}/etc/ipip/ /etc/ipip ; '
        '{rsync} -d {tmp_path}/var/lock/vtund/ /var/lock/ ; '
        '{rsync} -d {tmp_path}/etc/dnsmasq.conf /etc/dnsmasq.conf ; '
        '{rsync} -d {tmp_path}/etc/dns_upstream_list /etc/dns_upstream_list ; '
        '{rsync} -d {tmp_path}/etc/host_list /etc/host_list ; '
        '{rsync} -d {tmp_path}/etc/snmp/ /etc/snmp/ ;'
        '{rsync} -d {tmp_path}/etc/init.d/dnsmasq /etc/init.d/dnsmasq ; '
        '{rsync} -d {tmp_path}/var/lib/snmp/ /var/lib/snmp/ ;'
        '{rsync} -d {tmp_path}/etc/rsyslog.conf /etc/rsyslog.conf ;'
        '{rsync} -d {tmp_path}/etc/ntp.conf /etc/ntp.conf ;'
        '{rsync} -d {tmp_path}/etc/ssl/certs/rsyslog_ca.pem /etc/ssl/certs/rsyslog_ca.pem ;'
        '{rsync} -d {tmp_path}/var/ngfw/policy_back/ /var/ngfw/policy_back/ ;'
        '{rsync} -d {tmp_path}/var/lib/misc/dnsmasq.leases /var/lib/misc/dnsmasq.leases ;'
        '{rsync} -d {tmp_path}/etc/issue.net /etc/issue.net ;'
        '{rsync} -d {tmp_path}/etc/nginx/sites-available/narin.conf /etc/nginx/sites-available/narin.conf ;'
        '{rsync} -d {tmp_path}/etc/ssh/sshd_config /etc/ssh/sshd_config ;'
        '{rsync} -d {tmp_path}/etc/fail2ban/jail.conf /etc/fail2ban/jail.conf ;'
        '{rsync} -d {tmp_path}/etc/ssl/certs/nginx-selfsigned.crt /etc/ssl/certs/nginx-selfsigned.crt ;'
        '{rsync} -d {tmp_path}/etc/ssl/private/nginx-selfsigned.key /etc/ssl/private/nginx-selfsigned.key ;'
        '"'.format(
            passwd=password,
            ssh_port=ssh_port,
            rsync=rsync_cmd,
            slave_ip=slave_ip_address,
            tmp_path=tmp_path,
            user=user,
            duration=TIMEOUT_DURATION_FOR_SSH))

    if status:
        print_if_debug("HA: config files {} successfully synced!".format(slave_ip_address))
        return True
    else:
        print_if_debug("HA: sync config files with {} failed for this reason: {}!".format(slave_ip_address, result))
    return False


def restore_iptables_rules_on_slave(slave_ip_address, ssh_port, user='ngfw', password='ngfw'):
    iptables_backup_file = os.path.join(BACKUP_DIR, '{}/iptables.backup'.format(POLICY_BACK_POSTFIX))
    status, result = command_runner(
        'timeout --foreground {duration} ssh -t {user}@{slave_ip}  -p {ssh_port} "echo {passwd} | '
        'sudo -S bash {ipset_file}/for_ipset.sh;'
        'echo {passwd} | sudo -S iptables-restore {file}"'.format(
            user=user, passwd=password, slave_ip=slave_ip_address, file=iptables_backup_file, ssh_port=ssh_port,
            ipset_file=os.path.join(BACKUP_DIR, POLICY_BACK_POSTFIX), duration=TIMEOUT_DURATION_FOR_SSH))

    if status:
        print_if_debug("HA: iptables {} successfully synced!".format(slave_ip_address))
    else:
        print_if_debug("HA: sync iptables with {} failed for this reason: {}!".format(slave_ip_address, result))


class HASyncWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=20):
        # for_ipset.sh file: this file is created for loading ipsets in kernel.
        sudo_runner('mkdir -p {path} ;'
                    ' echo \'iptables -F \n iptables -X \n '
                    'iptables -t nat -F \n iptables -t nat -X \n'
                    'ipset -F \n ipset -X \n '
                    'for file in {path}/policy_*_ipsets* \n do \n if [ -f $file ] \n then \n bash $file \n fi \n done\''
                    ' > {path}/for_ipset.sh'.format(
            path=os.path.join(BACKUP_DIR, POLICY_BACK_POSTFIX)))

        while True:
            ha_config = HighAvailability.objects.all()
            if ha_config.exists() and ha_config[0].is_enabled and ha_config[0].status == 'succeeded':
                pcs_status = ha_read_status()
                if pcs_status:
                    if this_system_is_master(pcs_status):
                        slave_address = get_slave_ip_address(pcs_status)
                        if pcs_status['offline_node']:
                            Notification.objects.filter(source='HA',
                                                        message__contains='There is a problem for syncing peers in High availability').delete()
                        if slave_address:
                            Notification.objects.filter(source='HA',
                                                        message__contains='There is a problem for syncing peers in High availability').delete()
                            ssh_port = Setting.objects.get(key='ssh-port').data['value']
                            https_port = Setting.objects.get(key='https-port').data['value']
                            sync_db_ha(slave_address, ssh_port, https_port)
                            sync_files(slave_address, ssh_port)
                            restore_iptables_rules_on_slave(slave_address, ssh_port)
                        else:
                            print_if_debug("slave is not in touch!")
                            if not pcs_status['offline_node'] and not Notification.objects.filter(
                                    message__contains='There is a problem for syncing peers in High availability'):
                                create_notification(source='HA', item={},
                                                    message='There is a problem for syncing peers in High availability,'
                                                            ' please disable High Availability and then check the hostname '
                                                            'of peers to be correct and then enable High '
                                                            'Availability configuration',
                                                    severity='e',
                                                    request_username='')

            sleep(interval)
