from time import sleep

from config_app.models import HighAvailability
from config_app.utils import ha_read_status, this_system_is_master
from root_runner.sudo_utils import sudo_runner
from root_runner.utils import command_runner
from watcher.base import AbstractWatcher


class ServiceWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        while True:
            watcher_should_work = False
            if HighAvailability.objects.filter(is_enabled=True, status='succeeded').exists():
                pcs_status = ha_read_status()
                if pcs_status:
                    if this_system_is_master(pcs_status):
                        watcher_should_work = True
            else:
                watcher_should_work = True

            # watcher should not work for ipsec and dnsmasq services on slave system
            if watcher_should_work:
                for service in ['dnsmasq', 'ipsec']:
                    status, result = command_runner('service {} status'.format(service))
                    # result = subprocess.check_output('service {} status'.format(service), shell=True)
                    if not status or 'Active: active' not in str(result):
                        if service == 'ipsec':
                            sudo_runner('rm -f /var/run/charon.pid')
                            sudo_runner('rm -f /var/run/starter.charon.pid')

                        cmd = 'service {} restart'.format(service)
                        sudo_runner(cmd)
            for service in ['log-collector', 'root_runner', 'api', 'nginx', 'vlan-bridge']:
                status, result = command_runner('service {} status'.format(service))
                # result = subprocess.check_output('service {} status'.format(service), shell=True)
                if not status or 'Active: active' not in str(result):

                    cmd = 'service {} restart'.format(service)
                    sudo_runner(cmd)

            sleep(interval)


class DjangoCacheLocationPermissionWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        while True:
            cmd = 'ls -ld /tmp/django_cache | cut -d\' \' -f4'
            status, result = command_runner(cmd)
            if result != 'ngfw':
                cmd = 'chown -R ngfw:ngfw /tmp/django_cache'
                sudo_runner(cmd)

            sleep(interval)
