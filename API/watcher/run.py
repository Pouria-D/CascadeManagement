import os
import sys
from time import sleep

import django
from django.db import connections
from django.db.utils import OperationalError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api.settings")

django.setup()
db_conn = connections['default']

from watcher.config import DNSWatcher, InterfaceWatcher, NTPWatcher, RSyslogWatcher, StaticRouteWatcher, SettingWatcher, \
    SnmpWatcher, QOSWatcher, DHCPWatcher, HighAvailabilityWatcher
from watcher.firewall import FirewallWatcher
from watcher.vpn import VPNWatcher
from watcher.service import ServiceWatcher, DjangoCacheLocationPermissionWatcher
from root_runner.sudo_utils import sudo_restart_systemd_service, sudo_file_writer, sudo_runner, sudo_file_reader
from config_app.models import HighAvailability
from config_app.utils import this_system_is_master, ha_read_status
import re


def restart_dnsmasq_and_fix_interfaces():
    from utils.config_files import DNSMASQ_CONFIG_FILE
    while True:
        sudo_restart_systemd_service('dnsmasq')
        status, result = sudo_runner('service dnsmasq status')  # status is false if dnsmasq service is failed
        if not status:
            if 'dnsmasq: unknown interface' in result:
                down_interface = re.search(r'dnsmasq:\s*unknown\s*interface\s*(\S*)', result, re.M).group(1)
                s, content = sudo_file_reader(DNSMASQ_CONFIG_FILE)
                interface_line = re.search(r'\ninterface=(\S*)\n', content).group(1)
                if down_interface in interface_line:
                    tmp = interface_line.split(',')
                    tmp.remove(down_interface)
                    new_interface_line = 'interface={}'.format(','.join(tmp))
                    content = re.sub(r'\ninterface=\S*\n', '\n{}\n'.format(new_interface_line), content)

                    if '#down_iface' not in content:
                        content += '#down_iface={}\n'.format(down_interface)
                    else:
                        down_iface_line = re.search(r'(#down_iface=\S*)\n', content).group(1)
                        down_iface_line += ',{}'.format(down_interface)
                        content = re.sub(r'#down_iface=\S*\n', '\n{}\n'.format(down_iface_line), content)

                    sudo_file_writer(DNSMASQ_CONFIG_FILE, content, 'w')
        else:
            break

while True:
    try:
        c = db_conn.cursor()
    except OperationalError:
        sudo_restart_systemd_service("postgresql")
        sleep(1)
    else:
        break
#
# dnsmasq service has dependencies to interfaces, if one of its interfaces have a problem then service will fail. for this reason,
# we should be very careful. and its why we wrote if-up and if-post-down scripts to remove down interfaces from dnsmasq config file
# Despite the existence of this scripts we Sometimes saw dnsmasq will fail after reboot the system. and it is because this service
# started earlier than network service in the startup. So here in watcher (watcher service start after network service), we restart
# dnsmasq service to be sure that dnsmasq started after network service

# Notice that after reboot when interface link is already disconnected, our if-post-down script doesn't run (WHY?!)
# for this reason we have to write this method and run it when system is starting up
watcher_should_work = False
if HighAvailability.objects.filter(is_enabled=True, status='succeeded').exists():
    pcs_status = ha_read_status()
    if pcs_status:
        if this_system_is_master(pcs_status):
            watcher_should_work = True
else:
    watcher_should_work = True

#
#
SettingWatcher(interval=20000)
FirewallWatcher(interval=300, pending_interval=30)
InterfaceWatcher(interval=1000)
NTPWatcher(interval=600)
VPNWatcher(interval=1000, pending_interval=30)
ServiceWatcher(interval=300)
RSyslogWatcher(interval=600)
DjangoCacheLocationPermissionWatcher(interval=100)
DNSWatcher(interval=1000)
StaticRouteWatcher(interval=100)
SnmpWatcher(interval=30)
QOSWatcher(interval=500)
DHCPWatcher(interval=1000)
HighAvailabilityWatcher(interval=30)
if watcher_should_work:
    restart_dnsmasq_and_fix_interfaces()
