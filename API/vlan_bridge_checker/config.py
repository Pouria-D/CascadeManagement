from time import sleep

from netaddr import IPAddress

from config_app.models import Interface
from config_app.utils import set_Bridge_configuration, check_bridge_interface, set_Vlan_configuration
from root_runner.sudo_utils import sudo_runner
from watcher.base import AbstractWatcher


class VlanBridgeWatcher(AbstractWatcher):
    def run(self, interval, pending_interval=30):
        while True:
            for interface in Interface.objects.all():

                if interface.mode == 'bridge':
                    s, o = sudo_runner('cat /sys/class/net/{}/carrier'.format(interface.name))

                    if interface.is_enabled and not s or not check_bridge_interface(interface):
                        set_Bridge_configuration(interface, None, None, None, None, is_watcher=True)

                    s, o = sudo_runner(
                        "ifconfig {} | grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1".format(interface.name))

                    if interface.is_enabled and o != interface.ip_list[0]['ip']:
                        netmask = interface.ip_list[0]['mask']
                        netmask = IPAddress(netmask).netmask_bits()
                        sudo_runner(
                            'ifconfig {0} {1}/{2}'.format(interface.name, interface.ip_list[0]['ip'], netmask))






                elif interface.mode == 'vlan':

                    s, o = sudo_runner('cat /sys/class/net/{}/carrier'.format(interface.name))

                    if interface.is_enabled and not s:
                        set_Vlan_configuration(interface, None, None, None, None, is_watcher=True)

                    s, o = sudo_runner(
                        "ifconfig {} | grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1".format(interface.name))

                    if interface.is_enabled and o != interface.ip_list[0]['ip']:
                        netmask = IPAddress(interface.ip_list[0]['mask']).netmask_bits()
                        s, o = sudo_runner(
                            'nmcli con mod {0}.{1} ipv4.addresses {2}/{3}'.format(interface.data[0]['interface'][0],
                                                                                  interface.data[0]['vlan_id'],
                                                                                  interface.ip_list[0]['ip'],
                                                                                  netmask))

                        s, o = sudo_runner('nmcli con up  {}'.format(interface.name))

                    s, o = sudo_runner(
                        "ifconfig {} | grep 'MTU' | cut -d ':' -f 2 | cut -d ' ' -f 1".format(interface.name))

                    if interface.is_enabled and o != str(interface.mtu):
                        sudo_runner('ifconfig {0}.{1} mtu {2}'.format(interface.data[0]['interface'][0],
                                                                      interface.data[0]['vlan_id'],
                                                                      str(interface.mtu)))

            sleep(interval)
