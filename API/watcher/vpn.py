from time import sleep

from config_app.models import HighAvailability
from config_app.utils import ha_read_status, this_system_is_master
from root_runner.sudo_utils import sudo_file_reader, sudo_check_path_exists, sudo_runner
from utils.config_files import IPSEC_CONF_FILE, IPSEC_SECRETS_FILE, VTUND_CONFIGS_PATH
from utils.log import watcher_log
from utils.utils import run_thread, get_thread_status, print_if_debug
from vpn_app.models import VPN
from vpn_app.utils import get_vpn_status, update_vpn, restart_vpn, check_policy, \
    chack_and_create_ipsec_config_file
from watcher.base import AbstractWatcher


def exist_tunnel_interface(vpn):
    status, result = sudo_runner('ifconfig {}'.format(vpn.name))
    if status:
        if vpn.tunnel.virtual_local_endpoint.value_list[0].split("/")[0] not in result:
            return False
    return True


def vpn_watcher():
    chack_and_create_ipsec_config_file()

    vpn_list = VPN.objects.filter(is_enabled=True)
    for vpn in vpn_list:
        if vpn.last_operation == "delete":
            continue
        need_to_update = False
        tunnel_status = True

        vpn_status = get_vpn_status('vpn', vpn.name, None, None, None)
        if vpn.tunnel:
            virtual_remote_ip = vpn.tunnel.virtual_remote_endpoint.value_list[0].split("/")[0]
            virtual_local_ip = vpn.tunnel.virtual_local_endpoint.value_list[0].split("/")[0]
            tunnel_status = get_vpn_status('tunnel', vpn.name, vpn.tunnel.type, virtual_remote_ip,
                                           virtual_local_ip)

        if vpn.tunnel and not tunnel_status:
            if vpn.tunnel.type == 'vtun':
                status, result = sudo_check_path_exists(
                    "{path}{type}/{name}/vtund.conf".format(path=VTUND_CONFIGS_PATH, type=vpn.tunnel.mode,
                                                            name=vpn.name))
                if result == 'False':
                    need_to_update = True
                else:
                    if not check_policy(vpn):
                        need_to_update = True
            elif vpn.tunnel.type == 'gre' or vpn.tunnel.type == 'ipip':
                status, result = sudo_check_path_exists(
                    "/etc/{type}/{name}/{type}_tun.conf".format(type=vpn.tunnel.type, name=vpn.name))
                if result == 'False':
                    need_to_update = True
                elif not exist_tunnel_interface(vpn):
                    need_to_update = True
                else:
                    if not check_policy(vpn):
                        need_to_update = True

        if vpn_status == 'down':
            status, result = sudo_file_reader(IPSEC_SECRETS_FILE)
            if status:
                vpn_conf_preshared_key = vpn.local_id + " " + vpn.peer_id + \
                                         "  : PSK \"" + vpn.preshared_key + "\"" + \
                                         "   #" + vpn.name
                if vpn_conf_preshared_key not in result:
                    need_to_update = True
            else:
                need_to_update = True
            status, result = sudo_file_reader(IPSEC_CONF_FILE)
            if status:
                if 'conn {} '.format(vpn.name) not in result:
                    need_to_update = True
            else:
                need_to_update = True

        if need_to_update:
            old_tunnel = None
            old_vpn = vpn.__dict__
            if vpn.tunnel:
                old_tunnel = vpn.tunnel.__dict__
            update_vpn(vpn, old_vpn, old_tunnel, is_watcher=True)
            watcher_log('VPN', vpn.name, "the vpn should update")

        else:
            if not tunnel_status or vpn_status == 'down':
                print_if_debug("Trying to restart vpn")
                restart_vpn(vpn, None)
                watcher_log('VPN', vpn.name, "the vpn should restart")


class VPNWatcher(AbstractWatcher):
    def check_pending_vpns(self, pending_interval):
        from vpn_app.models import VPN
        while True:
            vpn_list = VPN.objects.filter(status='pending')
            for vpn in vpn_list:
                if not get_thread_status("vpn_{}".format(vpn.id)):
                    vpn.status = "failed"
                    vpn.save()
            sleep(pending_interval)

    def run(self, interval, pending_interval):
        run_thread(target=self.check_pending_vpns, name="vpn_watcher", args=(pending_interval,))
        while True:
            watcher_should_work = False
            if HighAvailability.objects.filter(is_enabled=True, status='succeeded').exists():
                pcs_status = ha_read_status()
                if pcs_status:
                    if this_system_is_master(pcs_status):
                        watcher_should_work = True
            else:
                watcher_should_work = True
            if watcher_should_work:
                vpn_watcher()

            sleep(interval)
