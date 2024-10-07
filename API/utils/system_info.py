from django.utils import timezone

from auth_app.models import AdminLoginLock
from root_runner.sudo_utils import sudo_runner
from utils.version import get_version


class SystemInfo:

    @staticmethod
    def get_wanip():
        s, o = sudo_runner('curl ifconfig.me')
        if s:
            return o

    @staticmethod
    def get_uptime():
        s, o = sudo_runner('uptime -p')
        if s:
            return o

    @staticmethod
    def get_timezone():
        s, o = sudo_runner('timedatectl status | grep "Time zone" ')
        if s:
            return o.split('Time zone: ', 1)[1]

    @staticmethod
    def get_servertime():
        return str(timezone.now())

    @staticmethod
    def get_last_login_ip():
        entry = AdminLoginLock.objects.all().order_by('datetime_created').last()
        return (entry.ip)

    @staticmethod
    def get_hostname():
        s, o = sudo_runner('hostname')
        if s:
            return o

    @staticmethod
    def get_last_login_time():
        entry = AdminLoginLock.objects.all().order_by('datetime_created').last()
        return str(entry.datetime_created)

    @staticmethod
    def get_narin_version():
        version = get_version()
        return version

    @staticmethod
    def get_module_list():
        with open('/var/ngfw/module-list.yml', 'r') as modulelist:
            return (modulelist.read())

    @staticmethod
    def get_serial_number():
        return ('DFW-31241562')

    @staticmethod
    def get_token_number():
        return ('NTM-3427242')
