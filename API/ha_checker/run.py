import os
import re
import sys

import django
from django.db import connections

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api.settings")

django.setup()
db_conn = connections['default']

from config_app.models import HighAvailability
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner
from utils.log import log


class HAChecker:
    @staticmethod
    def run():
        if HighAvailability.objects.filter(is_enabled=True, status='succeeded'):
            status, result = sudo_runner('pcs status resources')
            if not status or (status and not re.search(r'\(\S*\):\s*Started\s*\S*', result, re.M)):
                create_notification(source='HA', item={},
                                    message=str(
                                        'HighAvailability is not available until a few minutes later. please wait!'),
                                    severity='e')
                log('config', 'ha_config', 'check', 'fail', username='HA', ip='', details={})
                sudo_runner('service corosync restart')
                sudo_runner('service pacemaker restart')
                log('config', 'ha_config', 'check', 'fix', username='HA', ip='', details={})
                Notification.objects.filter(source='HA',
                                            message__contains='HighAvailability is not available '
                                                              'until a few minutes later').delete()
            else:
                Notification.objects.filter(source='HA',
                                            message__contains='HighAvailability is not available '
                                                              'until a few minutes later').delete()
                Notification.objects.filter(source='HA',
                                            message__contains='Some of High Availability resources(cluster ips or services) are not').delete()
                if re.search(r'\(\S*\):\s*Stopped\s*', result, re.M) or \
                        re.search(r'\(failure ignored\)', result, re.M):
                    create_notification(source='HA', item={},
                                        message=str(
                                            'Some of High Availability resources(cluster ips or services) are not '
                                            'started on active node. for more information go to High Availability '
                                            'configuration page.'),
                                        severity='e')


HAChecker.run()
