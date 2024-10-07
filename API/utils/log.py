import json
import logging

from utils.log_codes import log_codes


def log(logger_name, item, operation, status, username=None, ip=None, details=None):
    from logging_app.models import LastLog
    if operation == 'list' or operation == 'retrieve':
        if LastLog.objects.exists():
            if LastLog.objects.last().item == item and LastLog.objects.last().ip == ip:
                return None

        LastLog.objects.create(ip=ip, username=username, item=item)

    logger = logging.getLogger(logger_name)
    log_code = log_codes[item][operation][status]
    log_dict = {'message': log_code['message'], 'operation': operation}

    if username:
        log_dict['user'] = username

    if ip:
        log_dict['ip'] = ip

    if details:
        log_dict['details'] = details

    write_log = getattr(logger, log_code['severity'])
    write_log(json.dumps(log_dict))


def watcher_log(service, name=None, message=""):
    logger = logging.getLogger('watcher')
    if name:
        log_dict = {'message': 'System auto fixed {} in {} and the message is: {}'.format(name, service, message)}
    else:
        log_dict = {'message': 'System auto fixed {} and the message is: {}'.format(service, message)}

    write_log = getattr(logger, 'info')
    write_log(json.dumps(log_dict))
