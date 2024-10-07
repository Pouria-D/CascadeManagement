from os import abort

from psutil import virtual_memory, disk_usage

from parser_utils import make_response
from .utils import *

del datetime
import datetime


def get_user_traffic(request):
    interval = request.args.get('interval', 'day')
    if interval not in ('day', 'week', 'month', 'year', 'hour'):
        abort(400)

    params = dict()
    params['interval'] = interval
    if request.args.get('sortby', None):
        params['order_by'] = request.args.get('sortby')
    if request.args.get('direction', None) in ('0', 0, 'asc'):
        params['direction'] = 'asc'
    else:
        params['direction'] = 'desc'

    if request.args.get('username', None):
        params['username'] = request.args.get('username')

    try:
        params['page'] = int(request.args.get('page', 1))
        params['page_size'] = int(request.args.get('size', 10))
    except ValueError as e:
        logger.error(e)
        return make_response(400, "page and page size must be integer.")

    return json.dumps(calculate_used_traffic(**params))


def get_top_users(interval, count):
    if interval not in ('hour', 'day', 'week', 'month', 'year'):
        abort(400)

    top_uploaders = []
    top_downloaders = []
    top_total = []

    calculated_result_upload = calculate_top_users(interval, 'upload', count)
    calculated_result_download = calculate_top_users(interval, 'download', count)
    calculated_result_total = calculate_top_users(interval, 'total', count)

    for record in calculated_result_upload:
        top_uploaders.append({'username': record[0], 'upload': int(record[1]) / 1000.0})

    for record in calculated_result_download:
        top_downloaders.append({'username': record[0], 'download': int(record[1]) / 1000.0})

    for record in calculated_result_total:
        top_total.append({'username': record[0], 'total': int(record[1]) / 1000.0,
                          'download': int(record[2]) / 1000.0, 'upload': int(record[3]) / 1000.0})

    return json.dumps({'downloaders': top_downloaders,
                       'uploaders': top_uploaders, 'total': top_total})


def top_downloaders_view(interval, count):
    if interval not in ('hour', 'day', 'week', 'month', 'year'):
        abort(400)

    top_downloaders = []
    calculated_result_download = calculate_top_users(interval, 'download', count)
    for record in calculated_result_download:
        top_downloaders.append({'username': record[0], 'download': int(record[1]) / 1000.0})

    return make_response(json.dumps(top_downloaders), 200)


def top_uploaders_view(interval, count):
    if interval not in ('hour', 'day', 'week', 'month', 'year'):
        abort(400)

    top_uploaders = []
    calculated_result_upload = calculate_top_users(interval, 'upload', count)
    for record in calculated_result_upload:
        top_uploaders.append({'username': record[0], 'upload': int(record[1]) / 1000.0})

    return make_response(json.dumps(top_uploaders), 200)


def top_total_view(interval, count):
    if interval not in ('hour', 'day', 'week', 'month', 'year'):
        abort(400)

    top_total = []
    calculated_result_total = calculate_top_users(interval, 'total', count)
    for record in calculated_result_total:
        top_total.append({'username': record[0], 'total': int(record[1]) / 1000.0,
                          'download': int(record[2]) / 1000.0, 'upload': int(record[3]) / 1000.0})

    return make_response(json.dumps(top_total), 200)


def cpu_usage_view():
    return json.dumps({'cpu': get_cpu_usage()})


def ram_usage_view():
    return json.dumps({'total': virtual_memory().total / 1024 / 1024,
                       'available': virtual_memory().available / 1024 / 1024})


def disk_usage_view():
    return json.dumps({"total": disk_usage('/').total / 1024 / 1024,
                       "used": disk_usage('/').used / 1024 / 1024})


def get_cpu_and_ram_data():
    ram = {'total': virtual_memory().total / 1024 / 1024,
           'available': virtual_memory().available / 1024 / 1024}

    disk = {"total": disk_usage('/').total / 1024 / 1024,
            "used": disk_usage('/').used / 1024 / 1024}

    return json.dumps({'ram': ram, 'cpu': get_cpu_usage(), "disk": disk})


def get_bandwidth_view(interface):
    return json.dumps(get_bandwidth(interface))


def get_bandwidth_history_view(request):
    for qs in ('interface', 'interval', 'type', 'time'):
        if qs not in request.args:
            return make_response(400, "'%s' is nessesary (in query string)" % qs)

    interface = request.args['interface']
    interval = request.args['interval']
    _type = request.args['type']
    time = request.args['time']
    if 'limit' in request.args:
        try:
            limit = int(request.args['limit'])
        except ValueError:
            limit = 60
    else:
        limit = 60

    if interface not in get_network_interfaces():
        return make_response(400, "'%s' is not exists." % interface)

    data = get_bandwidth_history(interface, interval, _type, time, limit)

    # filling list with empty data to reach 'limit' length
    if _type == 'to':
        # set delta time with average interval time on NIC_BW_Collector
        if interval == 'hour':
            delta = datetime.timedelta(seconds=30)
        elif interval == 'day':
            delta = datetime.timedelta(seconds=1800)
        else:
            delta = datetime.timedelta(seconds=3)

        while len(data) < limit:
            if len(data) == 0:
                new_time = datetime.datetime.fromtimestamp(int(time)) - delta
            else:
                new_time = datetime.datetime.fromtimestamp(data[0]['epoch_time']) - delta
            data = [{
                'download_rate': 0,
                'upload_rate': 0,
                'time': new_time.strftime('%Y-%m-%d %H:%M:%S'),
                'epoch_time': int(new_time.strftime('%s'))
            }] + data

    if data is None:
        abort(400)

    return json.dumps({'data': data})


def get_interface_list_view(request):
    state = request.args.get('state', None)
    if state and state.lower() == 'true':
        state = True
    elif state and state.lower() == 'false':
        state = False
    data = get_network_interfaces(state)
    if data == None:
        abort(500)

    return make_response(json.dumps(data), 200)


def get_internet_status_view():
    response = None
    if get_internet_status():
        response = make_response(200, 'OK')
    else:
        response = make_response(500, 'Error')
    return response


def get_services_status_view():
    data = {
        'captive_portal': get_captive_portal_status(),
        'qos': True,
        'firewall': True,
        'application_filter': True
    }
    return json.dumps(data)


def get_system_info():
    data = {
        'datetime': get_datetime(),
        'uptime': get_uptime(),
        'hostname': get_hostname()
    }
    return json.dumps(data)
