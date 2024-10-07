import datetime
import re
import time

import psutil
from rest_framework import serializers

from api.settings import IS_TEST
from auth_app.utils import get_client_ip
from root_runner.sudo_utils import sudo_runner
from root_runner.utils import command_runner
from utils.log import log

result_thread = {}
queue_status = []


def create_json(type=None, remote_endpoint_report=None, local_host_report=None, remote_host_report=None):
    name = ''
    if type not in result_thread:

        if type == 'mtr':
            name = 'MTR'
        if type == 'ping':
            name = 'PING'
        if type == 'conntrack':
            name = 'Conntrack'
        if type == 'ram_cpu':
            name = 'RAM & CPU'

        result_thread[type] = {}
        result_thread[type]['display_name'] = name
        result_thread[type]['data'] = []

    if 'ram_cpu' == type:
        index = check_exsis_key(result_thread['ram_cpu']['data'], 'used')
        if len(index) == 0:
            result_thread[type]['data'].append({'key': 'used'})
            index = check_exsis_key(result_thread[type]['data'], 'used')
            result_thread[type]['data'][index[0]]['head_line'] = name

    if type == 'conntrack':
        index = check_exsis_key(result_thread[type]['data'], 'established')
        if len(index) == 0:
            result_thread[type]['data'].append({'key': 'established'})
            index = check_exsis_key(result_thread[type]['data'], 'established')
            result_thread[type]['data'][index[0]]['head_line'] = 'Count connection Established'
        # if len(index) > 0 and 'head_line' in result_thread[type]['data'][index[0]]:
        #     print("head line")
        #     result_thread[type]['data'][index[0]]['head_line'] = 'Count connection Established'

        index_new = check_exsis_key(result_thread[type]['data'], 'new')
        if len(index_new) == 0:
            result_thread[type]['data'].append({'key': 'new'})
            index_new = check_exsis_key(result_thread[type]['data'], 'new')
            result_thread[type]['data'][index_new[0]]['head_line'] = 'Count connection NEW'

    if type == 'ping':
        if remote_endpoint_report:
            index = check_exsis_key(result_thread[type]['data'], 'remote_endpoint_report')

            if len(index) == 0:
                result_thread[type]['data'].append({'key': 'remote_endpoint_report'})
                index = check_exsis_key(result_thread[type]['data'], 'remote_endpoint_report')
                result_thread[type]['data'][index[0]]['head_line'] = 'Ping {}'.format(remote_endpoint_report)

        if local_host_report and remote_host_report:
            index = check_exsis_key(result_thread[type]['data'], 'local_remote')

            if len(index) == 0:
                result_thread[type]['data'].append({'key': 'local_remote'})
                index = check_exsis_key(result_thread[type]['data'], 'local_remote')
                result_thread[type]['data'][index[0]]['head_line'] = 'Ping {} to {}'.format(local_host_report,
                                                                                            remote_host_report)

            # if len(index) > 0:
            #     result_thread[type]['data'][index[0]]['head_line'] = 'Ping {} to {}'.format(local_host_report, remote_host_report)

        # else:
        #     index = check_exsis_key(result_thread[type]['data'], 'local_remote')
        #     if len(index) > 0:
        #         del result_thread[type]['data'][index[0]]

    if type == 'mtr':
        if remote_endpoint_report:
            index = check_exsis_key(result_thread[type]['data'], 'remote_endpoint_report')
            if len(index) == 0:
                result_thread[type]['data'].append({'key': 'remote_endpoint_report'})
                index = check_exsis_key(result_thread[type]['data'], 'remote_endpoint_report')
                result_thread[type]['data'][index[0]]['head_line'] = 'MTR {}'.format(remote_endpoint_report)

            # if len(index) > 0:
            #     result_thread[type]['data'][index[0]]['head_line'] = 'MTR {}'.format(remote_endpoint_report)

        # else:
        #     index = check_exsis_key(result_thread[type]['data'], 'remote_endpoint_report')
        #     if len(index) > 0:
        #         del result_thread[type]['data'][index[0]]

        if remote_host_report:
            index = check_exsis_key(result_thread[type]['data'], 'remote_host_report')
            if len(index) == 0:
                result_thread[type]['data'].append({'key': 'remote_host_report'})
                index = check_exsis_key(result_thread[type]['data'], 'remote_host_report')

                result_thread[type]['data'][index[0]]['head_line'] = 'MTR {}'.format(remote_host_report)

            # if len(index) > 0:
            #     result_thread[type]['data'][index[0]]['head_line'] = 'MTR {}'.format(remote_host_report)

        # else:
        #     print("remote_host_report")
        #     index = check_exsis_key(result_thread[type]['data'], 'remote_host_report')
        #     if len(index) > 0:
        #         del result_thread[type]['data'][index[0]]


# conntrack -E -e NEW | pv -l -i 1 -r > /dev/null


def check_exsis_key(data, key):
    check_exsis = [x for x in range(0, len(data)) if data[x]['key'] == key]
    if check_exsis:
        return check_exsis

    return []


def ping_dst_interrupted(instance, request, remote_endpoint_report, duration):
    if 'ping_dst_interrupted' not in queue_status:
        queue_status.append('ping_dst_interrupted')
    create_json('ping', remote_endpoint_report, None, None)
    index = check_exsis_key(result_thread['ping']['data'], 'remote_endpoint_report')[0]

    try:
        # count = 0
        # sum_response_time = 0
        data_response_time = []
        # sum_packet_loss = 0
        data_packet_loss = []

        end_time = datetime.datetime.now() + datetime.timedelta(minutes=duration)
        while datetime.datetime.now() < end_time:
            cmd = 'ping {} -w 5'.format(remote_endpoint_report)
            status, result = command_runner(cmd, True)
            if 'Cannot assign requested address' in result:
                log('diagnosis', 'diagnosis_report', 'add', 'fail',
                    username=request.user.username, ip=get_client_ip(request), details={'error': result})

                result_thread['ping']['data'][index]['interrupted'] = []
                result_thread['ping']['data'][index]['error'] = result
                instance.result = result_thread
                instance.status = 'failed'
                instance.save()
                return
            if 'packet loss, time' in result:
                regular_expr = r'([\d.]+)% packet loss, time ([\d.]+)ms'
                tmp = re.search(regular_expr, result)
                date_time = datetime.datetime.now().strftime("%H:%M:%S")
                data_packet_loss.append({'value': tmp.group(1), 'name': date_time})
                data_response_time.append({'value': tmp.group(2), 'name': date_time})

                # sum_packet_loss += int(tmp.group(1))
                # sum_response_time += int(tmp.group(2))
                # count += 1

        # avg_packet_loss = sum_packet_loss / count
        # avg_response_time = sum_response_time / count
        # avg_results = {'avg_packet_loss': avg_packet_loss, 'avg_response_time': avg_response_time}
        data_chart = []
        data_chart.append({'name': 'packet loss (%)', 'series': data_packet_loss})
        data_chart.append({'name': 'time (ms)', 'series': data_response_time})
        result_thread['ping']['data'][index]['interrupted'] = data_chart

        instance.result = result_thread
        if 'ping_dst_interrupted' in queue_status:
            queue_status.remove('ping_dst_interrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'

        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['ping']['data'][index]['interrupted'] = []
        result_thread['ping']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def ping_dst_uninterrupted(instance, request, remote_endpoint_report, duration):
    if 'ping_dst_uninterrupted' not in queue_status:
        queue_status.append('ping_dst_uninterrupted')
    create_json('ping', remote_endpoint_report, None, None)
    index = check_exsis_key(result_thread['ping']['data'], 'remote_endpoint_report')[0]

    try:
        end_time = duration * 60

        cmd = 'ping {} -w {}'.format(remote_endpoint_report, end_time)
        status, result = command_runner(cmd, True)
        if 'Cannot assign requested address' in result:
            log('diagnosis', 'diagnosis_report', 'add', 'fail',
                username=request.user.username, ip=get_client_ip(request), details={'error': result})

            result_thread['ping']['data'][index]['uninterrupted'] = []
            result_thread['ping']['data'][index]['error'] = result
            instance.result = result_thread
            instance.status = 'failed'
            instance.save()
            return

        res = dict()
        if 'packet loss, time' in result:
            regular_expr = r'([\d.]+)% packet loss, time ([\d.]+)ms'
            tmp = re.search(regular_expr, result)
            res['packet_loss'] = tmp.group(1) + '%'
            res['response_time'] = tmp.group(2) + ' ms'
            res['timestamp'] = datetime.datetime.now().strftime("%H:%M:%S")

        result_thread['ping']['data'][index]['uninterrupted'] = res

        instance.result = result_thread

        if 'ping_dst_uninterrupted' in queue_status:
            queue_status.remove('ping_dst_uninterrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'

        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['ping']['data'][index]['uninterrupted'] = []
        result_thread['ping']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def ping_src_dst_interrupted(instance, request, local_host_report, remote_host_report, duration):
    if 'ping_src_dst_interrupted' not in queue_status:
        queue_status.append('ping_src_dst_interrupted')
    create_json('ping', None, local_host_report, remote_host_report)
    index = check_exsis_key(result_thread['ping']['data'], 'local_remote')[0]

    try:
        # count = 0
        # sum_response_time = 0
        data_response_time = []
        # sum_packet_loss = 0
        data_packet_loss = []
        end_time = datetime.datetime.now() + datetime.timedelta(minutes=duration)
        while datetime.datetime.now() < end_time:
            cmd = 'ping -I {} {} -w 5'.format(local_host_report, remote_host_report)
            status, result = command_runner(cmd, True)
            if 'Cannot assign requested address' in result:
                log('diagnosis', 'diagnosis_report', 'add', 'fail',
                    username=request.user.username, ip=get_client_ip(request), details={'error': result})

                result_thread['ping']['data'][index]['interrupted'] = []
                result_thread['ping']['data'][index]['error'] = result
                instance.result = result_thread
                instance.status = 'failed'
                instance.save()
                return

            if 'packet loss, time' in result:
                regular_expr = r'([\d.]+)% packet loss, time ([\d.]+)ms'
                tmp = re.search(regular_expr, result)
                date_time = datetime.datetime.now().strftime("%H:%M:%S")
                data_packet_loss.append({'value': tmp.group(1), 'name': date_time})
                data_response_time.append({'value': tmp.group(2), 'name': date_time})

                # sum_packet_loss += int(tmp.group(1))
                # sum_response_time += int(tmp.group(2))
                # count += 1

        # avg_packet_loss = sum_packet_loss / count
        # avg_response_time = sum_response_time / count
        # avg_results = {'avg_packet_loss': avg_packet_loss, 'avg_response_time': avg_response_time}

        data_chart = []
        data_chart.append({'name': 'packet loss (%)', 'series': data_packet_loss})
        data_chart.append({'name': 'time (ms)', 'series': data_response_time})
        result_thread['ping']['data'][index]['interrupted'] = data_chart

        instance.result = result_thread

        if 'ping_src_dst_interrupted' in queue_status:
            queue_status.remove('ping_src_dst_interrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            log('diagnosis', 'diagnosis_report', 'add', 'success',
                username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
            instance.status = 'succeeded'

        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})

        result_thread['ping']['data'][index]['interrupted'] = []
        result_thread['ping']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.save()


def ping_src_dst_uninterrupted(instance, request, local_host_report, remote_host_report, duration):
    if 'ping_src_dst_uninterrupted' not in queue_status:
        queue_status.append('ping_src_dst_uninterrupted')
    create_json('ping', None, local_host_report, remote_host_report)
    index = check_exsis_key(result_thread['ping']['data'], 'local_remote')[0]

    try:
        end_time = duration * 60
        cmd = 'ping -I {} {} -w {}'.format(local_host_report, remote_host_report, str(end_time))
        status, result = command_runner(cmd, True)
        if 'Cannot assign requested address' in result:
            log('diagnosis', 'diagnosis_report', 'add', 'fail',
                username=request.user.username, ip=get_client_ip(request), details={'error': result})

            result_thread['ping']['data'][index]['uninterrupted'] = []
            result_thread['ping']['data'][index]['error'] = result
            instance.result = result_thread
            instance.status = 'failed'
            instance.save()
            return
        res = dict()
        if 'packet loss, time' in result:
            regular_expr = r'([\d.]+)% packet loss, time ([\d.]+)ms'
            tmp = re.search(regular_expr, result)
            res['packet_loss'] = tmp.group(1) + '%'
            res['response_time'] = tmp.group(2) + ' ms'
            res['timestamp'] = datetime.datetime.now().strftime("%H:%M:%S")
        result_thread['ping']['data'][index]['uninterrupted'] = res

        instance.result = result_thread

        if 'ping_src_dst_uninterrupted' in queue_status:
            queue_status.remove('ping_src_dst_uninterrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['ping']['data'][index]['uninterrupted'] = []
        result_thread['ping']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def check_ping_link(src_ip, des_ip):
    if IS_TEST:
        return
    cmd = 'ping -I {} {} -w 1'.format(src_ip, des_ip)
    status, result = command_runner(cmd, True)
    if 'Cannot assign requested address' in result:
        raise serializers.ValidationError({'non_field_errors': 'Cannot assign requested address (not link between '
                                                               'local host and remote host)'.format(src_ip)})
    if 'sendmsg: Invalid argument' in result:
        raise serializers.ValidationError({'non_field_errors': 'ping: sendmsg: Invalid argument (not link between '
                                                               'local host and remote host)'.format(src_ip)})


def mtr_remote_endpoint_report_uninterrupted(instance, request, remote_endpoint_report, duration):
    if 'mtr_remote_endpoint_report_uninterrupted' not in queue_status:
        queue_status.append('mtr_remote_endpoint_report_uninterrupted')
    create_json('mtr', remote_endpoint_report, None, None)
    index = check_exsis_key(result_thread['mtr']['data'], 'remote_endpoint_report')
    index = index[0]

    try:
        end_time = duration * 60
        cmd = 'mtr -r {}  -o "LSDR NBAW VG JMXI"'.format(remote_endpoint_report)
        status, result = command_runner(cmd, True)

        data_chart = []
        if result:
            for line in result.split("\n"):

                row = line.split()
                if 'Start:' not in row and 'HOST:' not in row:
                    data_host = dict()
                    data_host['name'] = row[1]
                    series_default = []
                    series_default.append({'name': 'Loss ratio %', 'value': row[2]})  # Loss ratio
                    series_default.append({'name': 'Avg (Average RTT(ms))', 'value': row[8]})  # Average RTT(ms)
                    series_default.append({'name': 'Jttr (Current Jitter)', 'value': row[12]})  # Current Jitter
                    data_host['series_default'] = series_default

                    series_more = []
                    series_more.append({'name': 'Loss ratio %', 'value': row[2]})  # Loss ratio
                    series_more.append({'name': 'Snt (Send packet)', 'value': row[3]})  # Send packet
                    series_more.append({'name': 'Drop (Dropped packet)', 'value': row[4]})  # Dropped packet
                    series_more.append({'name': 'Rcv (Received packet)', 'value': row[5]})  # Received packet

                    series_more.append({'name': 'Last (Newest RTT(ms))', 'value': row[6]})  # Newest RTT(ms)
                    series_more.append({'name': 'Best (Min/Best RTT(ms))', 'value': row[7]})  # Min/Best RTT(ms)
                    series_more.append({'name': 'Avg (Average RTT(ms))', 'value': row[8]})  # Average RTT(ms)
                    series_more.append({'name': 'Wrst (Max/Worst RTT(ms))', 'value': row[9]})  # Max/Worst RTT(ms)

                    series_more.append({'name': 'StDev (Standard Deviation)', 'value': row[10]})  # Standard Deviation
                    series_more.append({'name': 'Gmean (Geometric Mean)', 'value': row[11]})  # Geometric Mean

                    series_more.append({'name': 'Jttr (Current Jitter)', 'value': row[12]})  # Current Jitter
                    series_more.append({'name': 'Javg (Jitter Mean/Avg.)', 'value': row[13]})  # Jitter Mean/Avg.
                    series_more.append({'name': 'Jmax (Worst Jitter)', 'value': row[14]})  # Worst Jitter
                    series_more.append({'name': 'Jint (Interarrival Jitter)', 'value': row[15]})  # Interarrival Jitter

                    data_host['series_more'] = series_more
                    data_chart.append(data_host)

        result_thread['mtr']['data'][index]['uninterrupted'] = data_chart

        instance.result = result_thread

        if 'mtr_remote_endpoint_report_uninterrupted' in queue_status:
            queue_status.remove('mtr_remote_endpoint_report_uninterrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['mtr']['data'][index]['uninterrupted'] = []
        result_thread['mtr']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def mtr_remote_host_report_uninterrupted(instance, request, remote_host_report, duration):
    if 'mtr_remote_host_report_uninterrupted' not in queue_status:
        queue_status.append('mtr_remote_host_report_uninterrupted')
    create_json('mtr', None, None, remote_host_report)
    index = check_exsis_key(result_thread['mtr']['data'], 'remote_host_report')
    index = index[0]

    try:
        end_time = duration * 60
        cmd = 'mtr -r {}  -o "LSDR NBAW VG JMXI"'.format(remote_host_report)
        status, result = command_runner(cmd, True)

        data_chart = []
        if result:
            for line in result.split("\n"):

                row = line.split()
                if 'Start:' not in row and 'HOST:' not in row:
                    data_host = dict()
                    data_host['name'] = row[1]

                    series_default = []
                    series_default.append({'name': 'Loss ratio %', 'value': row[2]})  # Loss ratio
                    series_default.append({'name': 'Avg (Average RTT(ms))', 'value': row[8]})  # Average RTT(ms)
                    series_default.append({'name': 'Jttr (Current Jitter)', 'value': row[12]})  # Current Jitter
                    data_host['series_default'] = series_default

                    series_more = []
                    series_more.append({'name': 'Loss ratio %', 'value': row[2]})  # Loss ratio
                    series_more.append({'name': 'Snt (Send packet)', 'value': row[3]})  # Send packet
                    series_more.append({'name': 'Drop (Dropped packet)', 'value': row[4]})  # Dropped packet
                    series_more.append({'name': 'Rcv (Received packet)', 'value': row[5]})  # Received packet

                    series_more.append({'name': 'Last (Newest RTT(ms))', 'value': row[6]})  # Newest RTT(ms)
                    series_more.append({'name': 'Best (Min/Best RTT(ms))', 'value': row[7]})  # Min/Best RTT(ms)
                    series_more.append({'name': 'Avg (Average RTT(ms))', 'value': row[8]})  # Average RTT(ms)
                    series_more.append({'name': 'Wrst (Max/Worst RTT(ms))', 'value': row[9]})  # Max/Worst RTT(ms)

                    series_more.append({'name': 'StDev (Standard Deviation)', 'value': row[10]})  # Standard Deviation
                    series_more.append({'name': 'Gmean (Geometric Mean)', 'value': row[11]})  # Geometric Mean

                    series_more.append({'name': 'Jttr (Current Jitter)', 'value': row[12]})  # Current Jitter
                    series_more.append({'name': 'Javg (Jitter Mean/Avg.)', 'value': row[13]})  # Jitter Mean/Avg.
                    series_more.append({'name': 'Jmax (Worst Jitter)', 'value': row[14]})  # Worst Jitter
                    series_more.append({'name': 'Jint (Interarrival Jitter)', 'value': row[15]})  # Interarrival Jitter

                    data_host['series_more'] = series_more

        result_thread['mtr']['data'][index]['uninterrupted'] = data_chart
        instance.result = result_thread

        if 'mtr_remote_host_report_uninterrupted' in queue_status:
            queue_status.remove('mtr_remote_host_report_uninterrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['mtr']['data'][index]['uninterrupted'] = []
        result_thread['mtr']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def conntrack_established_interrupted(instance, request, duration):
    if 'conntrack_established_interrupted' not in queue_status:
        queue_status.append('conntrack_established_interrupted')
    create_json('conntrack', None, None, None)
    index = check_exsis_key(result_thread['conntrack']['data'], 'established')
    index = index[0]

    try:
        end_time = duration * 60
        detail = []

        end_time = datetime.datetime.now() + datetime.timedelta(minutes=duration)
        while datetime.datetime.now() < end_time:
            cmd = "conntrack -L | grep 'ASSURED' | wc -l"
            status, result = sudo_runner(cmd, True)

            if result:
                result = result.split("\n")

                if len(result) > 1:
                    date_time = datetime.datetime.now().strftime("%H:%M:%S")
                    detail.append({'value': result[1], 'name': date_time})
            time.sleep(1)
        result_thread['conntrack']['data'][index]['interrupted'] = [{'name': 'ESTABLISHED', 'series': detail}]
        instance.result = result_thread

        if 'conntrack_established_interrupted' in queue_status:
            queue_status.remove('conntrack_established_interrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['conntrack']['data'][index]['interrupted'] = []
        result_thread['conntrack']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def conntrack_new_interrupted(instance, request, duration):
    if 'conntrack_new_interrupted' not in queue_status:
        queue_status.append('conntrack_new_interrupted')
    create_json('conntrack', 'mtr', None, None, None)
    index = check_exsis_key(result_thread['conntrack']['data'], 'new')
    index = index[0]

    try:
        end_time = duration * 60
        end_time = datetime.datetime.now() + datetime.timedelta(minutes=duration)
        detail = []
        pid_command = 0
        # while datetime.datetime.now() < end_time and not kill_thread:
        #     cmd = "sudo conntrack -E -e NEW | pv -l -i 1 -r > /dev/null"
        #     status, result = command_runner_popen(cmd, True)
        #     print(result)
        #
        #     if result:
        #         date_time = datetime.datetime.now().strftime("%H:%M:%S")
        #         detail.append({'value': result, 'name': date_time})
        #     time.sleep(1)

        cmd = "conntrack -E -e NEW | pv -l -i 1 -r > /dev/null"
        status, result = sudo_runner(cmd, True)
        # pid = result.pid
        stdout = []
        detail = ''
        while datetime.datetime.now() < end_time:
            line = result.stdout.readline()
            stdout.append(line)
            print
            line,
            if line == '' and result.poll() != None:
                break

        # os.kill(pid, signal.SIGKILL)

        detail = ''.join(stdout)

        # if not (datetime.datetime.now() < end_time and not kill_thread) :

        result_thread['conntrack']['data'][index]['interrupted'] = {'name': 'NEW', 'series': detail}
        instance.result = result_thread

        if 'conntrack_new_interrupted' in queue_status:
            queue_status.remove('conntrack_new_interrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['conntrack']['data'][index]['interrupted'] = []
        result_thread['conntrack']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()


def ram_cpu_interrupted(instance, request, duration):
    if 'ram_cpu_interrupted' not in queue_status:
        queue_status.append('ram_cpu_interrupted')
    create_json('ram_cpu', None, None, None)
    index = check_exsis_key(result_thread['ram_cpu']['data'], 'used')
    index = index[0]

    try:
        end_time = duration * 60
        end_time = datetime.datetime.now() + datetime.timedelta(minutes=duration)
        data_memory_used = []
        data_cpu_used = []

        while datetime.datetime.now() < end_time:
            data = dict()
            # used free
            # cmd_used = "free | awk 'FNR == 3 {print $3/($3+$4)*100 , $4/($3+$4)*100}'"
            # status, result = sudo_runner(cmd_used, True)
            # if result:
            date_time = datetime.datetime.now().strftime("%H:%M:%S")
            cpu = psutil.cpu_percent()
            data_cpu_used.append({'value': cpu, 'name': date_time})
            mem = psutil.virtual_memory()
            data_memory_used.append({'value': mem.percent, 'name': date_time})
            time.sleep(2)

        data_chart = []
        data_chart.append({'name': 'Memory Used %', 'series': data_memory_used})
        data_chart.append({'name': 'CPU Used %', 'series': data_cpu_used})
        result_thread['ram_cpu']['data'][index]['interrupted'] = data_chart
        instance.result = result_thread

        if 'ram_cpu_interrupted' in queue_status:
            queue_status.remove('ram_cpu_interrupted')

        if instance.status != 'failed' and instance.status != 'stopped':
            if len(queue_status) == 0:
                log('diagnosis', 'diagnosis_report', 'add', 'success',
                    username=request.user.username, ip=get_client_ip(request), details={'name': instance.name})
                instance.status = 'succeeded'
        instance.save()

    except Exception as e:
        log('diagnosis', 'diagnosis_report', 'add', 'fail',
            username=request.user.username, ip=get_client_ip(request), details={'error': str(e)})
        result_thread['ram_cpu']['data'][index]['interrupted'] = []
        result_thread['ram_cpu']['data'][index]['error'] = str(e)
        instance.result = result_thread
        instance.status = 'failed'
        instance.save()
