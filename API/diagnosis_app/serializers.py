from copy import deepcopy

from rest_framework import serializers

from api.settings import IS_TEST
from config_app.models import Interface
from diagnosis_app.models import Diagnosis
from diagnosis_app.utils import ping_dst_interrupted, ping_dst_uninterrupted, \
    ping_src_dst_interrupted, ping_src_dst_uninterrupted, check_ping_link, mtr_remote_endpoint_report_uninterrupted, \
    mtr_remote_host_report_uninterrupted, conntrack_established_interrupted, ram_cpu_interrupted
from utils.utils import run_thread


class DiagnosisSerializer(serializers.ModelSerializer):

    def validate_local_host_report(self, value):

        if value:
            # ip_list_real = [item['ip'] for item in get_all_ip_real()]

            list_of_ip_list = list(Interface.objects.filter().values_list('ip_list', flat=True))
            ip_list = [item['ip'] for ip_list in list_of_ip_list for item in ip_list]

            # ip_list = list(set(ip_list_real+ip_list))

            if value not in ip_list:
                raise serializers.ValidationError('This value is not in internal network.')
        return value

    def validate(self, data):
        if 'type' in data:

            if ('ping' or 'mtr') in data['type']:
                if 'remote_endpoint_report' in data and not data['remote_endpoint_report'] and \
                        'local_host_report' in data and not data['local_host_report'] and \
                        'remote_host_report' in data and not data['remote_host_report']:
                    raise serializers.ValidationError(
                        'At least set a remote endpoint or local host or remote host')

            if 'ping' in data['type']:
                if (not data['local_host_report'] and data['remote_host_report']) or \
                        (not data['remote_host_report'] and data['local_host_report']):
                    raise serializers.ValidationError('Fill both fields local host and remote host.')
                if data['local_host_report'] and data['remote_host_report']:
                    check_ping_link(data['local_host_report'], data['remote_host_report'])
        if Diagnosis.objects.filter(status='pending').count() > 0:
            raise serializers.ValidationError('The system is processing.')

        return data

    class Meta:
        model = Diagnosis
        fields = '__all__'

    def create(self, instance):

        if self.context['request'].method == 'POST':
            if Diagnosis.objects.all().count() >= 10:
                raise serializers.ValidationError(
                    {"non_field_errors": "The number of diagnosis report should not exceed 10"})

            instance = super(DiagnosisSerializer, self).create(instance)

            request_username = None
            request = None

            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']

            operation = 'add'
            instance.last_operation = operation
            instance.status = 'pending'
            instance.save()

            diagnosis_data = deepcopy(instance)
            if not IS_TEST:
                if 'ping' in instance.type:
                    if instance.remote_endpoint_report:
                        run_thread(target=ping_dst_interrupted, name='ping_dst_interrupted',
                                   args=(diagnosis_data, request, instance.remote_endpoint_report, instance.duration))
                        run_thread(target=ping_dst_uninterrupted, name='ping_dst_uninterrupted',
                                   args=(diagnosis_data, request, instance.remote_endpoint_report, instance.duration))

                    if instance.local_host_report and instance.remote_host_report:
                        run_thread(target=ping_src_dst_interrupted, name='ping_src_dst_interrupted',
                                   args=(
                                       diagnosis_data, request, instance.local_host_report, instance.remote_host_report,
                                       instance.duration))
                        run_thread(target=ping_src_dst_uninterrupted, name='ping_src_dst_uninterrupted',
                                   args=(
                                       diagnosis_data, request, instance.local_host_report, instance.remote_host_report,
                                       instance.duration))
                if 'mtr' in instance.type:
                    if instance.remote_endpoint_report:
                        run_thread(target=mtr_remote_endpoint_report_uninterrupted,
                                   name='mtr_uninterrupted_remote_endpoint_report',
                                   args=(diagnosis_data, request, instance.remote_endpoint_report, instance.duration))
                    if instance.remote_host_report:
                        run_thread(target=mtr_remote_host_report_uninterrupted,
                                   name='mtr_uninterrupted_remote_host_report',
                                   args=(diagnosis_data, request, instance.remote_host_report, instance.duration))

                if 'conntrack' in instance.type:
                    run_thread(target=conntrack_established_interrupted, name='conntrack_established_interrupted',
                               args=(diagnosis_data, request, instance.duration))

                    # run_thread(target=conntrack_new_interrupted, name='conntrack_new_interrupted',
                    #            args=(diagnosis_data, request, instance.duration))

                if 'ram_cpu' in instance.type:
                    run_thread(target=ram_cpu_interrupted, name='ram_cpu_interrupted',
                               args=(diagnosis_data, request, instance.duration))

            return instance
