import threading
from copy import deepcopy

import jsonschema
from django.db.models import Q
from rest_framework import serializers

from api.licence import ADDRESS_MAX_PORTS
from auth_app.utils import get_client_ip
from entity_app.models import Address, Schedule, Service, Application, CountryCode
from entity_app.utils import PortSerializer, PortRangeSerializer, check_address_validation, bulk_update_policy_list, \
    ProtocolNumberSerializer, TypeCodeSerializer
from firewall_app.models import Policy
from utils.log import log
from utils.serializers import get_diff
from utils.utils import run_thread
from vpn_app.models import VPN
from vpn_app.utils import update_vpn

result = dict()


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'

    def validate(self, data):
        if self.instance and (self.instance.type == 'ip' and len(self.instance.value_list) == 1) and \
                (data['type'] != 'ip' or len(data['value_list']) != 1 or
                 ('/' in data['value_list'][0] and '/32' not in data['value_list'][0])):
            existing_vpn_list = VPN.objects.all()
            for vpn in existing_vpn_list:
                if vpn.tunnel:
                    if vpn.tunnel.type == 'gre' or vpn.tunnel.type == 'ipip':
                        if data == vpn.tunnel.virtual_local_endpoint or \
                                data == vpn.tunnel.virtual_remote_endpoint or \
                                data == vpn.tunnel.real_remote_endpoint or \
                                data == vpn.tunnel.real_local_endpoint:
                            raise serializers.ValidationError(
                                'This value has been used in VPN and should be a single ip')
                    elif vpn.tunnel.type == 'vtun':
                        if data == vpn.tunnel.virtual_local_endpoint or \
                                data == vpn.tunnel.virtual_remote_endpoint:
                            raise serializers.ValidationError(
                                'This value has been used in VPN and should be a single ip')
                
                if self.instance.value_list == vpn.local_endpoint.value_list or \
                        self.instance.value_list == vpn.remote_endpoint.value_list:
                    raise serializers.ValidationError('This value has been used in VPN and should be a single ip')

        return data

    def validate_value_list(self, value):
        if not value:
            raise serializers.ValidationError('value list cannot be empty')
        if not isinstance(value, list):
            raise serializers.ValidationError('value list should be list of strings eg: ["192.168.1.1/32"]')

        for item in value:
            if not isinstance(item, str):
                raise serializers.ValidationError('value list should be list of strings eg: ["192.168.1.1/32"]')
            if item.split('.').pop() == '0':
                raise serializers.ValidationError('Enter a valid subnet mask for address that ends with 0')

        value = sorted(set(value))
        validation = check_address_validation(value, self.initial_data['type'])
        if validation is not True:
            raise serializers.ValidationError(validation)

        return value

    def create(self, instance):
        instance = super(AddressSerializer, self).create(instance)
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        details = {'items': self.validated_data}
        log('entity', 'address', 'add', 'success',
            username=request_username, ip=get_client_ip(request), details=details)
        return instance

    def update(self, instance, validated_data):
        changes = get_diff(instance, AddressSerializer, validated_data, ['is_user_defined'])
        instance = super(AddressSerializer, self).update(instance, validated_data)
        related_policy_list = Policy.objects.filter(
            Q(source_destination__src_network_list=instance) | Q(source_destination__dst_network_list=instance))

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        t = threading.Thread(target=bulk_update_policy_list, args=(related_policy_list, request_username))
        t.start()
        related_vpn_list = VPN.objects.filter(Q(local_network=instance)
                                              | Q(remote_network=instance)
                                              | Q(local_endpoint=instance)
                                              | Q(remote_endpoint=instance)
                                              | Q(tunnel__real_local_endpoint=instance)
                                              | Q(tunnel__virtual_local_endpoint=instance)
                                              | Q(tunnel__real_remote_endpoint=instance)
                                              | Q(tunnel__virtual_remote_endpoint=instance)
                                              | Q(tunnel__server_endpoint=instance))

        for vpn in related_vpn_list:
            old_vpn = deepcopy(vpn)
            if not hasattr(old_vpn, 'tunnel'):
                setattr(old_vpn, 'tunnel', {})
                setattr(old_vpn.tunnel, 'name', old_vpn.name)
            old_vpn = old_vpn.__dict__
            old_vpn.pop('_state')
            old_vpn.pop('_django_version')

            old_tunnel = None
            if hasattr(instance, 'tunnel') and instance.tunnel:
                old_tunnel = deepcopy(instance.tunnel)
            if old_tunnel:
                old_tunnel = old_tunnel.__dict__
                old_tunnel.pop('_state', None)
                old_tunnel.pop('_django_version', None)

            run_thread(target=update_vpn, name='vpn_{}'.format(vpn.id),
                       args=(vpn, old_vpn, old_tunnel, request_username, None, None, True))

        # todo: update separate nat
        # todo: update separate pbr
        log('entity', 'address', 'update', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)
        return instance


class ServiceSerializer(serializers.ModelSerializer):

    def check_port(self, port_list, name):
        global result

        if name == 'protocol_number':
            serializer = ProtocolNumberSerializer(data={'port': port_list})
            if not serializer.is_valid():
                result[name] = serializer.errors

        elif name == 'type' or name == 'code':
            serializer = TypeCodeSerializer(data={'port': port_list})
            if not serializer.is_valid():
                result[name] = serializer.errors

        else:
            if not isinstance(port_list, list):
                raise serializers.ValidationError('{} should be list'.format(name))

            ports = sorted(set([str(item).strip() for item in port_list]))

            for port in ports:
                if '-' in port:
                    serializer = PortRangeSerializer(data={'start_port': port.split('-')[0],
                                                           'end_port': port.split('-')[1]})
                else:
                    serializer = PortSerializer(data={'port': port})
                if not serializer.is_valid():
                    result[name] = serializer.errors

    def validate(self, data):
        global result
        result.clear()

        request = self.context.get('request')
        protocol = data.get('protocol', None)
        name = data.get('name', None)
        # if (name == 'ALL-TCP' and 'tcp' in protocol and protocol['tcp'] == {}) or \
        #         (name == 'ALL-UDP' and 'udp' in protocol and protocol['udp'] == {}) or \
        #         (name == 'ALL-ICMP' and 'icmp' in protocol and protocol['icmp'] == {}):
        #     return data
        # elif name == 'ALL-TCP':
        #     raise serializers.ValidationError('ALL-TCP must a json with tcp key and null json value')
        # elif name == 'ALL-UDP':
        #     raise serializers.ValidationError('ALL-UDP must a json with udp key and null json value')
        # elif name == 'ALL-ICMP':
        #     raise serializers.ValidationError('ALL-ICMP must a json with icmp key and null json value')

        if protocol:
            if 'tcp' in protocol:
                if 'src' in protocol['tcp'] and protocol['tcp']['src']:
                    if len(protocol['tcp']['src']) > ADDRESS_MAX_PORTS:
                        raise serializers.ValidationError('Number of tcp source ports exceeded, {} entries are allowed'.format(ADDRESS_MAX_PORTS))
                if 'dst' in protocol['tcp'] and protocol['tcp']['dst']:
                    if len(protocol['tcp']['dst']) > ADDRESS_MAX_PORTS:
                        raise serializers.ValidationError('Number of tcp destination ports exceeded, {} entries are allowed'.format(ADDRESS_MAX_PORTS))
            if 'udp' in protocol:
                if 'src' in protocol['udp'] and protocol['udp']['src']:
                    if len(protocol['udp']['src']) > ADDRESS_MAX_PORTS:
                        raise serializers.ValidationError('Number of udp source ports exceeded, {} entries are allowed'.format(ADDRESS_MAX_PORTS))
                if 'dst' in protocol['udp'] and protocol['udp']['dst']:
                    if len(protocol['udp']['dst']) > ADDRESS_MAX_PORTS:
                        raise serializers.ValidationError('Number of udp destination ports exceeded, {} entries are allowed'.format(ADDRESS_MAX_PORTS))

            if 'ip' not in protocol and \
                    'tcp' not in protocol and \
                    'udp' not in protocol and \
                    'icmp' not in protocol:
                raise serializers.ValidationError('Protocol must be one of tcp or udp or icmp or ip')

            if 'tcp' in protocol and 'udp' in protocol:

                if not protocol['tcp'] or not protocol['udp']:
                    raise serializers.ValidationError(
                        'At least one tcp source port or tcp destination port or udp source port or udp destination '
                        'port, should be specified')
                elif not isinstance(protocol['tcp'], dict):
                    raise serializers.ValidationError('TCP is not dictionary')
                elif not isinstance(protocol['udp'], dict):
                    raise serializers.ValidationError('UDP is not dictionary')
                else:
                    for key, value in protocol['tcp'].items():
                        if key not in ['dst', 'src']:
                            raise serializers.ValidationError(
                                'Bad json key for tcp source or tcp destination port')
                    for key, value in protocol['udp'].items():
                        if key not in ['dst', 'src']:
                            raise serializers.ValidationError(
                                'Bad json key for udp source port or udp destination port')

            elif 'tcp' in protocol:
                if not protocol['tcp']:
                    raise serializers.ValidationError(
                        'At least one tcp source or tcp destination port should be specified')
                elif not isinstance(protocol['tcp'], dict):
                    raise serializers.ValidationError('TCP is not dictionary')
                else:
                    for key, value in protocol['tcp'].items():
                        if key not in ['dst', 'src']:
                            raise serializers.ValidationError(
                                'Bad json key for tcp source port or tcp destination port')

            elif 'udp' in protocol:
                if not protocol['udp']:
                    raise serializers.ValidationError(
                        'At least one udp source or udp destination port should be specified')
                elif not isinstance(protocol['udp'], dict):
                    raise serializers.ValidationError('UDP is not dictionary')
                else:
                    for key, value in protocol['udp'].items():
                        if key not in ['dst', 'src']:
                            raise serializers.ValidationError(
                                'Bad json key for udp source or udp destination port')

            if 'icmp' in protocol and (not protocol['icmp'] or 'type' not in protocol['icmp']):
                raise serializers.ValidationError('Type should be specified')

            if 'ip' in protocol and (not protocol['ip'] or 'protocol_number' not in protocol['ip']):
                raise serializers.ValidationError('Protocol number should be specified')

            tcp_src_port = None
            if 'tcp' in protocol and 'src' in protocol['tcp']:
                tcp_src_port = protocol['tcp']['src']

            tcp_dst_port = None
            if 'tcp' in protocol and 'dst' in protocol['tcp']:
                tcp_dst_port = protocol['tcp']['dst']

            udp_src_port = None
            if 'udp' in protocol and 'src' in protocol['udp']:
                udp_src_port = protocol['udp']['src']

            udp_dst_port = None
            if 'udp' in protocol and 'dst' in protocol['udp']:
                udp_dst_port = protocol['udp']['dst']

            protocol_number = None
            if 'ip' in protocol and 'protocol_number' in protocol['ip']:
                protocol_number = protocol['ip']['protocol_number']

            type = None
            if 'icmp' in protocol and 'type' in protocol['icmp']:
                type = protocol['icmp']['type']

            code = None
            if 'icmp' in protocol and 'code' in protocol['icmp']:
                code = protocol['icmp']['code']

            if tcp_src_port:
                self.check_port(tcp_src_port, 'tcp_src_port_list')
            if tcp_dst_port:
                self.check_port(tcp_dst_port, 'tcp_dst_port_list')
            if udp_src_port:
                self.check_port(udp_src_port, 'udp_src_port_list')
            if udp_dst_port:
                self.check_port(udp_dst_port, 'udp_dst_port_list')
            if protocol_number:
                self.check_port(protocol_number, 'protocol_number')
            if code:
                self.check_port(code, 'code')
            if type:
                self.check_port(type, 'type')
            if result != {}:
                raise serializers.ValidationError(result)

            if 'tcp' in protocol and 'udp' in protocol:
                if tcp_src_port and tcp_dst_port and udp_src_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port, "dst": tcp_dst_port},
                                         "udp": {"src": udp_src_port, "dst": udp_dst_port}})
                elif tcp_src_port and tcp_dst_port and udp_src_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port, "dst": tcp_dst_port},
                                         "udp": {"src": udp_src_port}})
                elif tcp_src_port and tcp_dst_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port, "dst": tcp_dst_port},
                                         "udp": {"dst": udp_dst_port}})
                elif tcp_src_port and udp_src_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port},
                                         "udp": {"src": udp_src_port, "dst": udp_dst_port}})
                elif tcp_dst_port and udp_src_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"dst": tcp_dst_port},
                                         "udp": {"src": udp_src_port, "dst": udp_dst_port}})
                elif tcp_src_port and udp_src_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port},
                                         "udp": {"src": udp_src_port}})
                elif tcp_src_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port},
                                         "udp": {"dst": udp_dst_port}})
                elif tcp_dst_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"dst": tcp_dst_port},
                                         "udp": {"dst": udp_dst_port}})
                elif tcp_dst_port and udp_src_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"dst": tcp_dst_port},
                                         "udp": {"src": udp_src_port}})

                if request.method != 'POST':
                    if similar_services.exclude(id=self.instance.id):
                        pass
                elif similar_services.exists():
                    raise serializers.ValidationError(
                        'The fields tcp source port and tcp destination port and udp source port and '
                        'udp destination port, must make a unique set')

            elif 'tcp' in protocol:
                if tcp_src_port and tcp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port, "dst": tcp_dst_port}})
                elif tcp_src_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"src": tcp_src_port}})
                elif tcp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"tcp": {"dst": tcp_dst_port}})

                if request.method != 'POST':
                    if similar_services.exclude(id=self.instance.id):
                        pass
                elif similar_services.exists():
                    raise serializers.ValidationError(
                        'The fields tcp source port and tcp destination port, must make a unique set')

            elif 'udp' in protocol:
                if udp_src_port and udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"udp": {"src": udp_src_port, "dst": udp_dst_port}})
                elif udp_src_port:
                    similar_services = Service.objects. \
                        filter(protocol={"udp": {"src": udp_src_port}})
                elif udp_dst_port:
                    similar_services = Service.objects. \
                        filter(protocol={"udp": {"dst": udp_dst_port}})

                if request.method != 'POST':
                    if similar_services.exclude(id=self.instance.id):
                        pass
                elif similar_services.exists():
                    raise serializers.ValidationError(
                        'The fields udp source port and udp destination port must make a unique set')

            if 'icmp' in protocol:
                if type and code:
                    similar_services = Service.objects. \
                        filter(protocol={"icmp": {"type": type, "code": code}})
                elif 'type':
                    similar_services = Service.objects. \
                        filter(protocol={"icmp": {"type": type}})
                elif 'code':
                    similar_services = Service.objects. \
                        filter(protocol={"icmp": {"code": type}})

                if request.method != 'POST':
                    if similar_services.exclude(id=self.instance.id):
                        pass
                elif similar_services.exists():
                    raise serializers.ValidationError(
                        "The fields type and code must make a unique set")

            if 'ip' in protocol:
                similar_services = Service.objects. \
                    filter(protocol={"ip": {"protocol_number": protocol_number}})

                if request.method != 'POST':
                    if similar_services.exclude(id=self.instance.id):
                        pass
                elif similar_services.exists():
                    raise serializers.ValidationError(
                        "The fields protocol number must make a unique set")

            return data

        else:
            raise serializers.ValidationError("The protocol can not null")

    class Meta:
        model = Service
        fields = '__all__'
        read_only_fields = ('is_user_defined',)

    def create(self, instance):
        instance = super(ServiceSerializer, self).create(instance)
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        details = {'items': self.validated_data}
        log('entity', 'service', 'add', 'success',
            username=request_username, ip=get_client_ip(request), details=details)
        return instance

    def update(self, instance, validated_data):
        changes = get_diff(instance, ServiceSerializer, validated_data, ['is_user_defined'])
        instance = super(ServiceSerializer, self).update(instance, validated_data)
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        related_policies = Policy.objects.filter(source_destination__service_list=instance)
        log('config', 'service', 'update', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)
        t = threading.Thread(target=bulk_update_policy_list, args=(related_policies, request_username))
        t.start()

        # todo: update separate nat
        # todo: update separate pbr

        return instance


class ScheduleSerializer(serializers.ModelSerializer):
    def validate_days_of_week(self, value):
        schema = {
            'type': 'object',
            'properties': {
                'sunday': {'type': 'boolean'},
                'monday': {'type': 'boolean'},
                'tuesday': {'type': 'boolean'},
                'wednesday': {'type': 'boolean'},
                'thursday': {'type': 'boolean'},
                'friday': {'type': 'boolean'},
                'saturday': {'type': 'boolean'},
            },
            "additionalProperties": False,
            "required": ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"]
        }
        try:
            jsonschema.validate(value, schema)
        except jsonschema.exceptions.ValidationError:
            raise serializers.ValidationError('invalid json format for days of week')

        return value

    def validate(self, data):
        request = self.context.get('request')
        start_date = data.get('start_date', None)
        end_date = data.get('end_date', None)
        start_time = data.get('start_time', None)
        end_time = data.get('end_time', None)
        days_of_week = data.get('days_of_week', None)

        all_days_False = True
        for key in days_of_week.keys():
            if days_of_week[key]:
                all_days_False = False

        if request.method in ['POST', 'PUT'] and \
                all(field is None for field in [start_date, end_date, start_time, end_time]) and \
                all_days_False:
            raise serializers.ValidationError('At least set a start/end time/date or days of week for schedule')

        if request.method == 'PATCH' and \
                all(field in data for field in ['start_date', 'end_date', 'start_time', 'end_time']) and \
                all(data[field] is None for field in ['start_date', 'end_date', 'start_time', 'end_time']) and \
                all_days_False:
            raise serializers.ValidationError('At least set a start/end time/date or days of week for schedule')

        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError('start_date must be before end_date')

        similar_schedules = Schedule.objects. \
            filter(start_date=start_date, end_date=end_date, start_time=start_time, end_time=end_time,
                   days_of_week=days_of_week)

        if request.method != 'POST':
            similar_schedules = similar_schedules.exclude(id=self.instance.id)

        if similar_schedules.exists():
            raise serializers.ValidationError(
                "The fields start_date, end_date, start_time, end_time, days_of_week must make a unique set.")

        return data

    class Meta:
        model = Schedule
        fields = '__all__'

    def create(self, instance):
        instance = super(ScheduleSerializer, self).create(instance)
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        items = {}
        for k, v in self.initial_data.items():
            if k == 'start_date':
                items['start date'] = str(instance.start_date)
            elif k == 'end_date':
                items['end_date'] = str(instance.end_date)
            elif k == 'start_time':
                items['start time'] = str(instance.start_time)
            elif k == 'end_time':
                items['end time'] = str(instance.end_time)
            else:
                items[k] = v

        details = {'items': items}
        log('entity', 'schedule', 'add', 'success',
            username=request_username, ip=get_client_ip(request), details=details)

        return instance

    def update(self, instance, validated_data):
        changes = get_diff(instance, ScheduleSerializer, self.initial_data, ['is_user_defined'])
        instance = super(ScheduleSerializer, self).update(instance, validated_data)
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        related_policies = Policy.objects.filter(schedule=instance)
        log('config', 'schedule', 'update', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)
        t = threading.Thread(target=bulk_update_policy_list, args=(related_policies, request_username))
        t.start()

        # todo: update separate nat

        return instance


class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application
        fields = '__all__'


class CountryCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CountryCode
        fields = '__all__'
