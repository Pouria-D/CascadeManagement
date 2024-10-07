from copy import deepcopy

from django.db import transaction
from django.utils.translation import gettext as _
from rest_framework import serializers

from api.licence import POLICY_MAX_COUNT, POLICY_MAX_NETWORK, POLICY_MAX_GEOIP, POLICY_MAX_SERVICE
from auth_app.utils import get_client_ip
from config_app.models import Interface, HighAvailability, Setting
from config_app.serializers import InterfaceSerializer
from config_app.utils import getPolicyInfo, get_sorted_interface_name_list, get_peer2_interface_list, check_use_bridge, \
    check_use_vlan
from entity_app.models import Schedule
from entity_app.serializers import AddressSerializer, ServiceSerializer, CountryCodeSerializer, ScheduleSerializer
from firewall_app.models import Policy, NAT, PBR, SourceDestination, QOS
from parser_utils.mod_policy.policy import add_policy, update_policy, is_policy_applied
from qos_utils.utils import MIN_CLASS_ID, MAX_CLASS_ID
from report_app.models import Notification
from utils.log import log
from utils.serializers import get_diff
from utils.utils import run_thread


class SourceDestinationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SourceDestination
        fields = '__all__'

    def validate(self, data):
        # todo: add users and groups

        if (
                ('src_interface_list' not in data or not data['src_interface_list']) and
                ('dst_interface_list' not in data or not data['dst_interface_list']) and
                ('src_network_list' not in data or not data['src_network_list']) and
                ('dst_network_list' not in data or not data['dst_network_list']) and
                ('service_list' not in data or not data['service_list']) and
                # ('application_list' not in data or not data['application_list']) and
                ('src_geoip_country_list' not in data or not data['src_geoip_country_list']) and
                ('dst_geoip_country_list' not in data or not data['dst_geoip_country_list'])
        ):
            raise serializers.ValidationError('At least one source or destination must be specified')

        for inter in data['src_interface_list']:
            if check_use_bridge(inter.name):
                raise serializers.ValidationError('interface {} is used in bridge '.format(inter.name))
            if check_use_vlan(inter.name):
                raise serializers.ValidationError('interface {} is used in vlan'.format(inter.name))

        for inter in data['dst_interface_list']:
            if check_use_bridge(inter.name):
                raise serializers.ValidationError('interface {} is used in bridge '.format(inter.name))
            if check_use_vlan(inter.name):
                raise serializers.ValidationError('interface {} is used in vlan'.format(inter.name))

        if data['src_network_list']:
            cnt = 0
            for net in data['src_network_list']:
                cnt += len(net.value_list)
            if cnt > POLICY_MAX_NETWORK:
                raise serializers.ValidationError(
                    'Number of source network items of Policy exceeded, {} values are allowed'.format(
                        POLICY_MAX_NETWORK))

        if data['dst_network_list']:
            cnt = 0
            for net in data['dst_network_list']:
                cnt += len(net.value_list)
            if cnt > POLICY_MAX_NETWORK:
                raise serializers.ValidationError(
                    'Number of destination network items of Policy exceeded, {} values are allowed'.format(
                        POLICY_MAX_NETWORK))

        if data['src_geoip_country_list']:
            if len(data['src_geoip_country_list']) > POLICY_MAX_GEOIP:
                raise serializers.ValidationError('Number of source geo ip items of Policy exceeded, {} entries are allowed'.format(POLICY_MAX_GEOIP))

        if data['dst_geoip_country_list']:
            if len(data['dst_geoip_country_list']) > POLICY_MAX_GEOIP:
                raise serializers.ValidationError('Number of destination geo ip items of Policy exceeded, {} entries are allowed'.format(POLICY_MAX_GEOIP))

        if data['service_list']:
            if len(data['service_list']) > POLICY_MAX_SERVICE:
                raise serializers.ValidationError('Number of service items of Policy exceeded, {} entries are allowed'.format(POLICY_MAX_SERVICE))
        if HighAvailability.objects.filter(is_enabled=True):
            src_and_dst_interface_list = list(set(data['src_interface_list'] + data['dst_interface_list']))
            peer2_interface_list = get_sorted_interface_name_list(
                get_peer2_interface_list(HighAvailability.objects.get().peer2_address,
                                         ssh_port=Setting.objects.get(key='ssh-port').data['value'],
                                         https_port=Setting.objects.get(key='https-port').data['value']))
            not_sync_interface_list = []
            for interface in src_and_dst_interface_list:
                if interface.name not in peer2_interface_list:
                    not_sync_interface_list.append(interface.name)
            if not_sync_interface_list:
                raise serializers.ValidationError(
                    'HighAvailability has been configured and the selected {interface} does not '
                    'exist on Node2 system, add {interface} there and then try again.'.format(
                        interface=', '.join(not_sync_interface_list)))
        return data


class SourceDestinationReadSerializer(serializers.ModelSerializer):
    src_interface_list = InterfaceSerializer(many=True)
    dst_interface_list = InterfaceSerializer(many=True)
    src_network_list = AddressSerializer(many=True)
    dst_network_list = AddressSerializer(many=True)
    service_list = ServiceSerializer(many=True)
    # application_list = ApplicationSerializer(many=True)
    src_geoip_country_list = CountryCodeSerializer(many=True)
    dst_geoip_country_list = CountryCodeSerializer(many=True)

    class Meta:
        model = SourceDestination
        fields = '__all__'


class NATSerializer(serializers.ModelSerializer):
    source_destination = SourceDestinationSerializer(required=False)

    def validate_port(self, value):
        if value and not value.isdigit():
            raise serializers.ValidationError('A valid integer is required')
        return value

    def validate(self, data):
        if "nat_type" in data:
            if data["nat_type"] == "SNAT":

                if "snat_type" not in data or not data["snat_type"]:
                    raise serializers.ValidationError("Choose SNAT type")

                if ('src_interface_list' in data['source_destination'] and
                        data['source_destination']['src_interface_list']):
                    raise serializers.ValidationError({'non_field_errors': 'When using SNAT, you should not set incoming interface'})

                if 'src_geoip_country_list' in data['source_destination'] and \
                        data['source_destination']['src_geoip_country_list']:
                    raise serializers.ValidationError("When using SNAT, you should not set source GEOIP")

                if "snat_type" in data and data["snat_type"] == "interface_ip":
                    if 'dst_interface_list' not in data['source_destination'] or \
                            not data['source_destination']['dst_interface_list']:
                        raise serializers.ValidationError({'non_field_errors': 'When using SNAT with interface ip option, you should specify outgoing interface'})

                if "snat_type" in data and data["snat_type"] == "static_ip":
                    if "ip" not in data or not data['ip']:
                        raise serializers.ValidationError("Enter IP for SNAT type static_ip")

                    if "ip" in data and data["ip"]:
                        # 'if not dst interface in data: 'not lo' should add to dst interface list -> done in policy.py

                        if ('dst_interface_list' not in data['source_destination'] or
                            not data['source_destination']['dst_interface_list']) \
                                and ('src_network_list' not in data['source_destination'] or
                                     not data['source_destination']['src_network_list']) \
                                and ('dst_network_list' not in data['source_destination'] or
                                     not data['source_destination']['dst_network_list']):
                            raise serializers.ValidationError(
                                {'non_field_errors': 'Source or destination network or \
                                                  outgoing interface must be specified'})

                        if ('src_network_list' in data['source_destination'] and
                            data['source_destination']['src_network_list']) or \
                                ('dst_network_list' in data['source_destination'] and
                                 data['source_destination']['dst_network_list']):
                            list_of_int_ip_list = list(Interface.objects.filter().values_list("ip_list", flat=True))
                            int_ip_list = [ip_mask['ip'] for ip_mask in list_of_int_ip_list if 'ip' in ip_mask]
                            if data['source_destination']['src_network_list']:
                                list_of_net_list = list(address.value_list
                                                        for address in data['source_destination']['src_network_list'])
                                net_list = [item for sublist in list_of_net_list for item in sublist]
                                if set(net_list).intersection(set(int_ip_list)):
                                    raise serializers.ValidationError(
                                        {'non_field_errors': 'When using SNAT, Source network address should not contain'
                                                             ' interfaces address'})
                            if data['source_destination']['dst_network_list']:
                                list_of_net_list = list(address.value_list
                                                        for address in data['source_destination']['dst_network_list'])
                                net_list = [item for sublist in list_of_net_list for item in sublist]
                                if set(net_list).intersection(set(int_ip_list)):
                                    raise serializers.ValidationError(
                                        {
                                            'non_field_errors': 'When using SNAT, Destination network address '
                                                                'should not contain interfaces address'})

                        if 'src_network_list' in data['source_destination'] and \
                                data['source_destination']['src_network_list']:
                            pass  # TODO: warning!!! "Mapping source IP to a specific IP for all destination IPs will hide the source information in the device’s logs."

                # TODO: what is this line belllow?
                if 'src_network_list' in data['source_destination'] and data['source_destination']['src_network_list']:
                    for src_network in data['source_destination']['src_network_list']:
                        if src_network.type == 'mac':
                            raise serializers.ValidationError({'non_field_errors':
                                                                   'When SNAT is active, source network list cannot '
                                                                   'contain MAC type'})

            if data["nat_type"] == "DNAT":
                if ("ip" not in data or not data['ip']) and \
                        ("port" not in data or not data["port"]):
                    raise serializers.ValidationError("Enter IP or port for DNAT")

                if (
                        'dst_network_list' not in data['source_destination'] or
                        not data['source_destination']['dst_network_list']
                ) and (
                        'src_interface_list' not in data['source_destination'] or
                        not data['source_destination']['src_interface_list']
                ):
                    raise serializers.ValidationError({'non_field_errors': 'Destination network or \
                                                  incoming interface must be specified'})

                if ('dst_interface_list' in data['source_destination'] and
                        data['source_destination']['dst_interface_list']):
                    raise serializers.ValidationError({'non_field_errors': 'DNAT cannot have outgoing interface'})

                if 'dst_geoip_country_list' in data['source_destination'] and \
                        data['source_destination']['dst_geoip_country_list']:
                    raise serializers.ValidationError("When using DNAT, you should not specify destination GEOIP")
                # if ("ip" in data and data['ip']) and\ ("port" not in self.initial_data or not self.initial_data[
                # "port"]): if 'service_list' not in self.initial_data['source_destination'] or \ not
                # self.initial_data['source_destination']['service_list']: raise serializers.ValidationError(list(
                # Setting.objects.filter(key="ssh-port")\ .values_list("value").get())) #         # TODO: add not
                # setting ports to service list? #         # TODO:   and a critical warning :You are going to publish
                #  all IPs to an specific IP without any service or port, this may be very dangerous and can
                # disrupted some of your service functionality, are you sure?
                if "port" in data and data["port"]:
                    if 'service_list' not in data['source_destination'] or \
                            not data['source_destination']['service_list']:
                        raise serializers.ValidationError("services must be be defined with DNAT")

                    if not str(data["port"]).isdigit() or int(data["port"]) < 1 or int(data["port"]) > 65535:
                        raise serializers.ValidationError(
                            {'port': 'Please enter a valid port number'})

                    if 'dst_network_list' in data['source_destination']:  # and if this address is equal to our ip :
                        pass  # TODO: then setting ports should not be used as map port

                    if (
                            'src_port_list' not in data['source_destination'] or
                            not data['source_destination']['service_list']['src_port_list']) and \
                            (
                                    'dst_port_list' not in data['source_destination'] or
                                    not data['source_destination']['service_list']['dst_port_list']
                            ):
                        pass  # TODO: You are going to publish a generic service to an specific port, this may be
                        # very dangerous and can disrupted some of your service functionality, are you sure?

                    if "ip" in data and data['ip']:
                        if ('dst_network_list' not in data['source_destination'] or
                            not data['source_destination']['dst_network_list']) and \
                                ('service_list' not in data['source_destination'] or
                                 not data['source_destination']['service_list']):
                            pass  # TODO: critical warning: You are going to publish a generic service from all IPs
                            # to a specific IP and port, this may be very dangerous and can disrupted some of your
                            # service functionality, are you sure?

                    for service in data['source_destination']['service_list']:
                        if "tcp" not in service.protocol.keys() and "udp" not in service.protocol.keys():
                            raise serializers.ValidationError("service protocol with DNAT should be tcp or udp")

                    # TODO: is it required?
                    # should_raise_error = True
                    # for item in cleaned_data['services']:
                    #     if item.name in ['ALL_TCP', 'ALL_UDP']:
                    #         should_raise_error = False
                    #         break
                    #
                    #     if item.l4_protocols.filter(protocol__in=['TCP', 'UDP']):
                    #         should_raise_error = False
                    #         break
                    #
                    # if should_raise_error:
                    #     raise ValidationError(
                    #         {"services": _(
                    #             "At least on TCP or UDP service must be defined with DNAT(Publish) selected")}
                    #     )

        return data

    class Meta:
        model = NAT
        fields = '__all__'

    def create(self, validated_data):
        # if ("ip" in self.initial_data and self.initial_data['ip']) and\
        #         ("port" not in self.initial_data or not self.initial_data["port"]):
        #     if 'service_list' not in self.initial_data['source_destination'] or \
        #             not self.initial_data['source_destination']['service_list']:
        #         system_ports = Service.objects.create(
        #             name= "__default-ports",
        #             protocol="tcp",
        #             dst_port_list=[
        #                 str(Setting.objects.filter(key="ssh-port").values_list("value", flat=True)),
        #                 str(Setting.objects.filter(key="http-port").values_list("value", flat=True)),
        #                 str(Setting.objects.filter(key="https-port").values_list("value", flat=True))
        #                ]
        #         )
        #         print("###############################################")
        #         print(system_ports)
        #         validated_data['source_destination']['service_list'] = system_ports
        #         print(validated_data)

        if 'instance' in self.initial_data['source_destination']:
            source_destination_instance = self.initial_data['source_destination']['instance']
            validated_data.pop('source_destination')
            nat = NAT.objects.create(**validated_data, source_destination=source_destination_instance)
        else:
            nat = NAT.objects.create(**validated_data)
        return nat

    def update(self, instance, validated_data):
        # if ("ip" in validated_data and validated_data['ip']) and\
        #         ("port" not in self.initial_data or not self.initial_data["port"]):
        #     if 'service_list' not in self.initial_data['source_destination'] or \
        #             not self.initial_data['source_destination']['service_list']:
        #         system_ports = Service.objects.create(
        #             protocol="tcp",
        #             dst_port_list=[
        #                 str(Setting.objects.filter(key="ssh-port").values_list("value")),
        #                 str(Setting.objects.filter(key="http-port").values_list("value")),
        #                 str(Setting.objects.filter(key="https-port").values_list("value"))
        #             ]
        #         )
        #         validated_data['source_destination']['service_list'] = system_ports

        source_destination_data = validated_data.pop('source_destination')
        schedule_data = validated_data.pop('schedule', None)

        with transaction.atomic():
            instance.source_destination.__dict__.update(source_destination_data)
            instance.source_destination.save()
            instance.source_destination.src_network_list.set(source_destination_data.get('src_network_list'))
            instance.source_destination.dst_network_list.set(source_destination_data.get('dst_network_list'))
            instance.source_destination.service_list.set(source_destination_data.get('service_list'))
            # instance.source_destination.application_list.set(source_destination_data.get('application_list'))
            instance.source_destination.src_interface_list.set(source_destination_data.get('src_interface_list'))
            instance.source_destination.dst_interface_list.set(source_destination_data.get('dst_interface_list'))

            if instance.schedule and schedule_data:
                instance.schedule.__dict__.update(schedule_data)
                instance.schedule.save()

            elif schedule_data:
                instance.schedule = Schedule.objects.create(**schedule_data)

            elif instance.schedule:
                instance.schedule = None

            instance.__dict__.update(**validated_data)
            instance.save()

            return instance


class PBRSerializer(serializers.ModelSerializer):
    source_destination = SourceDestinationSerializer(required=False)

    def validate(self, data):
        if 'is_enabled' in data and data['is_enabled']:
            if (
                    'dst_interface_list' not in data['source_destination'] or
                    not data['source_destination']['dst_interface_list']
            ):
                raise serializers.ValidationError(
                    "One destination interface should be selected when pbr is enabled")
            elif 'dst_interface_list' in data['source_destination'] and len(
                    data['source_destination']['dst_interface_list']) > 1:
                raise serializers.ValidationError(
                    "Exactly one destination interface should be selected when pbr is enabled")
        return data

    def create(self, validated_data):
        if 'instance' in self.initial_data['source_destination']:
            source_destination_instance = self.initial_data['source_destination']['instance']
            validated_data.pop('source_destination')
            pbr = PBR.objects.create(**validated_data, source_destination=source_destination_instance)
        else:
            pbr = PBR.objects.create(**validated_data)
        return pbr

    def update(self, instance, validated_data):
        source_destination_data = validated_data.pop('source_destination')

        with transaction.atomic():
            instance.source_destination.__dict__.update(source_destination_data)
            instance.source_destination.save()
            instance.source_destination.src_network_list.set(source_destination_data.get('src_network_list'))
            instance.source_destination.dst_network_list.set(source_destination_data.get('dst_network_list'))
            instance.source_destination.service_list.set(source_destination_data.get('service_list'))
            # instance.source_destination.application_list.set(source_destination_data.get('application_list'))
            instance.source_destination.src_interface_list.set(source_destination_data.get('src_interface_list'))
            instance.source_destination.dst_interface_list.set(source_destination_data.get('dst_interface_list'))

            instance.__dict__.update(**validated_data)
            instance.save()

            return instance

    class Meta:
        model = PBR
        fields = '__all__'


class QOSSerializer(serializers.ModelSerializer):
    class Meta:
        model = QOS
        fields = '__all__'
        depth = 1

    def generate_class_id(self):
        import random
        ex_id_list = QOS.objects.values_list('class_id')
        while True:
            new_class_id = random.randint(MIN_CLASS_ID, MAX_CLASS_ID)
            if ex_id_list and new_class_id in ex_id_list:
                continue
            return new_class_id

    def validate_download_guaranteed_bw(self, value):
        if not value or value <= 0:
            raise serializers.ValidationError('A positive integer is required')
        return value

    def validate_download_max_bw(self, value):
        if value and value <= 0:
            raise serializers.ValidationError('A positive integer is required')
        return value

    def validate(self, data):

        if 'download_guaranteed_bw' in data and data['download_guaranteed_bw'] and 'download_max_bw' in data and data['download_max_bw']:
            if data['download_guaranteed_bw'] > data['download_max_bw']:
                raise serializers.ValidationError('download guaranteed bandwidth should be less than download max bandwidth')
        if ('download_guaranteed_bw' not in data or not data['download_guaranteed_bw']) and \
            ('download_max_bw' not in data or not data['download_max_bw']):
            raise serializers.ValidationError('Cannot have a Qos policy without download guaranteed and max bandwidth options')

        if self.context.get('is_create'):
            data.update({'class_id': self.generate_class_id()})
        return data




class NATInternalSerializer(serializers.ModelSerializer):
    class Meta:
        model = NAT
        exclude = ('source_destination',)


class PBRInternalSerializer(serializers.ModelSerializer):
    class Meta:
        model = PBR
        exclude = ('source_destination',)


class PolicySerializer(serializers.ModelSerializer):
    nat = NATInternalSerializer(required=False, allow_null=True)
    source_destination = SourceDestinationSerializer()
    pbr = PBRInternalSerializer(required=False, allow_null=True)
    qos = QOSSerializer(required=False, allow_null=True)

    def validate_name(self, value):
        try:
            value.encode(encoding='utf-8').decode('ascii')
        except UnicodeDecodeError:
            raise serializers.ValidationError('set a correct name')
        if ',' in value or '[' in value or ']' in value or ' ' in value or ':' in value or '"' in value:
            raise serializers.ValidationError(
                _('name should not contain :, ", [, ] ,white space and comma characters'))
        return value

    def validate_is_ipsec(self, value):
        if value and 'action' in self.initial_data and self.initial_data['action'] != 'accept':
            raise serializers.ValidationError('if ipsec is enabled, action can be accept')
        return value

    def validate_source_destination(self, value):
        if value and 'dst_network_list' in value and value['dst_network_list']:
            for item in value['dst_network_list']:
                if item.type == 'mac':
                    raise serializers.ValidationError('MAC addresses cannot set as destination network list')
        return value

    def validate(self, data):
        if (
                ("action" not in data or not data['action']) and
                ("is_log_enabled" not in data or not data['is_log_enabled']) and
                ("nat" not in data or not data['nat']) and
                ("pbr" not in data or not data['pbr']) and
                ("qos" not in data or not data['qos']) and
                ("is_ipsec" not in data or not data['is_ipsec'])
        ):
            raise serializers.ValidationError(
                "A policy should at least have one of these options: action, log, NAT, QoS or IPSec.")

        if 'nat' in data and data['nat'] and 'nat_type' in data['nat'] and \
                data['nat']["nat_type"] in ["SNAT", "DNAT"]:
            if data['action'] in ["drop", "reject"]:
                raise serializers.ValidationError(
                    "When using NAT, you can not set 'drop' or 'reject' actions for policy.")

        if 'qos' in data and data['qos'] and 'source_destination' in data and data['source_destination']:
            without_type_interface_list = Interface.objects.filter(type__isnull=True)
            if without_type_interface_list.exists():
                raise serializers.ValidationError('When using QOS, you must specify type of all interfaces before')
            if not 'dst_interface_list' in data['source_destination'] or not data['source_destination']['dst_interface_list']:
                raise serializers.ValidationError('When using QOS, you must specify outgoing interface')
            else:
                dst_interface_list = data['source_destination']['dst_interface_list']
                if dst_interface_list.__len__() > 1:
                    raise serializers.ValidationError('Currently you can only specify one outgoing interface for qos policies')
                if data['source_destination']['dst_interface_list'] and data['qos']['download_guaranteed_bw']:
                    for interface in dst_interface_list:
                        if interface.type == 'LAN':
                            raise serializers.ValidationError('QOS is only available for WAN interfaces currently')
                        if interface.qos_status != 'succeeded':
                            raise serializers.ValidationError('Outgoing interface bandwidth configuration not applied successfully')
                        if not interface.download_bandwidth:
                            raise serializers.ValidationError('When using QOS, you must specify outgoing interface bandwidth before')

        if 'is_ipsec' in data and data['is_ipsec']:
            if 'nat' in data and data['nat']:
                raise serializers.ValidationError('Cannot define NAT when ipsec is enabled')
            if (
                    'source_destination' in data and data['source_destination'] and
                    (
                            (
                                    'src_geoip_country_list' in data['source_destination'] and
                                    data['source_destination']['src_geoip_country_list'])
                            or
                            (
                                    'dst_geoip_country_list' in data['source_destination'] and
                                    data['source_destination']['dst_geoip_country_list'])
                    )
            ):
                raise serializers.ValidationError('Cannot define source or destination GEOIP when ipsec is enabled')
        if not self.instance and Policy.objects.all().count() == POLICY_MAX_COUNT:
            raise serializers.ValidationError('Number of Policies exceeded, {} policy entries are allowed'.format(POLICY_MAX_COUNT))
        return data

    class Meta:
        model = Policy
        fields = '__all__'

    def create(self, validated_data):
        nat = None
        pbr = None
        qos = None
        policy = None
        request_username = None
        request = None

        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        # print(request_username)

        nat_data = validated_data.pop('nat', None)
        pbr_data = validated_data.pop('pbr', None)
        qos_data = validated_data.pop('qos', None)

        source_destination_data = validated_data.pop('source_destination')

        with transaction.atomic():
            source_destination = SourceDestination.objects.create()
            if 'src_geoip_country_list' in source_destination_data:
                source_destination.src_geoip_country_list.set(source_destination_data.get('src_geoip_country_list'))
            if 'dst_geoip_country_list' in source_destination_data:
                source_destination.dst_geoip_country_list.set(source_destination_data.get('dst_geoip_country_list'))
            if 'src_network_list' in source_destination_data:
                source_destination.src_network_list.set(source_destination_data.get('src_network_list'))
            if 'dst_network_list' in source_destination_data:
                source_destination.dst_network_list.set(source_destination_data.get('dst_network_list'))
            if 'service_list' in source_destination_data:
                source_destination.service_list.set(source_destination_data.get('service_list'))
            if 'src_interface_list' in source_destination_data:
                source_destination.src_interface_list.set(source_destination_data.get('src_interface_list'))
            if 'dst_interface_list' in source_destination_data:
                source_destination.dst_interface_list.set(source_destination_data.get('dst_interface_list'))
            if qos_data:
                qos_serializer = QOSSerializer(data=qos_data, context={'is_create': True})
                if not qos_serializer.is_valid():
                    raise serializers.ValidationError(qos_serializer.errors)
                qos_serializer.save()
                qos = qos_serializer.data['id']

            if nat_data:
                if 'schedule' in validated_data and validated_data['schedule']:
                    nat_data['schedule'] = validated_data['schedule'].id
                nat_data['source_destination'] = self.initial_data['source_destination']
                nat_data['source_destination']['instance'] = source_destination
                nat_data['is_enabled'] = validated_data['is_enabled']

                nat_serializer = NATSerializer(data=nat_data)
                if not nat_serializer.is_valid():
                    raise serializers.ValidationError(nat_serializer.errors)
                nat_serializer.save()
                nat = nat_serializer.data['id']

            if pbr_data:
                pbr_data['source_destination'] = self.initial_data['source_destination']
                pbr_data['source_destination']['instance'] = source_destination

                pbr_serializer = PBRSerializer(data=pbr_data)
                if not pbr_serializer.is_valid():
                    raise serializers.ValidationError(pbr_serializer.errors)
                pbr_serializer.save()
                pbr = pbr_serializer.data['id']

            validated_data.pop('nat', None)
            validated_data.pop('qos', None)

            policy = Policy.objects.create(**validated_data, source_destination=source_destination, nat_id=nat,
                                           pbr_id=pbr, qos_id=qos)

        details = {
            'items':
                {k: v for k, v in self.validated_data.items() if k not in
                 ['next_policy', 'schedule', 'source_destination', 'nat', 'pbr', 'qos']}
        }

        policy.last_operation = 'add'
        if validated_data.get('is_enabled'):
            policy.status = 'pending'
            run_thread(target=self.policy_add, name='policy_{}'.format(policy.id),
                       args=(policy, request_username, True, request, details))

        else:
            policy.status = 'disabled'
            Notification.objects.filter(source='policy', item__id=policy.id).delete()
            log('firewall', 'policy', 'disable', 'success',
                username=request_username, ip=get_client_ip(request), details=details)

        policy.save()

        return policy

    def update(self, instance, validated_data):
        nat = None
        pbr = None
        qos = None
        request_username = None
        request = None
        changes = get_diff(instance, PolicySerializer, deepcopy(self.initial_data), ['last_operation', 'status'])

        if (
                'next_policy' in validated_data and
                validated_data['next_policy'] and
                validated_data['next_policy'] == instance
        ):
            raise serializers.ValidationError({'next_policy': 'next policy must be different from policy itself'})

        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        old_policy = deepcopy(instance)

        nat_data = validated_data.pop('nat', None)
        pbr_data = validated_data.pop('pbr', None)
        qos_data = validated_data.pop('qos', None)
        source_destination_data = validated_data.pop('source_destination')

        with transaction.atomic():
            instance.source_destination.src_geoip_country_list.set(
                source_destination_data.get('src_geoip_country_list'))
            instance.source_destination.dst_geoip_country_list.set(
                source_destination_data.get('dst_geoip_country_list'))
            instance.source_destination.src_network_list.set(source_destination_data.get('src_network_list'))
            instance.source_destination.dst_network_list.set(source_destination_data.get('dst_network_list'))
            instance.source_destination.service_list.set(source_destination_data.get('service_list'))
            # instance.source_destination.application_list.set(source_destination_data.get('application_list'))
            instance.source_destination.src_interface_list.set(source_destination_data.get('src_interface_list'))
            instance.source_destination.dst_interface_list.set(source_destination_data.get('dst_interface_list'))
            if qos_data:
                if instance.qos:
                    qos_serializer = QOSSerializer(data=qos_data, instance =instance.qos)
                else:
                    qos_serializer = QOSSerializer(data=qos_data, context={'is_create': True})
                if not qos_serializer.is_valid():
                    raise serializers.ValidationError(qos_serializer.errors)
                qos = qos_serializer.save()

            if nat_data:
                nat_data['source_destination'] = self.initial_data['source_destination']
                nat_data['source_destination']['instance'] = instance.source_destination
                nat_data['is_enabled'] = validated_data['is_enabled']

                if instance.nat:
                    nat_serializer = NATSerializer(data=nat_data, instance=instance.nat)
                else:
                    nat_serializer = NATSerializer(data=nat_data)

                if not nat_serializer.is_valid():
                    raise serializers.ValidationError(nat_serializer.errors)
                nat = nat_serializer.save()

            if pbr_data:
                pbr_data['source_destination'] = self.initial_data['source_destination']
                pbr_data['source_destination']['instance'] = instance.source_destination

                if instance.pbr:
                    pbr_serializer = PBRSerializer(data=pbr_data, instance=instance.pbr)
                else:
                    pbr_serializer = PBRSerializer(data=pbr_data)

                if not pbr_serializer.is_valid():
                    raise serializers.ValidationError(pbr_serializer.errors)
                pbr = pbr_serializer.save()

            validated_data['nat'] = nat
            validated_data['pbr'] = pbr
            validated_data['qos'] = qos

            instance = super(PolicySerializer, self).update(instance, validated_data)

            instance.last_operation = 'update'
            instance.status = 'pending'

            instance.save()

        run_thread(target=self.policy_update, name='policy_{}'.format(old_policy.id),
                   args=(old_policy, instance, request_username, request, changes))

        if instance.status == 'disabled':
            Notification.objects.filter(source='policy', item__id=instance.id).delete()

        return instance

    def policy_add(self, policy, request_username, is_new, request=None, changes=None):
        if is_new:
            operation = 'add'
        else:
            operation = 'update'

        try:

            ret = add_policy(policy, operation, request_username, request, changes)
            if ret > 0:
                policy.status = 'succeeded'
                policy.save()
            else:
                policy.status = 'failed'
                policy.save()
        except Exception as e:
            log('firewall', 'policy', operation, 'fail',
                username=request_username, ip=get_client_ip(request), details={'items': str(e)})
            policy.status = 'failed'
            policy.save()
            raise e

    def policy_update(self, old_policy, new_policy, request_username, request=None, changes=None):
        try:
            update_policy(old_policy, new_policy, request_username=request_username, request=request)
            log('firewall', 'policy', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)
            new_policy.status = 'succeeded'
            new_policy.save()
        except Exception as e:
            log('firewall', 'policy', 'update', 'fail',
                username=request_username, ip=get_client_ip(request), details={'items': str(e)})
            new_policy.status = 'failed'
            new_policy.save()
            raise e


class NextPolicySerializer(serializers.ModelSerializer):
    class Meta:
        fields = ('id', 'name')
        model = Policy


class PolicyReadSerializer(serializers.ModelSerializer):
    nat = NATInternalSerializer()
    source_destination = SourceDestinationReadSerializer()
    pbr = PBRInternalSerializer()
    qos = QOSSerializer()
    schedule = ScheduleSerializer()
    error = serializers.SerializerMethodField()
    next_policy = NextPolicySerializer()

    def get_error(self, policy):
        if policy.status == 'failed':
            notification = Notification.objects.filter(source='policy', item__id=policy.id)
            if notification.exists():
                return notification.values('message', 'severity', 'datetime')[0]

        return None

    class Meta:
        model = Policy
        fields = '__all__'


class PolicyRealSerializer(serializers.ModelSerializer):
    nat = NATInternalSerializer()
    source_destination = SourceDestinationReadSerializer()
    pbr = PBRInternalSerializer()
    qos = QOSSerializer()
    schedule = ScheduleSerializer()
    has_set = serializers.SerializerMethodField()
    statistic = serializers.SerializerMethodField()

    def get_has_set(self, policy):
        return is_policy_applied(policy)

    def get_statistic(self, policy):
        return getPolicyInfo(policy.id)

    class Meta:
        model = Policy
        fields = '__all__'

