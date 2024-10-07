from copy import deepcopy

from django.db import transaction
from rest_framework import serializers

from config_app.models import HighAvailability, Setting
from config_app.serializers import InterfaceSerializer
from config_app.utils import get_sorted_interface_name_list, get_peer2_interface_list
from entity_app.serializers import AddressSerializer
from firewall_input_app.models import Source, InputFirewall, Apply
from firewall_input_app.utils import apply_rule
from utils.serializers import get_diff
from utils.utils import run_thread


class SourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Source
        fields = '__all__'

    def validate(self, data):

        if 'src_interface_list' in data and data['src_interface_list'] and HighAvailability.objects.filter(
                is_enabled=True):
            peer2_interface_list = get_sorted_interface_name_list(
                get_peer2_interface_list(HighAvailability.objects.get().peer2_address,
                                         ssh_port=Setting.objects.get(key='ssh-port').data['value'],
                                         https_port=Setting.objects.get(key='https-port').data['value']))
            not_sync_interface_list = []
            for interface in data['src_interface_list']:
                if interface.name not in peer2_interface_list:
                    not_sync_interface_list.append(interface.name)
            if not_sync_interface_list:
                raise serializers.ValidationError(
                    'HighAvailability has been configured and the selected {interface} does not '
                    'exist on Node2 system, add {interface} there and then try again.'.format(
                        interface=', '.join(not_sync_interface_list)))
        return data


class SourceReadSerializer(serializers.ModelSerializer):
    src_interface_list = InterfaceSerializer(many=True)
    src_network_list = AddressSerializer(many=True)

    class Meta:
        model = Source
        fields = '__all__'


class InptFirewallReadserializer(serializers.ModelSerializer):
    source = SourceSerializer()

    class Meta:
        model = InputFirewall
        fields = '__all__'


class InputFirewallSerializer(serializers.ModelSerializer):
    source = SourceSerializer()

    def validate_name(self, value):
        try:
            value.encode(encoding='utf-8').decode('ascii')
        except UnicodeDecodeError:
            raise serializers.ValidationError('set a correct name')
        if ',' in value or '[' in value or ']' in value or ' ' in value or ':' in value or '"' in value:
            raise serializers.ValidationError(
                'name should not contain :, ", [, ] ,white space and comma characters')
        instance_list = InputFirewall.objects.all()
        for instance in instance_list:
            if instance.name == value and not self.instance:
                raise serializers.ValidationError('Firewall Input with this Name already exists.')

            if self.instance:
                if value == instance.name and instance.name != self.instance.name:
                    raise serializers.ValidationError('Firewall Input with this Name already exists.')
        return value

    def create(self, validated_data):
        policy = None
        request_username = None
        request = None

        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        source_data = validated_data.pop('source')

        with transaction.atomic():
            source = Source.objects.create()

            if 'src_network_list' in source_data:
                source.src_network_list.set(source_data.get('src_network_list'))

            if 'src_interface_list' in source_data:
                source.src_interface_list.set(source_data.get('src_interface_list'))

            policy = InputFirewall.objects.create(**validated_data, source=source)

        details = {
            'items':
                {k: v for k, v in self.validated_data.items() if k not in
                 ['source']}
        }

        policy.last_operation = 'add'
        if validated_data.get('is_enabled'):
            policy.status = 'unapplied'


        else:
            policy.status = 'disabled'

        policy.save()

        return policy

    def update(self, instance, validated_data):
        request_username = None
        request = None
        changes = get_diff(instance, InputFirewallSerializer, deepcopy(self.initial_data), ['last_operation', 'status'])

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

        source_destination_data = validated_data.pop('source')

        with transaction.atomic():
            instance.source.src_network_list.set(source_destination_data.get('src_network_list'))

            instance.source.src_interface_list.set(source_destination_data.get('src_interface_list'))

            instance = super(InputFirewallSerializer, self).update(instance, validated_data)

            instance.last_operation = 'update'
            instance.status = 'unapplied'
            instance.save()

        return instance

    class Meta:
        model = InputFirewall
        fields = '__all__'


class InputFirewallReadSerializer(serializers.ModelSerializer):
    source = SourceReadSerializer()

    class Meta:
        model = InputFirewall
        fields = '__all__'


class ApplySerializer(serializers.ModelSerializer):
    unapplied_role = InputFirewallReadSerializer(required=False, many=True)

    def create(self, validated_data):
        with transaction.atomic():
            request_username = None
            request = None

            all_apply_objcet = Apply.objects.all()
            for obj in all_apply_objcet:
                obj.delete()

            instance = super(ApplySerializer, self).create(validated_data)
            instance.status = 'pending'
            instance.save()
            run_thread(target=apply_rule, name='apply_role',
                       args=(instance, 'add', request_username, request))

            return instance

    class Meta:
        model = Apply
        fields = '__all__'
