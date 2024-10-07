import re
import time
from copy import deepcopy

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _
from rest_framework import serializers

from api.licence import VPN_MAX_COUNT
from entity_app.serializers import AddressSerializer
from firewall_input_app.models import Source, InputFirewall
from firewall_input_app.utils import apply_rule
from report_app.models import Notification
from root_runner.sudo_utils import sudo_runner
from utils.serializers import get_diff
from utils.utils import run_thread
from vpn_app.models import VPN, Tunnel, l2VPNServer, l2VPNBridge
from vpn_app.utils import create_vpn, update_vpn, get_vpn_traffic, get_vpn_status, get_ipsec_vpn_status


class TunnelSerializer(serializers.ModelSerializer):
    def validate_mode(self, value):
        if 'type' in self.initial_data and self.initial_data['type'] == 'vtun' and not value:
            raise serializers.ValidationError(_('This field is required.'))
        return value

    def validate_service_protocol(self, value):
        if 'type' in self.initial_data and self.initial_data['type'] == 'vtun' and not value:
            raise serializers.ValidationError(_('This field is required.'))
        return value

    def validate_service_port(self, value):
        if 'type' in self.initial_data and self.initial_data['type'] == 'vtun' and not value:
            raise serializers.ValidationError(_('This field is required.'))

        tunnel_id = None
        if hasattr(self, 'instance') and self.instance:
            tunnel_id = self.instance.id
        if value and Tunnel.objects.exclude(id=tunnel_id).filter(service_port=value).exists():
            raise serializers.ValidationError(_('tunnel with this service port already exists.'))

        return value

    def validate_server_endpoint(self, value):
        if ('type' in self.initial_data and self.initial_data['type'] == 'vtun'
                and 'mode' in self.initial_data and self.initial_data['mode'] == 'client'
                and not value):
            raise serializers.ValidationError(_('This field is required.'))
        if value:
            if value.type != 'ip' or len(value.value_list) != 1 or \
                    ('/' in value.value_list[0] and '/32' not in value.value_list[0]):
                raise serializers.ValidationError(_('remote endpoint should be a single ip.'))
        return value

    def validate_real_local_endpoint(self, value):
        if 'type' in self.initial_data and self.initial_data['type'] in ['gre', 'ipip'] and not value:
            raise serializers.ValidationError(_('This field is required.'))
        if value:
            if value.type != 'ip' or len(value.value_list) != 1 or \
                    ('/' in value.value_list[0] and '/32' not in value.value_list[0]):
                raise serializers.ValidationError(_('real local endpoint should be a single ip.'))
        return value

    def validate_real_remote_endpoint(self, value):
        if 'type' in self.initial_data and self.initial_data['type'] in ['gre', 'ipip'] and not value:
            raise serializers.ValidationError(_('This field is required.'))
        if value:
            if value.type != 'ip' or len(value.value_list) != 1 or \
                    ('/' in value.value_list[0] and '/32' not in value.value_list[0]):
                raise serializers.ValidationError(_('real remote endpoint should be a single ip.'))
        return value

    def validate_virtual_local_endpoint(self, value):
        import ipaddress, re
        if not value:
            raise serializers.ValidationError(_('This field may not be blank.'))
        if value:
            virtual_local_endpoint = value.value_list[0].split("/")[0]
            status, result = sudo_runner('route -n')
            if status:
                for line in result.splitlines():
                    addr_re = re.search(
                        r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\s*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\s*U\s*(\d*\s*)*(\S*)',
                        line, re.M)
                    if addr_re and addr_re.group(1) and addr_re.group(1) != '0.0.0.0':
                        net = ipaddress.ip_network('{}/24'.format(addr_re.group(1)), False)
                        if self.instance:  # put
                            instance_name = VPN.objects.get(tunnel=self.instance).name
                            if ipaddress.ip_address(virtual_local_endpoint) in ipaddress.ip_network(net).hosts() \
                                    and instance_name and addr_re.group(3) != instance_name:
                                raise serializers.ValidationError(_('virtual local endpoint is in used.'))
                        else:  # post
                            if ipaddress.ip_address(virtual_local_endpoint) in ipaddress.ip_network(net).hosts():
                                raise serializers.ValidationError(_('virtual local endpoint is in used.'))
            if value.type != 'ip' or len(value.value_list) != 1 or \
                    ('/' in value.value_list[0] and '/32' not in value.value_list[0]):
                raise serializers.ValidationError(_('virtual local endpoint should be a single ip.'))
        return value

    def validate_virtual_remote_endpoint(self, value):
        if not value:
            raise serializers.ValidationError(_('This field may not be blank.'))
        if value:
            if value.type != 'ip' or len(value.value_list) != 1 or \
                    ('/' in value.value_list[0] and '/32' not in value.value_list[0]):
                raise serializers.ValidationError(_('virtual remote endpoint should be a single ip.'))
        return value

    def validate(self, data):
        error_msg = dict()
        if all(field in data for field in
               ['type', 'mode', 'server_endpoint', 'virtual_remote_endpoint', 'virtual_local_endpoint']) and \
                data['type'] == 'vtun' and \
                data['mode'] == 'client' and \
                len({data['server_endpoint'].value_list[0].split("/")[0],
                     data['virtual_remote_endpoint'].value_list[0].split("/")[0],
                     data['virtual_local_endpoint'].value_list[0].split("/")[0]}) != 3:
            error_msg[
                'server_endpoint'] = 'server endpoint cannot be the same as virtual remote endpoint or virtual local endpoint.'

        if all(field in data for field in
               ['virtual_remote_endpoint', 'virtual_local_endpoint']) and \
                data['virtual_local_endpoint'].value_list[0].split("/")[0] == \
                data['virtual_remote_endpoint'].value_list[0].split("/")[0]:
            error_msg[
                'virtual_remote_endpoint'] = 'virtual local endpoint and virtual remote endpoint cannot be the same.'

        elif all(field in data for field in
                 ['type', 'virtual_remote_endpoint', 'virtual_local_endpoint', 'real_local_endpoint',
                  'real_remote_endpoint']) and \
                data['type'] in ['gre', 'ipip']:

            if len({data['real_local_endpoint'].value_list[0].split("/")[0],
                    data['virtual_remote_endpoint'].value_list[0].split("/")[0],
                    data['virtual_local_endpoint'].value_list[0].split("/")[0]}) != 3:
                error_msg[
                    'real_local_endpoint'] = 'real local endpoint cannot be the same as virtual remote endpoint or virtual local endpoint.'

            if len({data['real_remote_endpoint'].value_list[0].split("/")[0],
                    data['virtual_remote_endpoint'].value_list[0].split("/")[0],
                    data['virtual_local_endpoint']}) != 3:
                error_msg[
                    'real_remote_endpoint'] = 'real remote endpoint cannot be the same as virtual remote endpoint or virtual local endpoint.'

            if len({data['real_remote_endpoint'].value_list[0].split("/")[0],
                    data['real_local_endpoint'].value_list[0].split("/")[0]}) != 2:
                error_msg['real_remote_endpoint'] = 'real remote endpoint cannot be the same as real local endpoint.'

        if all(field in data for field in
               ['type', 'real_local_endpoint', 'real_remote_endpoint']) and \
                data['type'] in ['gre', 'ipip']:
            tunnel_id = None
            if hasattr(self, 'instance') and self.instance:
                tunnel_id = self.instance.id
            if VPN.objects.exclude(tunnel__id=tunnel_id).filter(
                    tunnel__real_local_endpoint=data['real_local_endpoint'].id,
                    tunnel__real_remote_endpoint=data['real_remote_endpoint'].id,
                    tunnel__type=data['type'],
                    is_enabled=True
            ).exists():
                error_msg['type'] = \
                    'Combination of real_local_endpoint, real_remote_endpoint and type should be unique for each tunnel'

        if all(field in data for field in
               ['virtual_local_endpoint', 'virtual_remote_endpoint']):
            tunnel_id = None
            if hasattr(self, 'instance') and self.instance:
                tunnel_id = self.instance.id
            if VPN.objects.exclude(tunnel__id=tunnel_id).filter(
                    tunnel__virtual_local_endpoint=data['virtual_local_endpoint'].id,
                    tunnel__virtual_remote_endpoint=data['virtual_remote_endpoint'].id,
                    is_enabled=True
            ).exists():
                error_msg['type'] = \
                    'Combination of virtual_local_endpoint and virtual_remote_endpoint should be unique for each tunnel'

        if error_msg:
            raise serializers.ValidationError([error_msg])

        return data

    class Meta:
        model = Tunnel
        fields = '__all__'


class TunnelInternalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tunnel
        fields = '__all__'
        depth = 1


class VPNInternalSerializer(serializers.ModelSerializer):
    class Meta:
        model = VPN
        fields = '__all__'


class VPNRealSerializer(serializers.ModelSerializer):
    vpn_connection_status = serializers.SerializerMethodField()
    is_tunnel_connected = serializers.SerializerMethodField()
    tunnel = TunnelInternalSerializer(required=False)
    remote_network = AddressSerializer(many=True)
    local_network = AddressSerializer(many=True)
    local_endpoint = AddressSerializer(many=False)
    remote_endpoint = AddressSerializer(many=False)
    traffic = serializers.SerializerMethodField()

    real_data = dict()
    many = False

    class Meta:
        model = VPN
        fields = '__all__'

    def __init__(self, obj, *args, **kwargs):
        if isinstance(obj, list):
            all_vpn_information, whole_line = get_ipsec_vpn_status()
            self.many = True
            for vpn in obj:
                # TODO check this if
                if '{}_real_data'.format(vpn.name) in all_vpn_information.keys():
                    self.real_data[vpn.name] = all_vpn_information['{}_real_data'.format(vpn.name)]
                else:
                    self.real_data[vpn.name] = 'down'
        else:
            real_info = get_vpn_status('vpn', obj.name, None, None, None)
            self.real_data = real_info

        super(VPNRealSerializer, self).__init__(obj, *args, **kwargs)

    def get_traffic(self, vpn):
        vpn_traffic = get_vpn_traffic(vpn.name)
        return vpn_traffic

    def get_vpn_connection_status(self, vpn):
        if self.many:
            result = self.real_data[vpn.name]
        else:
            result = self.real_data

        return result

    def get_is_tunnel_connected(self, vpn):
        if not vpn.tunnel:
            return None
        else:
            virtual_remote_ip = vpn.tunnel.virtual_remote_endpoint.value_list[0].split("/")[0]
            virtual_local_ip = vpn.tunnel.virtual_local_endpoint.value_list[0].split("/")[0]
            return get_vpn_status('tunnel', vpn.phase2_authentication_algorithm, vpn.tunnel.type, virtual_remote_ip,
                                  virtual_local_ip)


class VPNChangesSerializer(serializers.ModelSerializer):
    class Meta:
        model = VPN
        fields = '__all__'


class VPNWriteSerializer(serializers.ModelSerializer):
    tunnel = TunnelInternalSerializer(required=False)
    preshared_key_expire_date = serializers.DateTimeField(read_only=True)

    class Meta:
        model = VPN
        fields = '__all__'

    def validate_name(self, value):
        if (' ' or '\\' or '/' or ':' or '?' or '\"' or '*' or '<' or '>' or '|' or '[' or ']' or '{' or '}') in value:
            raise serializers.ValidationError(
                _('name should not contain \, /, :, ? , ", *, <, >, |, [, ], {, } and white space characters'))
        if value == 'setup':
            raise serializers.ValidationError(_('choose another name'))
        return value

    def validate(self, data):
        error_msg = dict()
        if 'local_endpoint' in data and 'remote_endpoint' in data and \
                data['local_endpoint'].value_list and data['remote_endpoint'].value_list and \
                data['local_endpoint'].value_list[0].split("/")[0] == \
                data['remote_endpoint'].value_list[0].split("/")[0]:
            error_msg['local_endpoint'] = 'local endpoint and remote endpoint cannot be the same.'
            raise serializers.ValidationError(error_msg)
        if data['peer_id'] == data['local_id']:
            raise serializers.ValidationError(_('local_id and peer_id shouldn\'t be same'))
        if not self.instance and VPN.objects.all().count() == VPN_MAX_COUNT:
            raise serializers.ValidationError(
                _('Number of items exceeded, {} VPN entries are allowed'.format(VPN_MAX_COUNT)))

        if 'local_endpoint' in data and data['local_endpoint']:
            if data['local_endpoint'].type != 'ip' or len(data['local_endpoint'].value_list) != 1 or \
                    ('/' in data['local_endpoint'].value_list[0] and '/32' not in data['local_endpoint'].value_list[0]):
                raise serializers.ValidationError(_('local endpoint should be a single ip.'))

        if 'remote_endpoint' in data and data['remote_endpoint']:
            if data['remote_endpoint'].type != 'ip' or len(data['remote_endpoint'].value_list) != 1 or \
                    ('/' in data['remote_endpoint'].value_list[0] and '/32' not in data['remote_endpoint'].value_list[
                        0]):
                raise serializers.ValidationError(_('remote endpoint should be a single ip.'))

        # AFTA validations based on FCS_IPSEC_EXT.1.12
        if re.search(r'\D+', data['phase1_encryption_algorithm']).group() == \
                re.search(r'\D+', data['phase2_encryption_algorithm']).group() and \
                int(re.search(r'\d+', data['phase1_encryption_algorithm']).group()) < \
                int(re.search(r'\d+', data['phase2_encryption_algorithm']).group()):
            raise serializers.ValidationError('Strength of Phase1 encryption algorithm ({}) should be greater than or'
                                              ' equal to the strength of the Phase2 encryption algorithm ({}) in'
                                              ' terms of the number of bits in the key.'
                                              .format(data['phase1_encryption_algorithm'],
                                                      data['phase2_encryption_algorithm']))

        if re.search(r'\D+', data['phase1_authentication_algorithm']).group() == \
                re.search(r'\D+', data['phase2_authentication_algorithm']).group() and \
                int(re.search(r'\d+', data['phase1_authentication_algorithm']).group()) < \
                int(re.search(r'\d+', data['phase2_authentication_algorithm']).group()):
            raise serializers.ValidationError('Strength of Phase1 authentication algorithm ({}) should be greater than '
                                              ' or equal to the strength of the Phase2 authentication algorithm ({}) in'
                                              ' terms of the number of bits in the key.'
                                              .format(data['phase1_authentication_algorithm'],
                                                      data['phase2_authentication_algorithm']))
        if int(re.search(r'\d+', data['phase1_diffie_hellman_group']).group()) < \
                int(re.search(r'\d+', data['phase2_diffie_hellman_group']).group()):
            raise serializers.ValidationError('Strength of Phase1 Diffie Helman group should be greater than '
                                              ' or equal to the strength of the Phase2 Diffie Helman group in'
                                              ' terms of the number of bits in the key.')

        if 'local_endpoint_backup' in data and data['local_endpoint_backup']:
            if data['local_endpoint_backup'].type != 'ip' or len(data['local_endpoint_backup'].value_list) != 1 or \
                    ('/' in data['local_endpoint_backup'].value_list[0] and '/32' not in
                     data['local_endpoint_backup'].value_list[0]):
                raise serializers.ValidationError(_('Backup local endpoint should be a single ip.'))

        if 'remote_endpoint_backup' in data and data['remote_endpoint_backup']:
            if data['remote_endpoint_backup'].type != 'ip' or len(data['remote_endpoint_backup'].value_list) != 1 or \
                    ('/' in data['remote_endpoint_backup'].value_list[0] and '/32' not in
                     data['remote_endpoint_backup'].value_list[
                         0]):
                raise serializers.ValidationError(_('Backup remote endpoint should be a single ip.'))

        if 'is_backup_enabled' in data and data['is_backup_enabled']:
            if not data['is_on_demand']:
                raise serializers.ValidationError(_('This field should be enable'))

            if not data['dpd']:
                raise serializers.ValidationError(_('This field should be enable'))

        return data

    def validate_local_endpoint(self, value):
        if not value:
            raise serializers.ValidationError(_('This field may not be blank.'))

        return value

    def validate_remote_endpoint(self, value):
        if not value:
            raise serializers.ValidationError(_('This field may not be blank.'))

        return value

    def validate_local_endpoint_backup(self, value):
        if self.initial_data['is_backup_enabled']:
            if not value:
                raise serializers.ValidationError(_('This field may not be blank.'))

        return value


    def validate_remote_endpoint_backup(self, value):

        if self.initial_data['is_backup_enabled']:
            if not value:
                raise serializers.ValidationError(_('This field may not be blank.'))

        return value


    def validate_preshared_key(self, value):
        if self.initial_data['authentication_method'] == 'preshared':
            if not value:
                raise serializers.ValidationError(_('This field may not be blank.'))

        return value

    def validate_certificate(self, value):
        if self.initial_data['authentication_method'] == 'RSA':
            if not value:
                raise serializers.ValidationError(_('This field may not be blank.'))

        return value


    def create(self, validated_data):
        tunnel_id = None
        vpn = None

        with transaction.atomic():
            tunnel = validated_data.pop('tunnel', None)

            if tunnel:

                tunnel_serializer = TunnelSerializer(data=self.initial_data['tunnel'])
                if not tunnel_serializer.is_valid():
                    raise serializers.ValidationError(tunnel_serializer.errors)
                tunnel_serializer.save()
                tunnel_id = tunnel_serializer.data['id']

            local_network = validated_data.pop('local_network')
            remote_network = validated_data.pop('remote_network')

            preshared_key_expire_date = (timezone.now() + timezone.timedelta(days=30))

            vpn = VPN.objects.create(**validated_data, tunnel_id=tunnel_id,
                                     preshared_key_expire_date=preshared_key_expire_date)
            vpn.local_network.set(local_network)
            vpn.remote_network.set(remote_network)

            vpn.status = 'pending'
            vpn.last_operation = 'add'
            vpn.save()

        details = {
            'items':
                {k: v for k, v in self.initial_data.items() if k not in
                 ['local_network', 'local_endpoint', 'remote_network', 'remote_endpoint', 'tunnel']}
        }

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        if not InputFirewall.objects.filter(service_list__contains=['ipsec']) and vpn.is_enabled:
            try:
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='default-ipsec',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='admin',
                    service_list='{ipsec}',
                    source=source)

                apply_rule(None, None)
            except:
                pass

        run_thread(target=create_vpn, name='vpn_{}'.format(vpn.id), args=(vpn, request_username, request, details))

        return vpn

    def update(self, instance, validated_data):
        Notification.objects.filter(source='vpn', item__id=instance.id).delete()
        tunnel = self.initial_data.pop('tunnel', None)
        changes = get_diff(instance, VPNWriteSerializer, deepcopy(self.initial_data), ['last_operation', 'status'])

        if (
                hasattr(instance, 'tunnel') and
                tunnel and
                hasattr(instance.tunnel, 'type') and instance.tunnel.type is not None and
                tunnel['type'] is not None and
                ((instance.tunnel.type in ['ipip', 'gre'] and tunnel['type'] == 'vtun') or
                 (instance.tunnel.type == 'vtun' and tunnel['type'] in ['ipip', 'gre']))
        ):
            raise serializers.ValidationError('Cannot change tunnel type from ipip or gre to vtun and vice versa')

        old_vpn = deepcopy(instance)
        old_tunnel = None
        if hasattr(instance, 'tunnel') and instance.tunnel:
            old_tunnel = deepcopy(instance.tunnel)

        with transaction.atomic():
            if tunnel:
                if not hasattr(old_vpn, 'tunnel'):
                    setattr(old_vpn, 'tunnel', {})
                    setattr(old_vpn.tunnel, 'name', old_vpn.name)
                if instance.tunnel:
                    tunnel_serializer = TunnelSerializer(data=tunnel, instance=instance.tunnel)
                else:
                    tunnel_serializer = TunnelSerializer(data=tunnel)

                if not tunnel_serializer.is_valid():
                    raise serializers.ValidationError(tunnel_serializer.errors)
                tunnel = tunnel_serializer.save()

            else:
                if old_tunnel:
                    Tunnel.objects.get(id=old_tunnel.id).delete()

            expire_day = instance.preshared_key_expire_date
            now = timezone.now()
            if instance.preshared_key != old_vpn.preshared_key:
                expire_day = (timezone.now() + timezone.timedelta(days=30))
            else:
                if now > instance.preshared_key_expire_date:
                    pass
                    # TODO: generate alert
                    # create_message(source='Tunnel',
                    #                severity='a',
                    #                title='PreshareKey Expire',
                    #                source_name=str(requested_tunnel.name),
                    #                source_id=requested_tunnel.id,
                    #                message="PreshareKey expired in date " + str(requested_tunnel.pre_key_expire_date))
                    #

            serializer = VPNInternalSerializer(instance=instance, data=self.initial_data)
            if not serializer.is_valid():
                raise serializers.ValidationError(serializer.errors)
            instance = serializer.save()
            instance.tunnel = tunnel
            instance.local_network.set(validated_data.get('local_network'))
            instance.remote_network.set(validated_data.get('remote_network'))
            instance.status = 'pending'
            instance.last_operation = 'update'
            instance.save()

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        old_vpn = old_vpn.__dict__
        old_vpn.pop('_state')
        old_vpn.pop('_django_version')

        if old_tunnel:
            old_tunnel = old_tunnel.__dict__
            old_tunnel.pop('_state', None)
            old_tunnel.pop('_django_version', None)

        if not InputFirewall.objects.filter(service_list__contains=['ipsec']) and instance.is_enabled:
            try:
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='default-ipsec',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='admin',
                    service_list='{ipsec}',
                    source=source)


            except:
                pass

            apply_rule(None, None)

        if not VPN.objects.filter(is_enabled=True):
            InputFirewall.objects.filter(service_list__exact=['ipsec']).delete()
            apply_rule(None, None)

        run_thread(target=update_vpn, name='vpn_{}'.format(instance.id),
                   args=(instance, old_vpn, old_tunnel, request_username, request, changes))
        return instance


class VPNReadSerializer(serializers.ModelSerializer):
    tunnel = TunnelInternalSerializer(required=False)
    remote_network = AddressSerializer(many=True)
    local_network = AddressSerializer(many=True)
    local_endpoint = AddressSerializer(many=False)
    remote_endpoint = AddressSerializer(many=False)
    error = serializers.SerializerMethodField()
    phase2_encryption_algorithm = serializers.SerializerMethodField()

    def get_error(self, vpn):
        if vpn.status == 'failed':
            notification = Notification.objects.filter(source='vpn', item__id=vpn.id)
            if notification.exists():
                return notification.values('message', 'severity', 'datetime')[0]
        return None

    def get_phase2_encryption_algorithm(self, vpn):
        # if vpn.phase2_encryption_algorithm == 'camellia256':
        #     return 'paya256'
        return vpn.phase2_encryption_algorithm

    class Meta:
        model = VPN
        fields = '__all__'
        depth = 1


class L2VPNServerCreateFile:
    def __init__(self, type_connection, vpnserver_interface, cascade_name, mkdir='no'):
        self.type_connection = type_connection
        self.vpnserver_interface = vpnserver_interface
        self.cascade_name = cascade_name
        self.mkdir = mkdir

    def create_config_file(self):
        '''Create config file'''

        if self.mkdir == 'yes':
            cmd0 = 'mkdir /usr/local/vpnserver/config/{}'.format(self.cascade_name)
            s, o = sudo_runner(cmd0)
            if not s:
                raise serializers.ValidationError({'non_field_errors': 'Can\'t create VPN related config files'})

        if self.type_connection == "tcp":

            server_config_file = open(
                "/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt".format(self.cascade_name,
                                                                                         self.cascade_name),
                "w+")
            server_config_file.write("HubCreate VirtualHub_{} /PASSWORD:123456\n".format(self.cascade_name))
            server_config_file.write(
                "BridgeCreate VirtualHub_{} /DEVICE:{} /TAP:yes\n".format(self.cascade_name, self.vpnserver_interface))
            server_config_file.write("Hub VirtualHub_{}\n".format(self.cascade_name))
            server_config_file.write("UserCreate root /GROUP:none /REALNAME:none /NOTE:none\n")
            server_config_file.write(
                "MakeCert2048 /CN:none /O:none /OU:none /C:none /ST:none /L:none /SERIAL:none /EXPIRES:10950 /SAVECERT:/usr/local/vpnserver/config/{}/{}_cert /SAVEKEY:/usr/local/vpnserver/config/{}/{}_key\n".format(
                    self.cascade_name, self.cascade_name, self.cascade_name, self.cascade_name))
            server_config_file.write(
                "UserCertSet root /LOADCERT:/usr/local/vpnserver/config/{}/{}_cert \n".format(self.cascade_name,
                                                                                              self.cascade_name))
            server_config_file.close()

        elif self.type_connection == "udp":

            server_config_file = open(
                "/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt".format(self.cascade_name,
                                                                                         self.cascade_name),
                "w+")
            server_config_file.write("OpenVpnEnable yes /PORTS:1196\n")
            server_config_file.write("HubCreate VirtualHub_{} /PASSWORD:123456\n".format(self.cascade_name))
            server_config_file.write(
                "BridgeCreate VirtualHub_{} /DEVICE:{} /TAP:yes\n".format(self.cascade_name, self.vpnserver_interface))
            server_config_file.write("Hub VirtualHub_{}\n".format(self.cascade_name))
            server_config_file.write("UserCreate root /GROUP:none /REALNAME:none /NOTE:none\n")
            server_config_file.write(
                "MakeCert2048 /CN:none /O:none /OU:none /C:none /ST:none /L:none /SERIAL:none /EXPIRES:10950 /SAVECERT:/usr/local/vpnserver/config/{}/{}_cert /SAVEKEY:/usr/local/vpnserver/config/{}/{}_key\n".format(
                    self.cascade_name, self.cascade_name, self.cascade_name, self.cascade_name))
            server_config_file.write(
                "UserCertSet root /LOADCERT:/usr/local/vpnserver/config/{}/{}_cert \n".format(self.cascade_name,
                                                                                              self.cascade_name))
            server_config_file.close()

        cmd = '/usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:123456 /in:/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt'.format(
            self.cascade_name, self.cascade_name)

        s, o = sudo_runner(cmd)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t start VPN'})


class L2VPNServerUpdateFile:
    def __init__(self, type_connection, vpnserver_interface, cascade_name):
        self.type_connection = type_connection
        self.vpnserver_interface = vpnserver_interface
        self.cascade_name = cascade_name

    def update_config_file(self):
        # update config file
        server_delete_file = open(
            "/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt".format(
                self.cascade_name, self.cascade_name), "w+")
        server_delete_file.write(
            "BridgeDelete VirtualHub_{} /DEVICE:{}\n".format(self.cascade_name, self.vpnserver_interface))
        server_delete_file.write("HubDelete VirtualHub_{}\n".format(self.cascade_name))
        server_delete_file.close()

        cmd1 = '/usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:123456 /in:/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt'.format(
            self.cascade_name, self.cascade_name)
        s, o = sudo_runner(cmd1)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t update VPN'})

        cmd2 = 'rm -f /usr/local/vpnserver/config/{}/server_configuration_file_{}.txt'.format(self.cascade_name,
                                                                                              self.cascade_name)
        s, o = sudo_runner(cmd2)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t remove old VPN Config files'})


class l2VPNServerSerilizer(serializers.ModelSerializer):
    class Meta:
        model = l2VPNServer
        fields = '__all__'

    def create(self, validated_data):
        type_connection = validated_data['type_connection']
        vpnserver_interface = validated_data['vpnserver_interface']
        cascade_name = validated_data['cascade_name']

        vpn = l2VPNServer(type_connection=type_connection,
                          vpnserver_interface=vpnserver_interface,
                          cascade_name=cascade_name)
        vpn.save()
        mkdir = 'yes'
        config_file = L2VPNServerCreateFile(type_connection, vpnserver_interface, cascade_name, mkdir)
        config_file.create_config_file()
        return vpn

    def update(self, instance, validated_data):
        type_connection = instance.type_connection
        vpnserver_interface = instance.vpnserver_interface
        cascade_name = instance.cascade_name

        instance.type_connection = validated_data['type_connection']
        instance.vpnserver_interface = validated_data['vpnserver_interface']
        instance.cascade_name = validated_data['cascade_name']
        instance.save()

        update_file = L2VPNServerUpdateFile(type_connection, vpnserver_interface, cascade_name)
        update_file.update_config_file()

        config_file = L2VPNServerCreateFile(instance.type_connection, instance.vpnserver_interface,
                                            instance.cascade_name)
        config_file.create_config_file()

        return instance


class L2VPNBridgeCreateFile:
    def __init__(self, type_connection, vpnserver_ip, vpnbridge_interface, cascade_name, mkdir='no'):
        self.type_connection = type_connection
        self.vpnserver_ip = vpnserver_ip
        self.vpnbridge_interface = vpnbridge_interface
        self.cascade_name = cascade_name
        self.mkdir = mkdir

    def create_config_file(self):

        # if self.mkdir == 'yes':
        #     cmd0 = 'mkdir /usr/local/vpnbridge/config/{}'.format(self.cascade_name)
        #     task.apply_async((cmd0,)).get(interval=0.0001)

        if self.type_connection == "tcp":

            bridge_config_file = open(
                "/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt".format(self.cascade_name,
                                                                                         self.cascade_name),
                "w+")
            bridge_config_file.write("BridgeCreate BRIDGE /DEVICE:{} /TAP:no\n".format(self.vpnbridge_interface))
            bridge_config_file.write("Hub BRIDGE\n")
            bridge_config_file.write(
                "CascadeCreate TO_VPNServer /SERVER:{}:443 /HUB:VirtualHub_{} /USERNAME:root\n".format(
                    self.vpnserver_ip,
                    self.cascade_name))
            bridge_config_file.write(
                "CascadeCertSet TO_VPNServer /LOADCERT:/usr/local/vpnbridge/config/{}/{}_cert /LOADKEY:/usr/local/vpnbridge/config/{}/{}_key\n".format(
                    self.cascade_name,
                    self.cascade_name,
                    self.cascade_name,
                    self.cascade_name))
            bridge_config_file.write("CascadeOnline TO_VPNServer\n")
            bridge_config_file.close()

        elif self.type_connection == "udp":

            bridge_config_file = open(
                "/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt".format(self.cascade_name,
                                                                                         self.cascade_name),
                "w+")
            bridge_config_file.write("BridgeCreate BRIDGE /DEVICE:{} /TAP:no\n".format(self.vpnbridge_interface))
            bridge_config_file.write("Hub BRIDGE\n")
            bridge_config_file.write(
                "CascadeCreate TO_VPNServer /SERVER:{}:1194 /HUB:VirtualHub_{} /USERNAME:root\n".format(
                    self.vpnserver_ip,
                    self.cascade_name))
            bridge_config_file.write(
                "CascadeCertSet TO_VPNServer /LOADCERT:/usr/local/vpnbridge/config/{}/{}_cert /LOADKEY:/usr/local/vpnbridge/config/{}/{}_key\n".format(
                    self.cascade_name,
                    self.cascade_name,
                    self.cascade_name,
                    self.cascade_name))
            bridge_config_file.write("CascadeOnline TO_VPNServer\n")
            bridge_config_file.close()

        cmd = '/usr/local/vpnbridge/vpncmd localhost /SERVER /PASSWORD:123456 /in:/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt'.format(
            self.cascade_name, self.cascade_name)

        s, o = sudo_runner(cmd)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t start VPN'})


class L2VPNBridgeUpdateFile:
    def __init__(self, type_connection, vpnserver_ip, vpnbridge_interface, cascade_name):
        self.type_connection = type_connection
        self.vpnserver_ip = vpnserver_ip
        self.vpnbridge_interface = vpnbridge_interface
        self.cascade_name = cascade_name

    def update_config_file(self):
        '''update config file'''
        bridge_delete_file = open(
            "/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt".format(
                self.cascade_name, self.cascade_name), "w+")
        bridge_delete_file.write(
            "BridgeDelete BRIDGE /DEVICE:{}\n".format(self.vpnbridge_interface))
        bridge_delete_file.write("Hub BRIDGE\n")
        bridge_delete_file.write("CascadeDelete TO_VPNServer\n")
        bridge_delete_file.close()

        cmd1 = '/usr/local/vpnbridge/vpncmd localhost /SERVER /PASSWORD:123456 /in:/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt'.format(
            self.cascade_name, self.cascade_name)
        s, o = sudo_runner(cmd1)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t stop L2VPN'})

        time.sleep(1)

        cmd2 = 'rm -f /usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt'.format(
            self.cascade_name,
            self.cascade_name)
        s, o = sudo_runner(cmd2)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t remove L2VPN Config files'})


class l2VPNBridgeSerilizer(serializers.ModelSerializer):
    class Meta:
        model = l2VPNBridge
        fields = '__all__'

    def create(self, validated_data):
        type_connection = validated_data['type_connection']
        vpnserver_ip = validated_data['vpnserver_ip']
        vpnbridge_interface = validated_data['vpnbridge_interface']
        cascade_name = validated_data['cascade_name']

        vpn = l2VPNBridge(type_connection=type_connection,
                          vpnserver_ip=vpnserver_ip,
                          vpnbridge_interface=vpnbridge_interface,
                          cascade_name=cascade_name)
        vpn.save()
        mkdir = 'yes'
        config_file = L2VPNBridgeCreateFile(type_connection, vpnserver_ip, vpnbridge_interface, cascade_name, mkdir)
        config_file.create_config_file()
        return vpn

    def update(self, instance, validated_data):
        type_connection = instance.type_connection
        vpnserver_ip = instance.vpnserver_ip
        vpnbridge_interface = instance.vpnbridge_interface
        cascade_name = instance.cascade_name

        instance.type_connection = validated_data['type_connection']
        instance.vpnserver_ip = validated_data['vpnserver_ip']
        instance.vpnbridge_interface = validated_data['vpnbridge_interface']
        instance.cascade_name = validated_data['cascade_name']
        instance.save()

        update_file = L2VPNBridgeUpdateFile(type_connection, vpnserver_ip, vpnbridge_interface, cascade_name)
        update_file.update_config_file()

        config_file = L2VPNBridgeCreateFile(instance.type_connection, instance.vpnserver_ip,
                                            instance.vpnbridge_interface, instance.cascade_name)
        config_file.create_config_file()

        return instance
