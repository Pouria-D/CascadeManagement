import json
import os
import sys

import requests
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils.translation import gettext as _
from requests.models import Response as MockResponse
from rest_framework import permissions, status
from rest_framework import viewsets, serializers
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response

from api.settings import BACKUP_DIR, POLICY_BACK_POSTFIX
from auth_app.utils import get_client_ip
from brand import BRAND, COMPANY
from config_app.filters import InterfaceFilter, StaticRouteFilter, DNSRecordFilter, BackupFilter, SNMPFilter, \
    LogServerFilter, \
    SystemServiceFilter
from config_app.models import Interface, StaticRoute, DHCPServerConfig, Backup, \
    NTPConfig, UpdateConfig, LogServer, Setting, DNSRecord, DNSConfig, fs, \
    SystemService, Update, Snmp, Hostname, HighAvailability
from config_app.serializers import InterfaceSerializer, StaticRouteWriteSerializer, DHCPServerConfigSerializer, \
    BackupSerializer, InterfaceRealSerializer, NTPConfigSerializer, \
    UpdateConfigSerializer, StaticRouteReadSerializer, LogServerSerializer, \
    StaticRouteRealSerializer, SettingSerializer, DNSConfigSerializer, DNSRecordSerializer, \
    DNSConfigReadSerializer, DNSRecordReadSerializer, SystemServiceSerializer, UpdateSerializer, \
    InterfaceChangeSerializer, StaticRouteChangeSerializer, \
    SnmpSerializer, DHCPServerReadSerializer, HighAvailabilitySerializer, \
    HighAvailabilityRealSerializer
from config_app.utils import delete_static_route_cmd, check_static_route_existence, dns_record_config, \
    remove_rsyslog_server, open_port_in_iptables, remove_snmpv2_config, remove_snmpv3_config, clear_DHCP_configuration, \
    remove_bridge_interface, \
    remove_Vlan_interface, ha_read_status, this_system_is_master, remove_ha_config_on_peers
from entity_app.models import Address, Schedule, Service
from firewall_app.models import SourceDestination, Policy
from firewall_input_app.models import InputFirewall
from firewall_input_app.utils import apply_rule
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner, sudo_restart_systemd_service, sudo_file_reader, sudo_install_update, \
    sudo_file_writer
from root_runner.utils import command_runner
from utils.config_files import IPSEC_CONF_FILE, IPSEC_SECRETS_FILE, RSYSLOG_CONFIG_FILE, GRE_CONFIGS_PATH, \
    IPIP_CONFIGS_PATH, VTUND_CONFIGS_PATH, RC_LOCAL_FILE, DNSMASQ_CONFIG_FILE
from utils.log import log
from utils.utils import run_thread, TLSAdapter
from vpn_app.models import VPN


class HighAvailabilityViewSet(viewsets.ModelViewSet):
    queryset = HighAvailability.objects.all()

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return HighAvailabilitySerializer
        real = self.request.query_params.get('real', None)
        if real:
            return HighAvailabilityRealSerializer
        else:
            return HighAvailabilitySerializer

    def list(self, request, *args, **kwargs):
        response = super(HighAvailabilityViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'ha_config', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(HighAvailabilityViewSet, self).retrieve(request, *kwargs, **kwargs)
        log('config', 'ha_config', 'retrieve', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def destroy(self, request, *args, **kwargs):
        if HighAvailability.objects.filter(is_enabled=True, status='succeeded'):
            real_ha_status = ha_read_status()
            try:
                active_node = real_ha_status['active_node']
            except:
                active_node = ""
            if not this_system_is_master(real_ha_status):
                if active_node:
                    raise serializers.ValidationError(_('Delete HighAvailability configuration is only possible on '
                                                        'active node or when active node does not exist.'))
        instance = self.get_object()
        serializer = HighAvailabilitySerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        if instance.is_enabled:
            instance_id = instance.id
            ssh_port = Setting.objects.get(key='ssh-port').data['value']
            https_port = Setting.objects.get(key='https-port').data['value']
            act = 'delete'
            run_thread(target=remove_ha_config_on_peers, name='delete_HA_config',
                       args=(instance.peer1_address, instance.peer2_address,
                             instance.configured_peer_interface_mac.split('#')[0],
                             instance_id, ssh_port, https_port, act))

        Notification.objects.filter(source='HA').delete()
        instance.delete()
        log('config', 'ha_config', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['POST', 'DELETE'])
    def ha_sync_db_assurance(self, *args, **kwargs):
        # we had this problem for syncing databases: When for example policies were completely deleted, sync coudln't
        # work correctly because there were no footprint of it in the dump file !
        # for this reason we oath to call this method to remove every thing that is not in dumpdata file
        file = '/tmp/dumpdata.json'

        status, result = command_runner('cat {}'.format(file))
        if status:
            if '"model": "config_app.setting"' in result:  # only for insuring that file has a content
                if '"model": "firewall_app.policy"' not in result:
                    Policy.objects.all().delete()
                if '"model": "vpn_app.vpn"' not in result:
                    VPN.objects.all().delete()
                if '"model": "config_app.staticroute"' not in result:
                    StaticRoute.objects.all().delete()
                if '"model": "entity_app.address"' not in result:
                    Address.objects.all().delete()
                if '"model": "entity_app.schedule"' not in result:
                    Schedule.objects.all().delete()
                if '"model": "entity_app.service"' not in result:
                    Service.objects.all().delete()
                if '"model": "config_app.dhcpserverconfig"' not in result:
                    DHCPServerConfig.objects.all().delete()
                if '"model": "config_app.dnsrecord"' not in result:
                    DNSRecord.objects.all().delete()
                if '"model": "config_app.snmp"' not in result:
                    Snmp.objects.all().delete()
                if '"model": "config_app.logserver"' not in result:
                    LogServer.objects.all().delete()
                if '"model": "config_app.ntpconfig"' not in result:
                    NTPConfig.objects.all().delete()
                if '"model": "config_app.updateconfig"' not in result:
                    UpdateConfig.objects.all().delete()
        return Response('syncing finished')


class InterfaceViewSet(viewsets.ModelViewSet):
    queryset = Interface.objects.all().order_by('name_sort')
    lookup_value_regex = '[a-z.0-9A-Z_-]+'  # Add this line for  accepting  dot character
    http_method_names = ['get', 'put', 'patch', 'post', 'delete']
    filter_class = InterfaceFilter
    search_fields = ('name', 'description', 'alias', 'ip_list', 'gateway', 'type',
                     'link_type', 'pppoe_username', 'pppoe_password', 'mtu',)
    ordering_fields = '__all__'

    def get_object(self):
        instance = Interface.objects.get(name=self.kwargs['pk'])
        return instance

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return InterfaceSerializer

        real = self.request.query_params.get('real', None)
        if real:
            return InterfaceRealSerializer
        else:
            return InterfaceSerializer

    def list(self, request, *args, **kwargs):
        from django.core import serializers

        response = super(InterfaceViewSet, self).list(request, *kwargs, **kwargs)
        try:
            for index, inter in enumerate(response.data['results']):
                if inter['mode'] == 'bridge' or inter['mode'] == 'vlan':

                    for index2, obj in enumerate(inter['data'][0]['interface']):
                        temp = Interface.objects.filter(name=obj)

                        inter_json = serializers.serialize('json', temp)
                        data = json.loads(inter_json)[0]['fields']
                        data['name'] = json.loads(inter_json)[0]['pk']
                        response.data['results'][index]['data'][0]['interface'][index2] = data
        except:
            # response.data['results'][index]['data'][0]['interface'][index2] = None
            pass
        try:
            if request.GET['mode'] == 'interface':
                log('config', 'interface', 'list', 'success', username=request.user.username, ip=get_client_ip(request))

            if request.GET['mode'] == 'bridge':
                log('config', 'bridge', 'list', 'success', username=request.user.username, ip=get_client_ip(request))

            if request.GET['mode'] == 'vlan':
                log('config', 'vlan', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        except:
            pass

        return response

    def retrieve(self, request, *args, **kwargs):
        from django.core import serializers

        response = super(InterfaceViewSet, self).retrieve(request, *kwargs, **kwargs)
        try:
            if response.data['mode'] == 'bridge' or response.data['mode'] == 'vlan':
                for index2, obj in enumerate(response.data['data'][0]['interface']):
                    temp = Interface.objects.filter(name=obj)
                    inter_json = serializers.serialize('json', temp)
                    data = json.loads(inter_json)[0]['fields']
                    data['name'] = json.loads(inter_json)[0]['pk']
                    response.data['data'][0]['interface'][index2] = data
        except:
            # response.data['data'][0]['interface'][index2] = None
            pass

        instance = self.get_object()
        details = {
            'items': {
                'name': instance.name
            }
        }

        try:
            if response.data['mode'] == 'interface':
                log('config', 'interface', 'retrieve', 'success',
                    username=request.user.username, ip=get_client_ip(request), details=details)

            if response.data['mode'] == 'bridge':
                log('config', 'bridge', 'retrieve', 'success',
                    username=request.user.username, ip=get_client_ip(request), details=details)

            if response.data['mode'] == 'vlan':
                log('config', 'vlan', 'retrieve', 'success',
                    username=request.user.username, ip=get_client_ip(request), details=details)
        except:
            pass
        return response

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = InterfaceChangeSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        response = HttpResponse()
        error = " "
        policy_in = SourceDestination.objects.filter(src_interface_list__name__exact=instance.name)
        policy_out = SourceDestination.objects.filter(dst_interface_list__name__exact=instance.name)
        dns = DNSConfig.objects.filter(interface_list__name__exact=instance.name)
        dhcp = DHCPServerConfig.objects.filter(interface__name__exact=instance.name)
        if policy_in or policy_out: error += ' Policy '
        if dns: error += ' DNS '
        if dhcp: error += ' DHCP '

        if policy_in or policy_out or dns or dhcp:
            raise serializers.ValidationError(

                "Can't delete interfaces, This interface is used by {}".format(error)

            )

        if instance.mode == 'bridge':
            remove_bridge_interface(instance, request.user.username, request, details, 'delete', is_watcher=False)
            response = super(InterfaceViewSet, self).destroy(request, *kwargs, **kwargs)

        if instance.mode == 'vlan':
            remove_Vlan_interface(instance, request.user.username, request, details, 'delete', is_watcher=False)
            response = super(InterfaceViewSet, self).destroy(request, *kwargs, **kwargs)

        log('config', 'interface', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        return response


class StaticRouteViewSet(viewsets.ModelViewSet):
    queryset = StaticRoute.objects.all()
    filter_class = StaticRouteFilter
    search_fields = (
        'name', 'description', 'destination_ip', 'destination_mask', 'interface__name', 'gateway', 'metric')
    ordering_fields = '__all__'
    ordering = ('id',)

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return StaticRouteWriteSerializer

        real = self.request.query_params.get('real', None)
        if real:
            return StaticRouteRealSerializer
        else:
            return StaticRouteReadSerializer

    def list(self, request, *args, **kwargs):
        response = super(StaticRouteViewSet, self).list(request, *kwargs, **kwargs)
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(StaticRouteViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('config', 'static-route', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def perform_destroy(self, instance):
        with transaction.atomic():
            request_username = None
            if self.request and hasattr(self.request, 'user'):
                request_username = self.request.user.username

            if instance.is_enabled and check_static_route_existence(instance):

                cmd = delete_static_route_cmd(instance)
                s, result = sudo_runner(cmd)

                if not s and 'No such process' not in str(result):
                    instance.last_operation = 'delete'
                    instance.status = 'failed'
                    instance.save()

                    create_notification(source='static_route', item={'id': instance.id, 'name': instance.name},
                                        message=str('Error in deleting static route'), severity='e',
                                        details={'command': cmd, 'error': str(result)},
                                        request_username=request_username)

                    details = {
                        'items': {
                            'id': instance.id,
                            'name': instance.name,
                        }
                    }
                    log('config', 'static-route', 'delete', 'fail',
                        username=request_username, ip=get_client_ip(self.request), details=details)
                    raise serializers.ValidationError('Cannot delete static route because ' + str(result))

            Notification.objects.filter(source='static_route', item__id=instance.id).delete()

            serializer = StaticRouteChangeSerializer(instance)
            details = {
                'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
            }
            log('config', 'static-route', 'delete', 'success',
                username=request_username, ip=get_client_ip(self.request), details=details)

            instance.delete()


class DHCPServerConfigViewSet(viewsets.ModelViewSet):
    queryset = DHCPServerConfig.objects.all()

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return DHCPServerConfigSerializer
        else:
            return DHCPServerReadSerializer

    def list(self, request, *args, **kwargs):
        response = super(DHCPServerConfigViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'dhcp-server-setting', 'list', 'success', username=request.user.username,
            ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(DHCPServerConfigViewSet, self).retrieve(request, *kwargs, **kwargs)
        return response

    def destroy(self, request, *args, **kwargs):
        request_username = None
        if request and hasattr(request, 'user'):
            request_username = request.user.username
        instance = self.get_object()
        if instance.is_enabled:
            instance.last_operation = 'delete'
            instance.status = 'pending'
            instance.save()

            run_thread(target=clear_DHCP_configuration, name='clear_DHCP_configuration', args=(instance,))

        serializer = DHCPServerConfigSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        log('config', 'dhcp-server-setting', 'delete', 'success',
            username=request_username, ip=get_client_ip(request), details=details)
        instance.status = 'failed'
        instance.save()
        instance.delete()

        if not DHCPServerConfig.objects.filter(is_enabled=True):
            InputFirewall.objects.filter(port__exact='67').delete()
            InputFirewall.objects.filter(port__exact='68').delete()
            apply_rule(None, None)

        return Response(status=status.HTTP_204_NO_CONTENT)


class BackupViewSet(viewsets.ModelViewSet):
    queryset = Backup.objects.all()
    filter_class = BackupFilter
    serializer_class = BackupSerializer
    search_fields = ('file', 'description', 'version')

    @action(detail=True, methods=['GET', 'POST'])
    def file(self, request, *args, **kwargs):
        instance = self.get_object()

        if self.request.method == 'GET':
            if not instance.file:
                return Response('Backup has no file.', status=status.HTTP_404_NOT_FOUND)

            backup_file_path = os.path.join(BACKUP_DIR, instance.file.name.replace('json', 'tar'))
            temp_backup_file_path = backup_file_path.replace('.tar', '.tmp')
            encrypted_backup_file_path = backup_file_path.replace('.tar', '.bak')

            command_runner('cp {} {}'.format(backup_file_path, temp_backup_file_path))

            cmd_status, output = command_runner('openssl enc -aes-256-cbc -in {} -out {} -k ngfw'.format(
                temp_backup_file_path, encrypted_backup_file_path))

            if not cmd_status:
                log('config', 'backup', 'add', 'fail',
                    username=request.user.username, ip=get_client_ip(request), details=output)

                instance.status = 'failed'
                instance.save()
                return Response('Error in downloading backup file', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            os.remove(temp_backup_file_path)

            file_name = instance.file.name.replace('.tar', '.bak')
            fsock = open(encrypted_backup_file_path, "rb")
            response = HttpResponse(fsock, content_type='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename=%s' % file_name
            command_runner('rm {}'.format(encrypted_backup_file_path))
            return response

        elif self.request.method == 'POST':
            self.parser_classes = (MultiPartParser,)
            if 'file' not in self.request.FILES:
                raise serializers.ValidationError({'file': 'This field is required'})

            encrypted_filename = fs.save(request.FILES.get('file').name, request.FILES.get('file'))
            file_name = encrypted_filename.replace('.bak', '.tar')
            file_path = os.path.join(BACKUP_DIR, file_name)

            cmd_status, output = command_runner("openssl enc -d -aes-256-cbc -in '{}' -out '{}' -k ngfw".format(
                os.path.join(BACKUP_DIR, encrypted_filename), file_path))

            if not cmd_status:
                command_runner('rm /var/ngfw/{}'.format(file_name))
                command_runner('rm /var/ngfw/{}'.format(encrypted_filename))
                instance.delete()
                raise serializers.ValidationError({'file': 'Invalid backup file'})

            os.remove(os.path.join(BACKUP_DIR, encrypted_filename))
            command_runner('cd /var/ngfw;tar -xf {} info.txt'.format(file_name))

            with open('/var/ngfw/info.txt') as f:
                content = f.read()
                description, version, backup_datetime = content.split('$$$ngfw$$$')

            s, version_now = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
                os.path.join(BACKUP_DIR, 'currentversion.yml'))
            )

            if version != version_now:
                command_runner('rm /var/ngfw/{}'.format(file_name))
                instance.delete()
                raise serializers.ValidationError({'file': 'system and backup file version does not match!'})

            file_name = 'sg_backup_{}.tar'.format(backup_datetime[:19]).replace(' ', '_').replace(':', '.')
            os.rename(file_path, os.path.join(BACKUP_DIR, file_name))

            if Backup.objects.filter(datetime=backup_datetime):
                instance.delete()
                raise serializers.ValidationError({'file': ' duplicate file'})

            instance.file = file_name.replace('.tar', '.json')
            instance.description = description
            instance.version = version
            instance.datetime = backup_datetime
            instance.save()

            serializer = BackupSerializer(instance=instance)

            log('config', 'backup', 'add', 'success', username=request.user.username, ip=get_client_ip(request))

            return Response(serializer.data)

        else:
            return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @action(detail=True, methods=['POST', 'PUT', 'PATCH', 'GET'])
    def restore(self, request, *args, **kwargs):
        instance = self.get_object()

        s, version = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
            os.path.join(BACKUP_DIR, 'currentversion.yml'))
        )

        if instance.version != version:
            return Response({'restore_backup': 'Version does not match!'}, status.HTTP_400_BAD_REQUEST)

        try:
            command_runner('cd /var/ngfw;tar -xvf {}.tar'.format(instance.file.path.replace('.json', '')))

            with open('{}'.format(instance.file.path)) as bac:
                data = json.load(bac)

                number_interface_backup = str(data).count("'mode': 'interface'")
                number_corent_interface = Interface.objects.filter(mode='interface').count()

                if number_corent_interface < number_interface_backup:
                    command_runner('rm {}'.format(instance.file.path))
                    return Response({'restore_backup': 'The device interface does not match the backup interface'},
                                    status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            instance.status = 'failed'
            instance.save()
            raise e

        run_thread(target=self.async_restore, name='restore_{}'.format(instance.id), args=(instance,))

        serializer = BackupSerializer(instance=instance)
        log('config', 'backup', 'restore', 'success', username=request.user.username, ip=get_client_ip(request))
        return Response(serializer.data)

    @action(detail=False, methods=['POST', 'PUT', 'PATCH'])
    def factory_reset(self, *args, **kwargs):
        confirm = self.request.query_params.get('confirm')

        if not confirm == 'true':
            raise serializers.ValidationError('You should confirm this action by sending confirm=true in query string')

        sudo_runner('sudo service postgresql restart;'
                    'psql -U postgres -c "drop database api";'
                    'psql -U postgres -c "create database api";'
                    'manage.py migrate;'
                    'rm -rf /var/ngfw/{}/*;'
                    'sudo service api restart;'
                    'sudo service watcher restart;'
                    'sudo service ws restart'.format(POLICY_BACK_POSTFIX))

    def list(self, request, *args, **kwargs):
        response = super(BackupViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'backup', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(BackupViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'description': instance.description
            }
        }
        log('config', 'backup', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = BackupSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in
                      ['file', 'is_uploaded_by_user', 'last_operation', 'status']}
        }

        log('config', 'backup', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        response = super(BackupViewSet, self).destroy(request, *kwargs, **kwargs)
        return response

    def async_restore(self, instance):
        from django.core.management import call_command

        instance.last_operation = 'restore'
        instance.status = 'pending'
        instance.save()

        command_runner('rm /var/ngfw/policy_back -r')
        sudo_runner('rm {}'.format(RSYSLOG_CONFIG_FILE))
        sudo_runner('mkdir {}'.format(os.path.join(BACKUP_DIR, '{}/'.format(POLICY_BACK_POSTFIX))))
        sudo_runner('cp /var/ngfw{}  /etc'.format(RSYSLOG_CONFIG_FILE))
        sudo_runner('cp /var/ngfw{}  /etc'.format(IPSEC_CONF_FILE))
        sudo_runner('cp /var/ngfw{}  /etc'.format(DNSMASQ_CONFIG_FILE))
        sudo_runner('cp /var/ngfw{}  /etc'.format(IPSEC_SECRETS_FILE))
        sudo_runner('cp /var/ngfw{}  /etc'.format(GRE_CONFIGS_PATH))
        sudo_runner('cp /var/ngfw{}  /etc'.format(IPIP_CONFIGS_PATH))
        sudo_runner('cp /var/ngfw{}  /etc'.format(VTUND_CONFIGS_PATH))
        command_runner('rm /var/ngfw/etc -r')

        # remove all bridge vlan static route
        bridge = Interface.objects.filter(mode='bridge')
        for obj in bridge:
            remove_bridge_interface(obj, None, None, None, None)

        vlan = Interface.objects.filter(mode='vlan')
        for obj in vlan:
            remove_Vlan_interface(obj, None, None, None, None)

        static_route_list = StaticRoute.objects.all()
        for item in static_route_list:
            sudo_runner(delete_static_route_cmd(item))

        try:
            call_command('dumpdata', exclude=[
                'auth_app.AdminLoginLock',
                'auth_app.Token',
                'sessions.Session',
                'auth.permission',
                'contenttypes'], output='/tmp/rollback_backup.json')
        except Exception as e:
            log('config', 'backup', 'restore', 'fail',
                username=self.request.user.username, ip=get_client_ip(self.request), details=str(e))
            instance.status = 'failed'
            instance.save()
            raise e

        try:
            call_command('dumpdata',
                         'config_app.Backup',
                         output='/tmp/narin_tmp.json')

            call_command('flush', '--no-input')

            call_command('loaddata', '/tmp/narin_tmp.json')
            call_command('loaddata', instance.file.path)
            instance.status = 'succeeded'

            command_runner('rm {}'.format(instance.file.path))

        except Exception as e:

            call_command('flush', '--no-input')
            call_command('loaddata', '/tmp/rollback_backup.json')

            log('config', 'backup', 'restore', 'fail',
                username=self.request.user.username, ip=get_client_ip(self.request), details=str(e))
            instance.status = 'failed'
            instance.save()
            raise e

        sudo_runner('iptables -F')
        sudo_runner('iptables -X')
        sudo_runner('iptables -F -t nat')
        sudo_runner('iptables -X -t nat')
        sudo_runner('iptables -F -t mangle')
        sudo_runner('iptables -X -t mangle')
        sudo_runner('ipset -F')
        sudo_runner('ipset -X')

        sudo_restart_systemd_service('watcher')
        sudo_restart_systemd_service('ipsec')
        sudo_restart_systemd_service('dnsmasq')

        instance.save()
        log('config', 'backup', 'restore', 'success',
            username=self.request.user.username, ip=get_client_ip(self.request))


class NTPConfigViewSet(viewsets.ModelViewSet):
    queryset = NTPConfig.objects.all()
    serializer_class = NTPConfigSerializer
    http_method_names = ['get', 'put', 'post', 'patch']

    def list(self, request, *args, **kwargs):
        response = super(NTPConfigViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'ntp-setting', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request))
        return response


class UpdateConfigViewSet(viewsets.ModelViewSet):
    queryset = UpdateConfig.objects.all()
    serializer_class = UpdateConfigSerializer
    http_method_names = ['get', 'put', 'post', 'patch']

    def list(self, request, *args, **kwargs):
        response = super(UpdateConfigViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'update-manager-setting', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request))
        return response


class SnmpViewset(viewsets.ModelViewSet):
    queryset = Snmp.objects.all()
    filter_class = SNMPFilter
    serializer_class = SnmpSerializer
    search_fields = (
        'user_name', 'security_level', 'private_algorithm', 'authentication_algorithm', 'allow_network', 'snmp_type',
        'is_enabled', 'description')
    ordering_fields = '__all__'
    ordering = ('id',)

    def list(self, request, *args, **kwargs):
        response = super(SnmpViewset, self).list(request, *args, **kwargs)
        log('config', 'snmp', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(SnmpViewset, self).retrieve(request, *args, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
            }
        }
        log('config', 'snmp', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = SnmpSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }

        if instance.is_enabled:
            operation = 'delete'
            if instance.snmp_type == "v2":
                remove_snmpv2_config(instance, request.user.username, request, details, operation)
            else:
                remove_snmpv3_config(instance, request.user.username, request, details, operation)

        Notification.objects.filter(source='snmp', item__id=instance.id).delete()
        response = super(SnmpViewset, self).destroy(request, *kwargs, **kwargs)

        if not Snmp.objects.filter(is_enabled=True):
            InputFirewall.objects.filter(port__exact='161').delete()
            apply_rule(None, None)

        return response


class LogServerViewSet(viewsets.ModelViewSet):
    queryset = LogServer.objects.all()
    filter_class = LogServerFilter
    serializer_class = LogServerSerializer
    search_fields = ('address', 'port', 'protocol', 'is_enabled', 'is_secure')
    filter_fields = ('is_enabled',)
    ordering_fields = '__all__'
    ordering = ('id',)

    def list(self, request, *args, **kwargs):
        response = super(LogServerViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'log-servers', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(LogServerViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'address': instance.address
            }
        }
        # log('config', 'log-servers', 'retrieve', 'success',
        #     username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = LogServerSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        if instance.is_enabled:
            operation = 'delete'
            # if not remove_rsyslog_server(instance, request.user.username, request, details, operation):
            #     instance.status = 'failed'
            #     raise serializers.ValidationError({'non_field_errors': 'Can\'t read syslog configs'})

            # if instance.is_enabled:
            instance.last_operation = 'delete'
            instance.status = 'pending'
            instance.save()

            run_thread(target=remove_rsyslog_server, name='rsyslog_{}'.format(instance.id),
                       args=(instance, request.user.username, request, details, operation))

            if instance.protocol == 'tcp':
                open_port_in_iptables(old_port=str(instance.port), direction='sport')

        log('config', 'log-servers', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        instance.status = 'succeeded'
        instance.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class SettingViewSet(viewsets.ModelViewSet):
    serializer_class = SettingSerializer
    http_method_names = ['get', 'put']
    search_fields = ('key', 'data')

    def get_queryset(self):
        if self.kwargs and self.kwargs.get('pk'):
            key = self.kwargs.get('pk')
            if key == 'host-name':
                queryset = Hostname.objects.filter(key=key)
            else:
                queryset = Setting.objects.filter(key=key)
        else:
            settings = Setting.objects.all()
            hostname = Hostname.objects.all()
            queryset = settings.union(hostname)
        return queryset

    def list(self, request, *args, **kwargs):
        settings = self.get_queryset().order_by('key')
        search_key = self.request.query_params.get('search')
        if search_key:
            settings = settings.filter(
                Q(key__icontains=search_key) |
                Q(data__icontains=search_key) |
                Q(display_name__icontains=search_key) |
                Q(descriptions__icontains=search_key) |
                Q(category__icontains=search_key)
            )

        serializer = SettingSerializer(settings, many=True)
        result = dict()

        for item in serializer.data:
            if item['category'] not in result:
                result[item['category']] = list()

            result[item['category']].append(item)

        log('config', 'settings', 'list', 'success',
            username=request.user.username, ip=get_client_ip(request))

        return Response(result)

    @action(methods=['put'], detail=True)
    def keygen(self, *args, **kwargs):
        instance = self.get_object()

        if instance.key != 'ssl_certificate':
            raise serializers.ValidationError('This action just available for ssl_certificate')

        sudo_runner('openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout /etc/ssl/private/nginx-selfsigned.key \
                -out /etc/ssl/certs/nginx-selfsigned.crt \
                -subj "/O={company}/OU={product}/CN={product}.loc"'.format(company=COMPANY, product=BRAND))

        sudo_restart_systemd_service('nginx')

        return Response('nginx ssl cert regenerated successfully')


class DNSConfigViewSet(viewsets.ModelViewSet):
    queryset = DNSConfig.objects.all()
    http_method_names = ['get', 'put', 'patch']

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return DNSConfigSerializer
        return DNSConfigReadSerializer

    def list(self, request, *args, **kwargs):
        response = super(DNSConfigViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'dns_config', 'retrieve', 'success', username=request.user.username, ip=get_client_ip(request))
        return response


class DNSRecordViewSet(viewsets.ModelViewSet):
    queryset = DNSRecord.objects.all()
    serializer_class = DNSRecordSerializer
    filter_class = DNSRecordFilter
    search_fields = (
        'ip_address', 'hostname_list')
    ordering_fields = '__all__'

    def list(self, request, *args, **kwargs):
        response = super(DNSRecordViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'dns_record', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(DNSRecordViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'ip address': instance.ip_address
            }
        }
        log('config', 'dns_record', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        record = self.get_object()
        serializer = DNSRecordSerializer(record)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }

        Notification.objects.filter(source='dns_record', item__id=record.id).delete()
        dns_record_config(record, 'delete', None, None, request.user.username, request, details)

        response = super().destroy(request, *args, **kwargs)
        return response

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return DNSRecordSerializer
        return DNSRecordReadSerializer


class SystemServiceViewSet(viewsets.ModelViewSet):
    queryset = SystemService.objects.all()
    serializer_class = SystemServiceSerializer
    http_method_names = ('get', 'put', 'patch')
    search_fields = ('name',)
    filter_class = SystemServiceFilter

    def list(self, request, *args, **kwargs):
        response = super(SystemServiceViewSet, self).list(request, *kwargs, **kwargs)
        log('config', 'system_services', 'list', 'success',
            username=self.request.user.username, ip=get_client_ip(self.request))
        return response

    @action(methods=['PUT', 'PATCH'], detail=True)
    def restart(self, *args, **kwargs):
        instance = self.get_object()

        if instance.real_name == 'ipsec':
            command_status, result = command_runner('service {} status'.format(instance.real_name))

            if not command_status or 'Active: active (running)' not in str(result):
                sudo_runner('rm -f /var/run/charon.pid')
                sudo_runner('rm -f /var/run/starter.charon.pid')

        command_status, output = sudo_runner('service {} restart'.format(instance.real_name))
        details = {'items': {'service name': instance.name}}

        if command_status:
            log('config', 'system_services', 'restart', 'success',
                username=self.request.user.username, ip=get_client_ip(self.request), details=details)
            return Response(status=status.HTTP_200_OK)
        else:
            log('config', 'system_services', 'restart', 'fail',
                username=self.request.user.username, ip=get_client_ip(self.request), details=details)
            return Response('Restarting service failed', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(methods=['PUT', 'PATCH'], detail=True)
    def stop(self, *args, **kwargs):
        instance = self.get_object()
        command_status, output = sudo_runner('service {} stop'.format(instance.real_name))
        details = {'items': {'service name': instance.name}}

        if command_status:
            log('config', 'system_services', 'stop', 'success',
                username=self.request.user.username, ip=get_client_ip(self.request), details=details)
            return Response(status=status.HTTP_200_OK)
        else:
            log('config', 'system_services', 'stop', 'fail',
                username=self.request.user.username, ip=get_client_ip(self.request), details=details)
            return Response('Stopping service failed', status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateViewSet(viewsets.ModelViewSet):
    queryset = Update.objects.all()
    serializer_class = UpdateSerializer
    test_param = None
    count_update_check = 0

    @action(detail=False, methods=['get'])
    def check(self, *args, **kwargs):
        try:
            instance = UpdateConfig.objects.get()
        except:
            return Response(status=status.HTTP_204_NO_CONTENT)

        if instance.is_update_enabled:
            update = None
            # The order of this list is important.
            for current_update_status in ['installing', 'validated', 'validating', 'downloaded',
                                          'downloading',
                                          'restore_point', 'rollback', 'failed']:
                try:
                    update = Update.objects.get(status=current_update_status)

                except Update.MultipleObjectsReturned:
                    Update.objects.filter(status=current_update_status).delete()
                    pass
                except Update.DoesNotExist:
                    pass

            if update:
                # this block use for rollback if system shutdown during installing
                try:
                    with open('/var/ngfw/update_temp/rollback.txt') as content:
                        content = content.read()

                    if 'roll_back' in content:

                        if update.status == 'installing' or update.status == 'rollback':
                            # call_command('flush', '--no-input')
                            # call_command('loaddata', '/var/ngfw/update_temp/restore_point*.json')

                            update.status = 'failed'
                            update.save()
                            sudo_runner('rm /var/ngfw/update_temp/rollback.txt')

                            s, content = sudo_file_reader(RC_LOCAL_FILE)
                            if s:
                                content = content.replace('rollback=1', 'rollback=0')
                                sudo_file_writer(RC_LOCAL_FILE, content, 'w')

                        if update.status == 'restore_point':
                            update.status = 'failed'
                            update.save()
                            sudo_runner('rm /var/ngfw/update_temp/rollback.txt')
                            s, content = sudo_file_reader(RC_LOCAL_FILE)
                            if s:
                                content = content.replace('rollback=1', 'rollback=0')
                                sudo_file_writer(RC_LOCAL_FILE, content, 'w')

                except:
                    pass

                serializer = UpdateSerializer(update)
                return Response(serializer.data)

            UpdateViewSet.count_update_check += 1
            if UpdateViewSet.count_update_check > 10:
                run_thread(target=self.check_thread, name='check_thread', args=(None,))
                UpdateViewSet.count_update_check = 0

            try:
                update = Update.objects.last()
                if update:
                    if update.status == 'completed' or update.status == 'available':
                        serializer = UpdateSerializer(Update.objects.last())
                        log('config', 'updates', 'check', 'success',
                            username=self.request.user.username, ip=get_client_ip(self.request))
                        return Response(serializer.data)
            except Update.DoesNotExist:
                log('config', 'updates', 'check', 'fail',
                    username=self.request.user.username, ip=get_client_ip(self.request))
                return Response(status=status.HTTP_204_NO_CONTENT)

            return Response(status=status.HTTP_204_NO_CONTENT)
        else:

            return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'])
    def check_now(self, *args, **kwargs):
        run_thread(target=self.check_thread, name='check_thread', args=(None,))
        self.check()
        return Response(status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def download(self, *args, **kwargs):
        update_list = Update.objects.filter(status__in=['available', 'failed'])

        if not update_list:
            log('config', 'updates', 'download', 'fail',
                username=self.request.user.username, ip=get_client_ip(self.request))
            raise serializers.ValidationError('First you must check for new version by '
                                              'sending request to /api/config/updates/check')

        update = update_list[0]

        self.test_param = self.request.query_params.get('test')

        run_thread(target=self.download_update, name='download_update_{}'.format(update.id), args=(update,))

        log('config', 'updates', 'download', 'success',
            username=self.request.user.username, ip=get_client_ip(self.request))

        return Response('Download started successfully')

    @action(detail=False, methods=['get'])
    def cancel_download(self, *args, **kwargs):

        for current_update_status in ['downloading', 'downloaded']:

            try:

                update = Update.objects.get(status=current_update_status)
                update.delete()
                sudo_runner('rm /var/ngfw/*.gpg')


            except Update.DoesNotExist:
                pass

        return Response('Download cancel successfully')

    @action(detail=False, methods=['get'])
    def retry(self, *args, **kwargs):
        try:
            update = Update.objects.get(status='failed')
            update.status = 'downloaded'
            update.save()

        except Update.MultipleObjectsReturned:
            Update.objects.filter(status='failed').delete()
            pass
        except Update.DoesNotExist:
            raise serializers.ValidationError('you must have failed update to retry  '
                                              'sending request to /api/config/updates/check')

        return Response('change state to downloaded')

    @action(detail=False, methods=['get'])
    def discard(self, *args, **kwargs):
        try:
            update = Update.objects.get(status='failed')
            update.delete()

        except Update.MultipleObjectsReturned:
            Update.objects.filter(status='failed').delete()
            pass
        except Update.DoesNotExist:
            raise serializers.ValidationError('you must have failed update to discard  '
                                              'sending request to /api/config/updates/check')

        return Response('your update status was successfully deleted')

    @action(detail=False, methods=['get'])
    def update_log(self, *args, **kwargs):

        try:
            update = Update.objects.get(status='failed')

        except Update.MultipleObjectsReturned:
            Update.objects.filter(status='failed').delete()
            pass
        except Update.DoesNotExist:
            pass

        update.update_log_flag = 1
        update.save()
        token = self.authenticate()
        try:
            cmd_status, output = command_runner(
                'openssl enc -aes-256-cbc -in /var/ngfw/update_info.txt -out /var/ngfw/update_info.der -k ngfw')
            files = {'file_data': open('/var/ngfw/update_info.der', 'rb')}

            s, version = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
                os.path.join(BACKUP_DIR, 'currentversion.yml'))
            )

            payload_tuples = [('version', version), ('file_name', 'mmm')]
            req = requests.Session()
            req.mount('https://', TLSAdapter())
            response = req.post(
                self.get_update_server_address() + '/api/update_log', files=files, data=payload_tuples,
                headers={'authorization': 'Token {}'.format(token)},
                verify=False)
        except requests.ConnectionError:
            response = MockResponse()
            response.status_code = 400
            return response

        return Response('crash report successfully send')

    @action(detail=False, methods=['get'])
    def cancel_update_log(self, *args, **kwargs):
        try:
            update = Update.objects.get(status='failed')

        except Update.MultipleObjectsReturned:
            Update.objects.filter(status='failed').delete()
            pass
        except Update.DoesNotExist:
            pass

        update.update_log_flag = 1
        update.save()

        return Response('crash report successfully cancel')

    @action(detail=False, methods=['get'])
    def validate(self, *args, **kwargs):
        update_list = Update.objects.filter(status__in=['downloaded', 'failed'])

        if not update_list:
            log('config', 'updates', 'validate', 'fail',
                username=self.request.user.username, ip=get_client_ip(self.request))
            raise serializers.ValidationError('First you must download new version by '
                                              'sending request to /api/config/updates/download')

        update = update_list[0]

        self.import_update_server_public_key()

        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                {'update_error': 'HighAvailability configured on this system,'
                                 ' disable HighAvailability configuration first to update the system.'})

        s, o = command_runner(
            'gpg --yes /var/ngfw/{brand}.v{ver}.tar.xz.enc.gpg'.format(brand=BRAND, ver=update.version))

        if not s:
            update.status = 'failed'
            update.save()
            raise serializers.ValidationError(
                {
                    'update_error': 'Looks like the server is taking too long to respond, please try again after sometime (0xBB) '})
        self.download_key(update)
        try:
            with open('/var/ngfw/{brand}.v{ver}.tar.xz.key'.format(brand=BRAND, ver=update.version)) as temp:
                key = temp.read()
        except:
            raise serializers.ValidationError({
                'update_error': 'something went wrong (0x2)'})

        s, o = command_runner(
            'openssl enc -d -aes-256-cbc -in /var/ngfw/{brand}.v{ver}.tar.xz.enc -out /var/ngfw/{brand}.v{ver}.tar.xz -k {key}'.format(
                brand=BRAND, ver=update.version, key=key))
        if not s:
            update.status = 'failed'
            update.save()
            raise serializers.ValidationError(
                {
                    'update_error': 'Looks like the server is taking too long to respond, please try again after sometime (0x5)'})

        update.status = 'validated'
        update.save()

        log('config', 'updates', 'validate', 'success',
            username=self.request.user.username, ip=get_client_ip(self.request))
        return Response('Update validated successfully')

    @action(detail=False, methods=['get'])
    def install(self, *args, **kwargs):
        update_list = Update.objects.filter(status__in=['validated', 'failed'])

        if not update_list:
            log('config', 'updates', 'install', 'success',
                username=self.request.user.username, ip=get_client_ip(self.request))
            raise serializers.ValidationError('First you must validate new version by '
                                              'sending request to /api/config/updates/validate')

        update = update_list[0]

        update.status = 'restore_point'
        update.save()

        run_thread(target=sudo_install_update, name='install_update_{}'.format(update.id),
                   args=('/var/ngfw/{brand}.v{ver}.tar.xz'.format(brand=BRAND, ver=update.version),
                         self.request.user.username,
                         get_client_ip(self.request),))

        return Response('Update install starting, This can take several hours')

    def import_update_server_public_key(self):
        if 'test' in sys.argv:
            pass

        token = self.authenticate()
        req = requests.Session()
        req.mount('https://', TLSAdapter())
        response = req.get(
            '{}/api/public_key'.format(self.get_update_server_address()),
            headers={'authorization': 'Token {}'.format(token)},
            verify=False)

        with open('/tmp/update-server-public.key', 'w') as f:
            f.write(response.content.decode())

        s, o = command_runner('gpg --import /tmp/update-server-public.key')
        if not s:
            raise serializers.ValidationError({
                'update_error': 'something went wrong ensure your system time is correct'})

    def query_update_server_for_new_version(self):
        if self.test_param:
            if self.test_param == '400':
                response = MockResponse()
                response.status_code = 400
                return response

            if self.test_param == '200':
                response = MockResponse()
                response.status_code = 200
                response.encoding = 'utf-8'
                response._content = json.dumps(
                    {
                        'description': '...',
                        'new_version': '1.0.0.2',
                        'id': 1
                    }).encode()
                return response

        s, current_version = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
            os.path.join(BACKUP_DIR, 'currentversion.yml'))
        )

        token = self.authenticate()

        try:
            # AFTA: we should use tlsv1_1 or tlsv1_2 => ignore tlsv1_0 => so we should use this adaptor
            req = requests.Session()
            req.mount('https://', TLSAdapter())
            response = req.get(
                self.get_update_server_address() + '/api/updates?previous_version=' + current_version,
                headers={'authorization': 'Token {}'.format(token)},
                verify=False)

        except requests.ConnectionError:
            response = MockResponse()
            response.status_code = 400
            return response

        return response

    def download_update(self, update):
        try:

            update.status = 'downloading'
            update.save()

            if self.test_param:
                response = MockResponse()
                response.status_code = 200

                update.status = 'downloaded'
                update.save()

                return response

            token = self.authenticate()
            req = requests.Session()
            req.mount('https://', TLSAdapter())
            response = req.get(
                '{}/api/updates/{}/file'.format(self.get_update_server_address(), update.server_id),
                headers={'authorization': 'Token {}'.format(token)},
                verify=False
            )

            if response.status_code == status.HTTP_200_OK:
                sudo_runner('chown -R ngfw:ngfw /var/ngfw')
                with open('/var/ngfw/{brand}.v{ver}.tar.xz.enc.gpg'.format(brand=BRAND, ver=update.version), 'wb') as f:
                    f.write(response.content)

                update.status = 'downloaded'
                update.save()

            else:

                update.status = 'failed'
                update.save()
        except Update.DoesNotExist:
            raise serializers.ValidationError({
                'update_error': 'Looks like you have an unstable network at the moment, please try again when network stabilizes'})

    def get_update_server_address(self):
        try:

            address = UpdateConfig.objects.get().update_server

            protocol = 'http' if '127.0.0.1' in address else 'https'
            return '{}://{}'.format(protocol, address)

        except UpdateConfig.DoesNotExist:
            raise serializers.ValidationError('No update server defined.')

    def check_thread(self, test):
        self.test_param = self.request.query_params.get('test')
        response = self.query_update_server_for_new_version()
        if response.status_code == status.HTTP_200_OK:
            if not Update.objects.filter(version=response.json()['new_version']):
                Update.objects.create(
                    version=response.json()['new_version'],
                    description=response.json()['description'],
                    server_id=response.json()['id']
                )
        # Remove any available updates if can't connect to update server or the return code is not 200
        else:
            try:
                update = Update.objects.get(status='available')
                update.delete()
            except Update.MultipleObjectsReturned:
                Update.objects.filter(status='available').delete()
            except Update.DoesNotExist:
                return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(status=status.HTTP_204_NO_CONTENT)

    def authenticate(self):
        try:
            data = {'username': 'client', 'password': '8C#2st5C#3PTRC-tGSZWHG-n7dm-ZRw5Y&QMa%#Y=@8fyX@G97n9wRUYCktyMTB'}
            # ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)

            req = requests.Session()
            req.mount('https://', TLSAdapter())
            response = req.post(self.get_update_server_address() + '/api-token-auth/', data=data, verify=False)

            return response.json()['token']

        except:

            return Response(status=status.HTTP_204_NO_CONTENT)

    def download_key(self, update):

        token_number = self.get_token_number()

        token = self.authenticate()
        req = requests.Session()
        req.mount('https://', TLSAdapter())
        response = req.get(
            '{0}/api/updates/{1}/key?token_number={2}'.format(self.get_update_server_address(), update.server_id,
                                                              token_number),
            headers={'authorization': 'Token {}'.format(token)},
            verify=False
        )

        if response.status_code == status.HTTP_200_OK:
            sudo_runner('chown -R ngfw:ngfw /var/ngfw')
            with open('/var/ngfw/{brand}.v{ver}.tar.xz.key.enc'.format(brand=BRAND, ver=update.version), 'wb') as f:
                f.write(response.content)
            s, o = sudo_runner(
                "openssl rsautl -decrypt -inkey /etc/ssh/ssh_host_rsa_key -in  /var/ngfw/{brand}.v{ver}.tar.xz.key.enc -out /var/ngfw/{brand}.v{ver}.tar.xz.key".format(
                    brand=BRAND, ver=update.version))

            if not s:
                update.status = 'failed'
                update.save()
                raise serializers.ValidationError(
                    {
                        'update_error': 'Looks like the server is taking too long to respond, please try again after sometime  (0x56)'})


        else:

            update.status = 'failed'
            update.save()

    def get_token_number(self):
        try:

            token_number_path = '/var/ngfw/system_info.txt'
            with open(token_number_path, 'r') as temp:
                system_info = temp.read().splitlines()
                token_number = system_info[0]

            return token_number

        except:
            raise serializers.ValidationError({
                'update_error': 'something went wrong (0x6E)'})
