import ipaddress
import os
import re
from copy import deepcopy
from threading import Thread
from time import sleep

import jsonschema
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.db.models import Q
from django.utils.translation import gettext as _
from fqdn import FQDN
from netaddr import IPAddress
from netaddr import IPNetwork
from rest_framework import serializers

from api.licence import INTERFACE_MAX_VIRTUAL_IP
from api.settings import BACKUP_DIR, POLICY_BACK_POSTFIX, IS_TEST
from auth_app.utils import get_client_ip
from config_app.models import Interface, StaticRoute, DHCPServerConfig, Backup, \
    NTPConfig, UpdateConfig, LogServer, Setting, DNSRecord, DNSConfig, SystemService, Update, \
    Snmp, HighAvailability
from config_app.utils import static_route_error_message, create_static_route_cmd, delete_static_route_cmd, \
    check_static_route_existence, dns_record_config, dns_configuration, config_narin_access_ports, \
    config_ntp_server, set_rsyslog_server, remove_rsyslog_server, generate_ssh_banner, open_port_in_iptables, \
    change_or_add_key_to_content, set_snmpv2, set_snmpv3, remove_snmpv2_config, remove_snmpv3_config, \
    set_DHCP_configuration, set_Bridge_configuration, remove_bridge_interface, get_peer_hostname, \
    set_Vlan_configuration, remove_Vlan_interface, get_peer2_interface_list, \
    get_peer2_version, get_sorted_interface_name_list, get_peer1_interface_name_list, \
    peer2_is_slave_static_ip, get_related_interface_name_of_peer2, set_HA_configuration, ha_read_status, \
    this_system_is_master, check_use_bridge, check_use_vlan
from firewall_app.models import Policy
from firewall_input_app.models import Source, InputFirewall
from firewall_input_app.utils import apply_rule
from parser_utils.mod_resource.utils import get_interface_real_data, get_all_interface_real_data, \
    get_interface_link_status
from parser_utils.mod_setting.utils import get_primary_default_gateway_interface_name, convert_to_cidr, \
    config_network_interface
from pki_app.models import PKI
from qos_utils.utils import redirect_lan_traffic_to_ifb_filter, delete_redirect_lan_traffic_to_ifb_filter
from report_app.models import Notification
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner, sudo_file_writer, sudo_pam_authenticate, sudo_file_reader
from root_runner.utils import command_runner, file_writer
from utils.config_files import SSH_CONFIG_FILE, RSYSLOG_CONFIG_FILE, FAIL_2_BAN_CONFIG_FILE, ISSUE_NET_FILE, ISSUE_FILE, \
    HOSTS_FILE, IPSEC_CONF_FILE, IPSEC_SECRETS_FILE, GRE_CONFIGS_PATH, IPIP_CONFIGS_PATH, VTUND_CONFIGS_PATH, \
    DNSMASQ_CONFIG_FILE, SSL_CERT_RSYSLOG_CA_FILE
from utils.log import log
from utils.serializers import SingleIPSerializer, IPMaskSerializer, IPIntegerMaskSerializer, MaskSerializer, \
    IntegerMaskSerializer, get_diff
from utils.utils import run_thread, print_if_debug
from utils.version import get_version


class HighAvailabilityChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = HighAvailability
        fields = '__all__'


class HighAvailabilityRealSerializer(serializers.ModelSerializer):
    active_node = serializers.SerializerMethodField()
    offline_node = serializers.SerializerMethodField()
    alive_node_list = serializers.SerializerMethodField()
    # current_dc = serializers.SerializerMethodField()
    node_info_list = serializers.SerializerMethodField()
    pcs_status = serializers.SerializerMethodField()
    is_master = serializers.SerializerMethodField()

    real_data = dict()

    class Meta:
        model = HighAvailability
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        self.real_data = ha_read_status()
        super(HighAvailabilityRealSerializer, self).__init__(*args, **kwargs)

    def get_active_node(self, ha):
        try:
            return self.real_data['active_node']
        except:
            return None

    def get_offline_node(self, ha):
        try:
            return self.real_data['offline_node']
        except:
            return None

    def get_alive_node_list(self, ha):
        try:
            return self.real_data['alive_node_list']
        except:
            return None

    # def get_current_dc(self, ha):
    #     try:
    #         return self.real_data['current_dc']
    #     except:
    #         return None

    def get_node_info_list(self, ha):
        try:
            return self.real_data['node_info_list']
        except:
            return None

    def get_pcs_status(self, ha):
        try:
            return self.real_data['pcs_status']
        except:
            return None

    def get_is_master(self, ha):
        try:
            return this_system_is_master(self.real_data)
        except:
            return None


class HighAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HighAvailability
        fields = '__all__'

    def validate(self, data):
        if HighAvailability.objects.filter(status='pending'):
            raise serializers.ValidationError(
                _('HighAvailability configuration is not available right now, wait a moment!'))

        if not self.instance and HighAvailability.objects.all():
            raise serializers.ValidationError(_('HighAvailability already configured.'))
        is_in_network = False
        if not isinstance(data['cluster_address_list'], list):
            raise serializers.ValidationError(_('This field must be list'))
        interface_list = Interface.objects.all()
        interfaces_ip_list = []
        interfaces_name_list = []
        peer1_related_interface_name = None
        peer1_related_interface_mac = None
        for interface in interface_list:
            interfaces_name_list.append(interface.name)
            for ip in interface.ip_list:
                interfaces_ip_list.append(ip['ip'])
                if interface.ip_list and data["peer1_address"] == interface.ip_list[0]['ip']:
                    peer1_related_interface_name = interface.name
                    peer1_related_interface_mac = interface.mac

        fw_input_interface = None
        if peer1_related_interface_name:
            fw_input_interface = peer1_related_interface_name
        else:
            # this condition happens when the master(s1) system switches on slave(s2) and we want update HA instance on slave(s2)
            if hasattr(self, 'instance') and self.instance:
                fw_input_interface = self.instance.configured_peer_interface_mac.split('#')[0]
            try:
                if fw_input_interface and \
                        not InputFirewall.objects.filter(
                            Q(service_list__contains=['cli'], source__src_interface_list__isnull=True,
                              source__src_network_list__isnull=True, is_enabled=True) |
                            Q(service_list__contains=['cli'],
                              source__src_interface_list__name__contains=fw_input_interface,
                              source__src_network_list__isnull=True, is_enabled=True) |
                            Q(service_list__contains=['cli'],
                              source__src_interface_list__name__contains=fw_input_interface,
                              source__src_network_list__value_list=[data["peer2_address"]], is_enabled=True)):
                    raise serializers.ValidationError(
                        _('For configuring High availability, a firewall input rule for CLI is needed for both nodes.'
                          '(with no interface and Allow ip or at least with related interface and Node2 ip)'))
            except:
                pass
        if data['peer1_address'] not in interfaces_ip_list:
            raise serializers.ValidationError(
                _('The address that entered as Node1 IP address should be static IP of this system'))

        if data['peer1_address'] == data["peer2_address"]:
            raise serializers.ValidationError(_('Node1 IP address cannot be the same as Node2 IP address.'))

        for item in data['cluster_address_list']:
            try:
                nic = item.get("nic")
                cidr = item.get("cidr")
                if not nic or not cidr:
                    raise Exception
            except:
                raise serializers.ValidationError('every cluster address item should have interface and cidr.')
            if nic not in interfaces_name_list:
                raise serializers.ValidationError(_('interface {} in cluster address list does not exist.'.format(nic)))
            if "/" not in cidr:
                raise serializers.ValidationError(
                    _('Clausters should have a positive number less than 31 as their Subnetmask'))
            ip_mask_serializer = IPIntegerMaskSerializer(
                data={'ip': re.match(r'(.*?)/(.*)', cidr).group(1), 'mask': re.match(r'(.*?)/(.*)', cidr).group(2)})
            match = re.match(r'(.*?)/(.*)', cidr)
            if match.group(2) == "32" or match.group(2) == "31":
                raise serializers.ValidationError(
                    _('Clausters should have a positive number less than 31 as their Subnetmask'))
            if match.group(1) in interfaces_ip_list:
                raise serializers.ValidationError('cluster ips should not use as interfaces ip. {} is used as'
                                                  ' an interface ip.'.format(match.group(1)))
            if match.group(1).endswith('.0'):
                raise serializers.ValidationError(
                    _('Clausters ip can not be a network address, correct {} cluster ip.'.format(cidr)))
            if not ip_mask_serializer.is_valid():
                raise serializers.ValidationError({'cluster_address_list': 'Enter a valid IPv4 CIDR'})
            for interface in interface_list:
                for ip_interface in interface.ip_list:
                    system_ip = str(ip_interface["ip"]) + "/" + str(IPAddress(ip_interface["mask"]).netmask_bits())
                    if IPNetwork(cidr) in IPNetwork(system_ip):
                        is_in_network = True
                        break
            if not is_in_network:
                raise serializers.ValidationError(
                    _('cluster address, Node1 and Node2 addresses are not in a network range'))

        if IS_TEST:
            return data
        # we should avoid ssh asking permissions (yes/no question)
        command_runner('echo " StrictHostKeyChecking no" >> ~/.ssh/config')
        # master and slave hostnames should be different, otherwise HA service could not work properly. in addition to
        # this validation, we wrote a validation for hostname, that don't let user to change its hostname while it has
        # HA configuration.
        try:
            ssh_port = Setting.objects.get(key='ssh-port').data['value']
            https_port = Setting.objects.get(key='https-port').data['value']
        except:
            raise serializers.ValidationError(
                _('SSH or HTTPS port not set, configure this setting in system setting section.'))

        status, master_hostname = command_runner('hostname')
        slave_hostname = get_peer_hostname(data['peer2_address'], ssh_port, https_port)
        if not slave_hostname and data['is_enabled']:
            raise serializers.ValidationError(
                _('Node2 is not available, check its ip address, https-port and ssh-port. https-port and ssh-port '
                  'should be same in both nodes.'
                  ' Also for configuring High availability, a firewall input rule for CLI is needed.'
                  '(with no interface and Allow ip or at least with related interface and Node2 ip)'))
        if master_hostname == slave_hostname:
            raise serializers.ValidationError(_('Node1 and Node2 hostnames cannot be same, change one of them.'))

        slave_interfaces = get_peer2_interface_list(data['peer2_address'], ssh_port, https_port)
        # master and slave network interfaces names should be same, unless all the sync process will be wrong or will fail
        slave_interface_name_list = get_sorted_interface_name_list(slave_interfaces)
        master_interface_name_list = get_peer1_interface_name_list()
        if not master_interface_name_list or not slave_interface_name_list or master_interface_name_list != slave_interface_name_list:
            raise serializers.ValidationError(_('Node1 and Node2 interfaces, VLANs and bridges names should be same.'))
        if not peer2_is_slave_static_ip(data["peer2_address"], slave_interfaces):
            raise serializers.ValidationError(
                _('The address that entered as Node2 IP address should be static IP of the Node2 system'))
        peer2_related_interface_name = get_related_interface_name_of_peer2(data["peer2_address"], slave_interfaces)
        if peer1_related_interface_name != peer2_related_interface_name:
            raise serializers.ValidationError(
                _(
                    'The address that entered as Node2 IP address should be static IP of interface \"{}\" of Node2 system'.format(
                        peer1_related_interface_name)))

        # master and slave versions should be same, unless the sync process may be fail, specially if database have changes
        master_version = get_version()
        slave_version = get_peer2_version(data['peer2_address'], ssh_port, https_port)
        if not master_version or not slave_version or master_version != slave_version:
            raise serializers.ValidationError(_('Node1 and Node2 versions should be same.'))
        if HighAvailability.objects.filter(is_enabled=True, status='succeeded'):
            real_ha_status = ha_read_status()
            try:
                active_node = real_ha_status['active_node']
            except:
                active_node = ""
            if not this_system_is_master(real_ha_status):
                if active_node:
                    raise serializers.ValidationError(_('Update HighAvailability configuration is only possible on '
                                                        'active node or when active node does not exist.'))
        data['configured_peer_interface_mac'] = '{}#{}'.format(peer1_related_interface_name,
                                                               peer1_related_interface_mac)
        return data

    def create(self, validated_data):
        with transaction.atomic():
            Notification.objects.filter(source='HA').delete()
            instance = super(HighAvailabilitySerializer, self).create(validated_data)
            instance.last_operation = 'add'
            instance.status = 'pending'
            instance.save()
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        serializer = HighAvailabilityChangeSerializer()
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }

        run_thread(target=set_HA_configuration, name='set_HA_config',
                   args=(instance, 'add', None, request_username, request, details))

        return instance

    def update(self, instance, validated_data):
        old_instance = deepcopy(instance)
        changes = get_diff(self.instance, HighAvailabilityChangeSerializer, self.initial_data,
                           ['last_operation', 'status'])
        with transaction.atomic():
            Notification.objects.filter(source='HA').delete()
            instance = super(HighAvailabilitySerializer, self).update(instance, validated_data)
            instance.last_operation = 'update'
            instance.status = 'pending'
            instance.save()
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        old_instance = old_instance.__dict__
        old_instance.pop('_state')
        old_instance.pop('_django_version')

        run_thread(target=set_HA_configuration, name='set_HA_config',
                   args=(instance, 'update', old_instance, request_username, request, changes))

        return instance


class SnmpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Snmp
        fields = "__all__"

    def validate_snmp_type(self, value):
        if not value:
            raise serializers.ValidationError(_('This field is required.'))
        return value

    def validate_community_name(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v2" and not value:
            raise serializers.ValidationError(_('This filed is required.'))
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v2" and len(value) < 8:
            raise serializers.ValidationError(_('More than 8 character is required.'))

        return value

    def validate_allow_network(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v2" and not value:
            raise serializers.ValidationError(_('This filed is required.'))
        return value

    def validate_user_name(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v3" and not value:
            raise serializers.ValidationError(_('This filed is required.'))
        return value

    def validate_private_password(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v3" and self.initial_data[
            'security_level'] == 'priv':
            if not value:
                raise serializers.ValidationError(_('This filed is required.'))
            elif len(value) < 8:
                raise serializers.ValidationError(_('More than 8 character is required.'))

        return value

    def validate_security_level(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v3" and not value:
            raise serializers.ValidationError(_('This filed is required.'))
        return value

    def validate_private_algorithm(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v3" and self.initial_data[
            'security_level'] == 'priv' and not value:
            raise serializers.ValidationError(_('This filed is required.'))
        return value

    def validate_authentication_algorithm(self, value):
        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v3" and (
                self.initial_data['security_level'] == 'priv' or self.initial_data[
            'security_level'] == "auth") and not value:
            raise serializers.ValidationError(_('This filed is required.'))

        return value

    def validate_authentication_password(self, value):

        if 'snmp_type' in self.initial_data and self.initial_data['snmp_type'] == "v3" and (
                self.initial_data['security_level'] == 'priv' or self.initial_data['security_level'] == 'auth'):
            if not value:
                raise serializers.ValidationError(_('This filed is required.'))
            elif len(value) < 8:
                raise serializers.ValidationError(_('More than 8 character is required.'))
        return value

    def create(self, validated_data):
        if Snmp.objects.all().count() > 2:
            raise serializers.ValidationError({"non_field_errors": "The number of Snmp Agent should not exceed 3"})
        instance = super().create(validated_data)
        details = {
            "items": {
                "id": instance.id
            }
        }
        instance.last_operation = "add"
        instance.status = "pending"
        operation = 'add'
        request_username = None
        request = None

        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        if instance.is_enabled:
            if not InputFirewall.objects.filter(port__exact='161'):
                try:
                    InputFirewall.objects.create(
                        name='snmp',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        protocol='udp',
                        port='161',
                        service_list='{snmp}')
                except:
                    pass

                apply_rule(None, None)

            if instance.snmp_type == "v2":

                output_status = set_snmpv2(instance, request_username, request, details, operation)
                if not output_status:
                    instance.status = "failed"
                    instance.save()
                    raise serializers.ValidationError(({"non_field_errors": "Failed to create SNMPv2"}))

                else:
                    instance.status = "succeeded"
                    instance.save()

            else:
                output_status = set_snmpv3(instance, request_username, request, details, operation)
                if not output_status:
                    instance.status = "failed"
                    instance.save()
                    raise serializers.ValidationError(({"non_field_errors": "Failed to create SNMPv3"}))

                else:
                    instance.status = "succeeded"
                    instance.save()
        else:
            instance.status = 'disabled'
            instance.save()
        return instance

    def update(self, instance, validated_data):

        changes = get_diff(self.instance, SnmpSerializer, self.initial_data, ['last_operation', 'status'])
        opration = 'update'
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username

            request = self.context['request']

        # Remove previeus notifications for this snmp's id
        Notification.objects.filter(source='snmp', item__id=instance.id).delete()
        if instance.snmp_type == "v2":
            output_status = remove_snmpv2_config(instance, request_username, request, changes, opration)
            if not output_status:
                instance.status = "failed"
                instance.save()
                raise serializers.ValidationError(({"non_field_errors": "Failed to create SNMPv2"}))

            else:
                instance.status = "succeeded"
                instance.save()

        else:
            output_status = remove_snmpv3_config(instance, request_username, request, changes, opration)
            if not output_status:
                instance.status = "failed"
                instance.save()
                raise serializers.ValidationError(({"non_field_errors": "Failed to create SNMPv3"}))

            else:
                instance.status = "succeeded"
                instance.save()

        instance = super().update(instance, validated_data)
        instance.last_operation = 'update'
        if instance.is_enabled:
            if not InputFirewall.objects.filter(port__exact='161'):
                try:
                    InputFirewall.objects.create(
                        name='snmp',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        protocol='udp',
                        port='161',
                        service_list='{snmp}')
                except:
                    pass

                apply_rule(None, None)

            instance.status = 'pending'

            if self.initial_data['snmp_type'] == "v2":
                output_status = set_snmpv2(instance, request_username, request, changes, opration)
                if not output_status:
                    instance.status = "failed"
                    instance.save()
                    raise serializers.ValidationError(({"non_field_errors": "Failed to create SNMPv2"}))
                else:
                    instance.status = "succeeded"
                    instance.save()

            elif self.initial_data['snmp_type'] == "v3":
                output_status = set_snmpv3(instance, request_username, request, changes, opration)
                if not output_status:
                    instance.status = "failed"
                    instance.save()
                    raise serializers.ValidationError(({"non_field_errors": "Failed to create SNMPv3"}))

                else:
                    instance.status = "succeeded"
                    instance.save()
        else:
            instance.status = 'disabled'
            instance.save()

            if not Snmp.objects.filter(is_enabled=True):
                InputFirewall.objects.filter(port__exact='161').delete()
                apply_rule(None, None)

        return instance


class InterfaceNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Interface
        fields = ('__all__')


class InterfaceChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Interface
        fields = '__all__'


class InterfaceSerializer(serializers.ModelSerializer):
    error = serializers.SerializerMethodField()
    is_used_in_dhcp = serializers.SerializerMethodField()
    is_used_in_ha = serializers.SerializerMethodField()

    def get_is_used_in_ha(self, interface):
        if HighAvailability.objects.filter(
                configured_peer_interface_mac='{}#{}'.format(interface.name, interface.mac)).exists():
            return True
        return False

    def get_is_used_in_dhcp(self, interface):
        if DHCPServerConfig.objects.filter(interface=interface.name).exists():
            return True
        return False

    def get_error(self, interface):
        if interface.status == 'failed':
            notification = Notification.objects.filter(source='interface', item__id=interface.name)
            if notification.exists():
                return notification.values('message', 'severity', 'datetime')[0]
        return None

    class Meta:
        model = Interface
        fields = '__all__'
        # read_only_fields = ('name',)

    # def validate_is_default_gateway(self, value):
    #     if value is True:
    #         interfaces = Interface.objects.all()
    #         for interface in interfaces:
    #             if interface.name != self.initial_data['name'] and interface.is_default_gateway:
    #                 raise serializers.ValidationError("Just one interface can be marked as default gateway.")
    #     return value

    def validate_data(self, value):
        if value:
            if not isinstance(value, list):
                raise serializers.ValidationError(_('This field must be list'))

            if self.initial_data['mode'] == 'bridge':

                if not value[0]['interface']:
                    raise serializers.ValidationError('at least one interface required for bridge interface ')

                instance = Interface.objects.all()

                for interface in instance:
                    if self.instance:
                        if interface.mode != 'interface' and interface.name != self.instance.name:

                            for x in interface.data[0]['interface']:

                                for y in value[0]['interface']:

                                    if x == y:
                                        raise serializers.ValidationError(
                                            'interface {0} is used in {1} {2}'.format(x, interface.mode,
                                                                                      interface.name))
                    else:
                        if interface.mode != 'interface':

                            for x in interface.data[0]['interface']:

                                for y in value[0]['interface']:

                                    if x == y:
                                        raise serializers.ValidationError(
                                            'interface {0} is used in {1} {2}'.format(x, interface.mode,
                                                                                      interface.name))
            if self.initial_data['mode'] == 'vlan':

                if not value[0]['interface']:
                    raise serializers.ValidationError({'interface': 'one interface required for VLAN interface '})

                if 'vlan_id' not in value[0]:
                    raise serializers.ValidationError(
                        {'vlan_id': 'value list cannot be empty '})
                if not value[0]['vlan_id']:
                    raise serializers.ValidationError(
                        {'vlan_id': 'value  cannot be empty '})

                if not value[0]['vlan_id'].isdigit():
                    raise serializers.ValidationError(
                        {'vlan_id': 'value  should be integer '})

                vlan_id = value[0]['vlan_id']
                if int(vlan_id) < 1 or int(vlan_id) > 4094:
                    raise serializers.ValidationError(
                        {'vlan_id': 'VLAN ID should be a positive number, between 1 and 4094 '})

                name = '{}.{}'.format(self.initial_data['data'][0]['interface'][0],
                                      self.initial_data['data'][0]['vlan_id'])
                instance = Interface.objects.all()

                for interface in instance:
                    if interface.mode == 'bridge':
                        for x in interface.data[0]['interface']:
                            if x == self.initial_data['data'][0]['interface'][0]:
                                raise serializers.ValidationError(
                                    {'non_field_errors': 'interface {} is used in bridge {}'.format(x, interface.name)})

                    if self.instance:
                        if interface.name != self.instance.name:
                            if interface.name == name:
                                raise serializers.ValidationError(
                                    {
                                        'non_field_errors': 'Vlan interface with this vlan id and interface already exists'})
                    else:
                        if interface.name == name:
                            raise serializers.ValidationError(
                                {
                                    'non_field_errors': 'Vlan interface with this vlan id and interface already exists'})

                if self.instance:

                    if not self.initial_data['data'][0]['interface'][0] == self.instance.data[0]['interface'][0] or not \
                            self.initial_data['data'][0]['vlan_id'] == self.instance.data[0]['vlan_id']:
                        raise serializers.ValidationError(
                            {
                                'non_field_errors': "you can't modify VLAN ID or Interface"
                            }
                        )

        return value

    def validate_mtu(self, value):
        if value:
            if value > 1500 or value < 1:
                raise serializers.ValidationError(
                    'This field should be a positive number, between 1 and 1500')
        return value

    def validate_pppoe_username(self, value):
        if 'link_type' in self.initial_data and self.initial_data['link_type'] == 'PPPOE' and not value:
            raise serializers.ValidationError(_('This field is required.'))
        return value

    def validate_pppoe_password(self, value):
        if 'link_type' in self.initial_data and self.initial_data['link_type'] == 'PPPOE' and not value:
            raise serializers.ValidationError(_('This field is required.'))
        return value

    def validate_gateway(self, value):
        if 'is_dhcp_enabled' in self.initial_data and self.initial_data['is_dhcp_enabled']:
            return None

        if 'is_default_gateway' in self.initial_data and self.initial_data['is_default_gateway'] and not value:
            raise serializers.ValidationError('This field is required.')

        return value

    def validate_name(self, value):
        if self.instance:
            if self.instance.mode == 'bridge':
                if not self.initial_data['name'] == self.instance.name:
                    raise serializers.ValidationError(

                        "you can't modify Bridge name")
        return value

    def validate_type(self, value):
        if not value:
            raise serializers.ValidationError(_('This field is required'))
        return value

    def validat_download_bandwidth(self, value):
        if value < 0 or value > 4294967:
            raise serializers.ValidationError(_('This field should be a positive number, less than 4294967'))
        return value

    def validat_upload_bandwidth(self, value):
        if value < 0 or value > 4294967:
            raise serializers.ValidationError(_('This field should be a positive number, less than 4294967'))
        return value

    def validate_ip_list(self, value):

        if not isinstance(value, list):
            raise serializers.ValidationError(_('This field must be list'))
        if len(value) > INTERFACE_MAX_VIRTUAL_IP:
            raise serializers.ValidationError(
                _('Number of virtual ip exceeded, {} entries are allowed'.format(INTERFACE_MAX_VIRTUAL_IP)))
        value = list({k['ip']: k for k in value}.values())
        value = sorted(value, key=lambda k: k['ip'])

        if 'is_dhcp_enabled' in self.initial_data:
            if self.initial_data['is_dhcp_enabled']:
                return []

        if not value:
            raise serializers.ValidationError(_('This field is required.'))

        if 'is_dhcp_enabled' in self.initial_data and not self.initial_data[
            'is_dhcp_enabled'] or 'mode' in self.initial_data:
            schema_with_string_mask = {
                'type': 'object',
                'properties': {
                    'ip': {'type': 'string'},
                    'mask': {'type': 'string'}
                },
                "additionalProperties": False,
                "required": ["ip", "mask"]
            }
            schema_with_int_mask = {
                'type': 'object',
                'properties': {
                    'ip': {'type': 'string'},
                    'mask': {'type': 'integer'}
                },
                "additionalProperties": False,
                "required": ["ip", "mask"]
            }

            for ip_mask in value:
                try:
                    jsonschema.validate(ip_mask, schema_with_string_mask)
                except jsonschema.exceptions.ValidationError:
                    try:
                        jsonschema.validate(ip_mask, schema_with_int_mask)
                    except jsonschema.exceptions.ValidationError:
                        raise serializers.ValidationError('invalid json format for ip_list')

                if '.' in ip_mask['mask']:
                    ip_mask_serializer = IPMaskSerializer(
                        data={'ip': ip_mask['ip'], 'mask': ip_mask['mask']})
                else:
                    ip_mask_serializer = IPIntegerMaskSerializer(
                        data={'ip': ip_mask['ip'], 'mask': ip_mask['mask']})

                if not ip_mask_serializer.is_valid():
                    raise serializers.ValidationError(ip_mask_serializer.errors)

                masklist = ['255.255.255.255', '255.255.255.254', '255.255.255.252', '255.255.255.248',
                            '255.255.255.240',
                            '255.255.255.224', '255.255.255.192', '255.255.255.128', '255.255.255.0', '255.255.254.0',
                            '255.255.252.0', '255.255.248.0', '255.255.240.0', '255.255.224.0', '255.255.192.0',
                            '255.255.128.0', '255.255.0.0', '255.254.0.0', '255.252.0.0', '255.248.0.0', '255.240.0.0',
                            '255.224.0.0', '255.192.0.0', '255.128.0.0', '255.0.0.0', '254.0.0.0', '252.0.0.0',
                            '248.0.0.0',
                            '240.0.0.0', '224.0.0.0', '192.0.0.0', '128.0.0.0']

                if ip_mask['mask'] not in masklist:
                    raise serializers.ValidationError('invalid mask please choose from a list')

        return value

    def validate(self, data):
        if self.instance and self.instance.pk:
            if HighAvailability.objects.filter(is_enabled=True):
                ha_config = HighAvailability.objects.get()
                ha_interface = ha_config.configured_peer_interface_mac
                if self.instance.name == ha_interface.split('#')[0]:
                    raise serializers.ValidationError(
                        {'non_field_errors': 'HighAvailability configured on this interface ip,'
                                             ' disable HighAvailability configuration first to update interface.'})

            if 'type' in data and data.get('type') == 'LAN':
                if ('download_bandwidth' in data and data.get('download_bandwidth')) or \
                        ('upload_bandwidth' in data and data.get('upload_bandwidth')):
                    raise serializers.ValidationError({
                        'non_field_errors': 'Configuring interface bandwidth is available for WAN interfaces currently'})
            if ('download_bandwidth' in data and data.get('download_bandwidth')) and \
                    ('upload_bandwidth' not in data or not data.get('upload_bandwidth')):
                raise serializers.ValidationError({'non_field_errors': 'Upload bandwidth field is not specified'})
            if ('upload_bandwidth' in data and data.get('upload_bandwidth')) and \
                    ('download_bandwidth' not in data or not data.get('download_bandwidth')):
                raise serializers.ValidationError({'non_field_errors': 'Download bandwidth field is not specified'})

            if Policy.objects.filter(qos_id__isnull=False, is_enabled=True,
                                     source_destination__dst_interface_list__name__contains=self.instance.name) and \
                    ('download_bandwidth' not in data or not data.get('download_bandwidth')
                     or data.get('download_bandwidth') <= 0 or 'upload_bandwidth' not in data
                     or not data.get('upload_bandwidth') or data.get('upload_bandwidth') <= 0):
                raise serializers.ValidationError(
                    {'non_field_errors': 'Bandwidth fields cannot be free because Interface has been used in policies'})

            # Avoid changing DHCP status and interface type in case of interface has been used in captive portal
            # captive_portal_config = CaptivePortalConfig.objects.all()
            # if captive_portal_config and captive_portal_config[0].is_enabled:
            #
            #     captive_portal_lan_interface = captive_portal_config[0].lan_interface
            #     if captive_portal_lan_interface and self.instance == captive_portal_lan_interface:
            #         if 'is_dhcp_enabled' in data and data.get('is_dhcp_enabled'):
            #             raise serializers.ValidationError(
            #                 _('DHCP cannot be enabled when captive portal is enabled')
            #             )
            #         if 'type' in data and self.instance.type != data.get('type'):
            #             raise serializers.ValidationError(
            #                 _('Interface type cannot be changed because it is used in captive portal')
            #             )
            #
            #         if "ip_list" not in data or not data['ip_list']:
            #             raise serializers.ValidationError(
            #                 {'ip_list': [_('IP must set for interface')]})
            #
            #     captive_portal_wan_interfaces = captive_portal_config[0].wan_interfaces.all()
            #     if captive_portal_wan_interfaces:
            #         for interface in captive_portal_wan_interfaces:
            #             if self.instance == interface:
            #                 if 'type' in data and self.instance.type != data.get('type'):
            #                     raise serializers.ValidationError(
            #                         _('Interface type cannot be changed because it is used in captive portal')
            #                     )

            # CHECK FOR WAN INTERFACES
            # multi_wan_configs = multi_WAN_links.objects.all()
            # for item in multi_wan_configs:
            #     if item.enabled and obj.name == item.interface.name:
            #         self.fields['type'].widget = forms.TextInput(attrs={'readonly': 'readonly'})

            # if 'type' in cleaned_data.keys() and cleaned_data['type'] == "WAN" and \
            #                 'DHCP_enabled' in cleaned_data.keys() and not cleaned_data['DHCP_enabled']:
            #     if self.instance.pk:
            #         multiwan_configs_on_this_interface = self.instance.multi_wan_interface.all()
            #         if multiwan_configs_on_this_interface:
            #             if 'GW_IP' not in cleaned_data.keys() or not cleaned_data['GW_IP']:
            #                 raise ValidationError(
            #                     {'GW_IP': [_('This WAN interface is set to Traffic load balancing (this field is necessary)')
        return data

    def create(self, validated_data):
        with transaction.atomic():

            instance = super(InterfaceSerializer, self).create(validated_data)

            instance.last_operation = 'add'
            instance.status = 'pending'
            instance.save()
            request_username = None
            request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        if instance.mode == 'bridge':
            run_thread(target=set_Bridge_configuration, name='set_Bridge_config',
                       args=(instance, 'add', request_username, request))
        if instance.mode == 'vlan':
            run_thread(target=set_Vlan_configuration, name='set_Vlan_config',
                       args=(instance, 'add', request_username, request))
        return instance

    def update(self, instance, validated_data):
        alias = self.validated_data.get('alias', None)
        if not alias:
            self.validated_data['alias'] = self.instance.name

        changes = get_diff(instance, InterfaceChangeSerializer, self.initial_data, ['last_operation', 'status'])

        if instance.mode == 'bridge':

            operation = 'update'
            instance.last_operation = operation
            instance.status = 'pending'
            instance.save()
            request_username = None
            request = None
            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']

            remove_bridge_interface(instance, request_username, request, changes, operation)

            instance = super().update(instance, validated_data)

            run_thread(target=set_Bridge_configuration, name='set_Bridge_config',
                       args=(instance, 'update', request_username, request))

        elif instance.mode == 'vlan':

            operation = 'update'
            instance.last_operation = operation
            instance.status = 'pending'
            instance.save()
            request_username = None
            request = None
            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']

            remove_Vlan_interface(instance, request_username, request, changes, operation)
            sleep(2)
            instance = super().update(instance, validated_data)
            run_thread(target=set_Vlan_configuration, name='set_Bridge_config',
                       args=(instance, 'update', request_username, request))

        else:

            old_default_gateway_interface_list = Interface.objects.filter(is_default_gateway=True)
            old_default_gateway_interaface = None
            if old_default_gateway_interface_list:
                old_default_gateway_interaface = old_default_gateway_interface_list[0]

            if 'is_default_gateway' in validated_data and self.validated_data['is_default_gateway']:
                Interface.objects.filter(is_default_gateway=True) \
                    .exclude(name=self.instance.name) \
                    .update(is_default_gateway=False)

            should_up_ifb_link = False
            if 'download_bandwidth' in validated_data and self.validated_data['download_bandwidth']:
                if not Interface.objects.filter(download_bandwidth__isnull=False):
                    should_up_ifb_link = True
            interface_already_has_qdisc = False
            if instance.upload_bandwidth:
                interface_already_has_qdisc = True

            if 'type' in validated_data and self.validated_data['type'] == 'LAN':
                redirect_lan_traffic_to_ifb_filter(instance.name)
            elif instance.type == 'LAN' and 'type' in validated_data and self.validated_data['type'] == 'WAN':
                delete_redirect_lan_traffic_to_ifb_filter(instance.name)

            instance.__dict__.update(**validated_data)
            instance.last_operation = 'update'
            instance.status = 'pending'
            if instance.upload_bandwidth or instance.download_bandwidth:
                instance.qos_status = 'pending'
            instance.save()
            request_username = None
            request = None
            if 'request' in self.context:
                request_username = self.context['request'].user.username
                request = self.context['request']

            t = Thread(target=config_network_interface,
                       args=(instance, request_username, old_default_gateway_interaface, should_up_ifb_link,
                             interface_already_has_qdisc, request, changes))
            t.start()

            # config_network_interface(instance, request_username)

        return instance

    # data = convert_interface_config_to_json(instance)
    # if instance.name not in get_network_interfaces():
    #     return make_response(400, "Interface %s does not exist." % data['interface'])
    # res_set_interface = config_network_interface(instance)
    #
    # if res_set_interface:
    #     # Update Captive Portal if this interface is assigned to Chilli LAN interafce
    #     chilli_config_data = CaptivePortalConfig.objects.all()
    #     if chilli_config_data:
    #         lan_interface = chilli_config_data[0].lan_interface
    #         if chilli_config_data[0].is_enabled and lan_interface and self.instance.name == lan_interface.name:
    #             data = convert_chilli_config_to_json(chilli_config_data[0])
    #             res_update_chili = send_chilli_config_to_parser(chilli_config_data[0], data, "set")
    #
    # # Update WAN interface for multi-wan configuration
    # # if instance.type == "WAN":
    # #     multi_wan_configs = multi_WAN_links.objects.all()
    # #     for wan_if in multi_wan_configs:
    # #         if wan_if.enabled and wan_if.interface.name == instance.name:
    # #             res = send_multi_wan_config_to_parser(wan_if, "update")
    #
    # # if instance.dns_servers:
    # #     edited_dns_servers_string = ""
    # #     dns_list = instance.dns_servers
    # #     for item in dns_list:
    # #         if re.match('^' + '[\.]'.join(['(\d{1,3})'] * 4) + '$', item):
    # #             applied_dns = DNS_servers.objects.filter(dns_server=item)
    # #             if not applied_dns:
    # #                 DNS_servers.objects.create(dns_server=item)


class InterfaceRealSerializer(serializers.ModelSerializer):
    real_ip_list = serializers.SerializerMethodField()
    real_gateway = serializers.SerializerMethodField()
    real_is_enabled = serializers.SerializerMethodField()
    real_is_dhcp_enabled = serializers.SerializerMethodField()
    real_is_default_gateway = serializers.SerializerMethodField()
    is_link_connected = serializers.SerializerMethodField()
    real_is_bridge = serializers.SerializerMethodField()
    real_is_vlan = serializers.SerializerMethodField()
    is_used_in_ha = serializers.SerializerMethodField()

    real_data = dict()
    many = False

    class Meta:
        model = Interface
        fields = '__all__'

    def __init__(self, obj, *args, **kwargs):
        import time
        start_time = time.time()
        default_gateway_interface_name = get_primary_default_gateway_interface_name()
        bridge_object = Interface.objects.filter(mode='bridge')
        vlan_object = Interface.objects.filter(mode='vlan')
        try:

            if isinstance(obj, list):
                all_interface_information = get_all_interface_real_data()

                self.many = True

                for interface in obj:

                    real_info = all_interface_information['{}_real_data'.format(interface.name)]

                    is_bridge = False
                    is_vlan = False

                    if bridge_object:
                        for bridge in bridge_object:
                            for inter in bridge.data[0]['interface']:
                                if inter == interface.name:
                                    is_bridge = True

                    if vlan_object:
                        for vlan in vlan_object:
                            if vlan.data[0]['interface'][0] == interface.name:
                                is_vlan = True

                    self.real_data[interface.name] = {
                        'real_ip_list': real_info['real_ip_list'],
                        'real_gateway': real_info['real_gateway'],
                        'real_is_enabled': interface.is_enabled if real_info['real_is_enabled'] else False,
                        'real_is_default_gateway': True if default_gateway_interface_name == interface.name else False,
                        'is_link_connected': get_interface_link_status(interface.name),
                        'real_is_dhcp_enabled': interface.is_dhcp_enabled,
                        'real_is_bridge': is_bridge,
                        'real_is_vlan': is_vlan

                    }
            else:
                real_info = get_interface_real_data(interface_name=obj.name)
                is_bridge = False
                is_vlan = False

                if bridge_object:
                    for bridge in bridge_object:
                        for inter in bridge.data[0]['interface']:
                            if inter == obj.name:
                                is_bridge = True

                if vlan_object:
                    for vlan in vlan_object:
                        if vlan.data[0]['interface'][0] == obj.name:
                            is_vlan = True

                self.real_data = {
                    'real_ip_list': real_info['real_ip_list'],
                    'real_gateway': real_info['real_gateway'],
                    'real_is_enabled': obj.is_enabled if real_info['real_is_enabled'] else False,
                    'real_is_default_gateway': True if default_gateway_interface_name == obj.name else False,
                    'is_link_connected': get_interface_link_status(obj.name),
                    'real_is_dhcp_enabled': obj.is_dhcp_enabled,
                    'real_is_bridge': is_bridge,
                    'real_is_vlan': is_vlan

                }
        except Exception as e:
            print_if_debug('problem in showing interface real data: {}'.format(e))
            self.real_data = {
                'real_ip_list': [],
                'real_gateway': None,
                'real_is_enabled': None,
                'real_is_default_gateway': None,
                'is_link_connected': None,
                'real_is_dhcp_enabled': None,
                'real_is_bridge': None,
                'real_is_vlan': None
            }
        super(InterfaceRealSerializer, self).__init__(obj, *args, **kwargs)

    def get_is_used_in_ha(self, interface):
        if HighAvailability.objects.filter(
                configured_peer_interface_mac='{}#{}'.format(interface.name, interface.mac)).exists():
            return True
        return False

    def get_real_ip_list(self, interface):
        try:
            if self.many:
                result = self.real_data[interface.name]['real_ip_list']
            else:
                result = self.real_data['real_ip_list']

            if result and not '' == result[0]:
                result = sorted(result, key=lambda k: k['ip'])
                return result
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_real_gateway(self, interface):
        try:
            if interface.mode == 'interface':
                if self.many:
                    result = self.real_data[interface.name]['real_gateway']
                else:
                    result = self.real_data['real_gateway']

                if result:
                    return result
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_real_is_enabled(self, interface):
        try:

            if self.many:
                return self.real_data[interface.name]['real_is_enabled']

            return self.real_data['real_is_enabled']
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_real_is_dhcp_enabled(self, interface):
        try:
            if interface.mode == 'interface':
                if self.many:
                    result = self.real_data[interface.name]['real_is_dhcp_enabled']
                else:
                    result = self.real_data['real_is_dhcp_enabled']

                return result
                # if get_interface_status(interface.name, use_nmcli=True) != "connected":
                #     print("----------in real dhcp1 is: {} --------".format(time.time() - start_time))
                #     return True
                #
                # real_is_dhcp_enabled = False
                # connection_name = get_interface_active_connection(interface)
                # if not connection_name and has_related_connection(interface.name):
                #     connection_name = "{}_con".format(interface.name)
                # if connection_name and get_interface_method(connection_name) == 'auto':
                #     real_is_dhcp_enabled = True
                #
                # return real_is_dhcp_enabled
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_real_is_default_gateway(self, interface):
        try:
            if interface.mode == 'interface':
                if self.many:
                    return self.real_data[interface.name]['real_is_default_gateway']

                return self.real_data['real_is_default_gateway']
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_is_link_connected(self, interface):
        try:

            if self.many:
                return self.real_data[interface.name]['is_link_connected']

            return self.real_data['is_link_connected']
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_real_is_bridge(self, interface):
        try:
            if interface.mode == 'interface':
                if self.many:
                    return self.real_data[interface.name]['real_is_bridge']

                return self.real_data['real_is_bridge']
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None

    def get_real_is_vlan(self, interface):
        try:
            if interface.mode == 'interface':
                if self.many:
                    return self.real_data[interface.name]['real_is_vlan']

                return self.real_data['real_is_vlan']
        except Exception as e:
            print_if_debug('problem in get interface real data: {}'.format(e))
            return None


class StaticRouteChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaticRoute
        fields = '__all__'


class DHCPServerChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DHCPServerConfig
        fields = '__all__'


class StaticRouteReadSerializer(serializers.ModelSerializer):
    interface = InterfaceNameSerializer()
    error = serializers.SerializerMethodField()

    def get_error(self, static_route):
        if static_route.status == 'failed':
            notification = Notification.objects.filter(source='static_route', item__id=static_route.id)
            if notification.exists():
                return notification.values('message', 'severity', 'datetime')[0]

        return None

    class Meta:
        model = StaticRoute
        fields = '__all__'


class StaticRouteRealSerializer(serializers.ModelSerializer):
    interface = InterfaceNameSerializer()
    has_set = serializers.SerializerMethodField()

    def get_has_set(self, route):
        return check_static_route_existence(route)

    class Meta:
        model = StaticRoute
        fields = '__all__'


class StaticRouteWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaticRoute
        fields = '__all__'

    def validate_destination_mask(self, value):
        if not value:
            return value

        if '.' in value:
            mask_serializer = MaskSerializer(data={'mask': value})
        else:
            mask_serializer = IntegerMaskSerializer(data={'mask': value})

        if not mask_serializer.is_valid():
            raise serializers.ValidationError(mask_serializer.errors['mask'])

        return value

    def validate(self, data):
        if 'destination_mask' not in data or not data['destination_mask']:
            data['destination_mask'] = 32

        if 'destination_ip' in data and 'destination_mask' in data and \
                data['destination_ip'] and data['destination_mask']:

            if isinstance(data['destination_mask'], str) and '.' in data['destination_mask']:
                destination_cidr = convert_to_cidr(data['destination_ip'], data['destination_mask'])
            else:
                destination_cidr = '{}/{}'.format(data['destination_ip'], data['destination_mask'])

            try:
                network_cidr = str(IPNetwork('{}/{}'.format(data['destination_ip'], data['destination_mask'])).cidr)
            except Exception as err:
                raise serializers.ValidationError(str(err))

            if destination_cidr != network_cidr:
                raise serializers.ValidationError("destination ip and mask does not match")
        if HighAvailability.objects.filter(is_enabled=True) and 'interface' in data and data['interface']:
            peer2_interface_list = get_sorted_interface_name_list(
                get_peer2_interface_list(HighAvailability.objects.get().peer2_address,
                                         ssh_port=Setting.objects.get(key='ssh-port').data['value']
                                         , https_port=Setting.objects.get(key='https-port').data['value']))
            interface = data['interface']
            if interface.name not in peer2_interface_list:
                raise serializers.ValidationError(
                    'HighAvailability has been configured and the selected {interface} does not '
                    'exist on Node2 system, add this {interface} there and then try again.'.format(
                        interface=interface.mode))
        return data

    def create(self, validated_data):
        with transaction.atomic():
            instance = super().create(validated_data)
            instance.last_operation = 'add'
            request_username = None
            request = None
            details = {
                'items':
                    {k: v for k, v in self.initial_data.items() if k not in ['interface']}
            }

            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']

            if validated_data['is_enabled']:
                cmd = create_static_route_cmd(instance)
                status, result = sudo_runner(cmd)
                if not status:
                    instance.status = 'failed'
                    instance.save()
                    create_notification(source='static_route', item={'id': instance.id, 'name': instance.name},
                                        message=str('Error in creating static route'), severity='e',
                                        details={'command': cmd, 'error': str(result)},
                                        request_username=request_username)
                    log('config', 'static-route', 'add', 'fail',
                        username=request_username, ip=get_client_ip(request), details=details)
                    error_message = static_route_error_message(str(result))
                    raise serializers.ValidationError(error_message)

                instance.status = 'succeeded'
                log('config', 'static-route', 'add', 'success',
                    username=request_username, ip=get_client_ip(request), details=details)

            else:
                instance.status = 'disabled'

            instance.save()
            Notification.objects.filter(source='static_route', item__id=instance.id).delete()

        return instance

    def update(self, instance, validated_data):
        with transaction.atomic():
            changes = get_diff(instance, StaticRouteChangeSerializer, self.initial_data, ['last_operation', 'status'])
            instance.last_operation = 'update'
            request_username = None
            request = None
            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']
            # delete old route
            if instance.is_enabled:
                cmd = delete_static_route_cmd(instance)
                sudo_runner(cmd)

            old_instance = deepcopy(instance)
            # update database row
            super(StaticRouteWriteSerializer, self).update(instance, validated_data)

            # add new route
            if validated_data['is_enabled']:
                cmd = create_static_route_cmd(instance)
                status, result = sudo_runner(cmd)
                if not status:
                    instance.status = 'failed'
                    instance.save()
                    # If atomic
                    sudo_runner(create_static_route_cmd(old_instance))
                    create_notification(source='static_route', item={'id': instance.id, 'name': instance.name},
                                        message=str('Error in updating static route'), severity='e',
                                        details={'command': cmd, 'error': str(result)},
                                        request_username=request_username)
                    if changes:
                        log('config', 'static-route', 'update', 'fail',
                            username=request_username, ip=get_client_ip(request), details=changes)
                    error_message = static_route_error_message(str(result))
                    raise serializers.ValidationError(error_message)
                instance.status = 'succeeded'
            else:
                instance.status = 'disabled'

            instance.save()
            Notification.objects.filter(source='static_route', item__id=instance.id).delete()

            if changes:
                log('config', 'static-route', 'update', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)

        return instance


class DHCPServerReadSerializer(serializers.ModelSerializer):
    interface = InterfaceNameSerializer()

    class Meta:
        model = DHCPServerConfig
        fields = '__all__'


class DHCPServerChangesSerializer(serializers.ModelSerializer):
    class Meta:
        model = DHCPServerConfig
        fields = '__all__'


class DHCPServerConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = DHCPServerConfig
        fields = '__all__'

    def validate_dns_server_list(self, value):
        if value and value.__len__() > 2:
            raise serializers.ValidationError('Number of items exceeded,only two DNS entries are allowed')
        if value:
            for dns_server in value:
                try:
                    ipaddress.ip_address(dns_server)
                except Exception:
                    raise serializers.ValidationError('Enter a valid ip address')
        return value

    def validate_interface(self, value):
        if value:
            if not value.is_enabled or value.status == 'failed' or value.ip_list == [] or not InterfaceRealSerializer(
                    value).get_is_link_connected(value):
                raise serializers.ValidationError(
                    'This interface has no IP address or disabled or disconnected or have some problems in config')

            if check_use_bridge(value.name):
                raise serializers.ValidationError('interface {} is used in bridge '.format(value.name))

            if check_use_vlan(value.name):
                raise serializers.ValidationError('interface {} is used in vlan'.format(value.name))

        return value

    def validate_exclude_ip_list(self, value):
        if value:
            for ip in value:
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    raise serializers.ValidationError('Enter a valid ip address')
        return value

    def validate_subnet_mask(self, value):
        if value:
            if value > 30 or value < 24:
                raise serializers.ValidationError(
                    'This field should be a positive number, between 24 and 30')
        return value

    def validate(self, data):
        from netaddr import IPAddress

        error_msg = dict()
        interface = data['interface']
        start_ip_flag = True
        end_ip_flag = True
        subnet_mask_flag = True

        dhcp_instance = DHCPServerConfig.objects.filter(interface=data['interface'])
        if dhcp_instance.exists():
            if (not self.instance) or (self.instance and dhcp_instance[0].id != self.instance.id):
                error_msg['interface'] = 'DHCP configuration for this interface already have done'

        for ip in interface.ip_list:
            net = ipaddress.ip_network('{}/{}'.format(ip['ip'], ip['mask']), False)
            if ipaddress.ip_address(data['start_ip']) not in ipaddress.ip_network(net).hosts():
                start_ip_flag = False
            if ipaddress.ip_address(data['end_ip']) not in ipaddress.ip_network(net).hosts():
                end_ip_flag = False

            if int(data['subnet_mask']) != int(IPAddress(ip['mask']).netmask_bits()):
                subnet_mask_flag = False
        if not start_ip_flag:
            error_msg['start_ip'] = 'start ip is not in network range of selected interface'
        if not end_ip_flag:
            error_msg['end_ip'] = 'end ip is not in network range of selected interface'
        if not subnet_mask_flag:
            error_msg['subnet_mask'] = 'Both subnet mask and selected interface subnet mask should be equal'

        if ipaddress.ip_address(data['start_ip']) >= ipaddress.ip_address(data['end_ip']):
            error_msg['non_field_errors'] = 'start ip should be less than end ip'
        # if not self.instance and DHCPServerConfig.objects.all().count() == 1:
        #     error_msg['non_field_errors'] = 'only one dhcp server config entry is allowed'
        if error_msg:
            raise serializers.ValidationError(error_msg)
        if HighAvailability.objects.filter(is_enabled=True) and 'interface' in data and data['interface']:
            peer2_interface_list = get_sorted_interface_name_list(
                get_peer2_interface_list(HighAvailability.objects.get().peer2_address,
                                         ssh_port=Setting.objects.get(key='ssh-port').data['value'],
                                         https_port=Setting.objects.get(key='https-port').data['value']))
            interface = data['interface']
            if interface.name not in peer2_interface_list:
                raise serializers.ValidationError(
                    'HighAvailability has been configured and the selected {interface} does not '
                    'exist on Node2 system, add this {interface} there and then try again.'.format(
                        interface=interface.mode))
        return data

    def create(self, validated_data):
        with transaction.atomic():
            instance = super(DHCPServerConfigSerializer, self).create(validated_data)
            instance.last_operation = 'add'
            instance.status = 'pending'
            instance.save()
            request_username = None
            request = None
            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']
            serializer = DHCPServerChangeSerializer()
            details = {
                'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
            }
            run_thread(target=set_DHCP_configuration, name='set_DHCP_config',
                       args=(instance, None, 'add', request_username, request, details))

        return instance

    def update(self, instance, validated_data):
        old_instance = deepcopy(instance)
        changes = get_diff(self.instance, DHCPServerChangeSerializer, self.initial_data, ['last_operation', 'status'])
        Notification.objects.filter(source='dhcp', item__id=instance.id).delete()
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        instance = super(DHCPServerConfigSerializer, self).update(instance, validated_data)
        instance.last_operation = 'update'
        instance.status = 'pending'
        instance.save()
        old_instance = old_instance.__dict__
        old_instance.pop('_state')
        old_instance.pop('_django_version')

        run_thread(target=set_DHCP_configuration, name='set_DHCP_config',
                   args=(instance, old_instance, 'update', request_username, request, changes))

        return instance


class BackupSerializer(serializers.ModelSerializer):
    size = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()

    class Meta:
        model = Backup
        exclude = ('file',)
        read_only_fields = ('version', 'last_operation', 'status')

    def create(self, validated_data):

        instance = super(BackupSerializer, self).create(validated_data)
        details = {
            'items':
                {k: v for k, v in self.initial_data.items() if k not in
                 ['file', 'datetime', 'is_uploaded_by_user', 'version']}
        }
        if not instance.is_uploaded_by_user:
            run_thread(target=self.backup, name='backup_{}'.format(instance.id), args=(instance, details))

        return instance

    def update(self, instance, validated_data):
        changes = get_diff(instance, UpdateConfigSerializer, self.initial_data,
                           ['file', 'datetime', 'is_uploaded_by_user', 'version', 'last_operation', 'status'])
        result = super(BackupSerializer, self).update(instance, validated_data)
        log('config', 'backup', 'update', 'success', username=self.context['request'].user.username,
            ip=get_client_ip(self.context['request']), details=changes)
        return result

    def get_size(self, instance):

        if instance.file:
            try:
                file_size = str(
                    command_runner('cd /var/ngfw;ls -sh {} '.format(instance.file.name.replace('.json', '.tar'))))
                file_size = file_size[file_size.find("'") + 1: file_size.find('n')]
                return (file_size)

            except FileNotFoundError:
                # this exception use becuase the singnal delete file before
                pass

    def get_name(self, instance):
        if instance.file:
            return instance.file.name.replace('.json', '.bak')

    def backup(self, instance, changes=None):
        from django.core.management import call_command

        if 'request' not in self.context:
            request_username = 'test'
        else:
            request_username = self.context['request'].user.username

        instance.last_operation = 'backup'
        instance.status = 'pending'
        instance.save()

        from datetime import datetime
        now = datetime.now()
        backup_file_name = 'sg_backup_{}.json'.format(now.strftime('%Y-%m-%d_%H.%M.%S'))
        backup_file_path = os.path.join(BACKUP_DIR, backup_file_name)

        try:
            call_command('dumpdata', exclude=[
                'config_app.Backup',
                'auth_app.AdminLoginLock',
                'auth_app.Token',
                'sessions.Session',
                'auth.permission',
                'contenttypes'
                # 'silk'
            ], output=backup_file_path)

            sudo_runner('chown -R ngfw:ngfw {}'.format(BACKUP_DIR))

        except Exception as e:
            log('config', 'backup', 'add', 'fail',
                username=request_username, ip=get_client_ip(self.context['request']), details=str(e))
            instance.status = 'failed'
            instance.save()
            raise e

        instance.file = backup_file_name
        instance.datetime = now
        instance.status = 'succeeded'

        status, version = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
            os.path.join(BACKUP_DIR, 'currentversion.yml'))
        )

        delimiter = '$$$ngfw$$$'
        command_runner("cd /var/ngfw;echo '{1}{0}{2}{0}{3}' > info.txt".format(
            delimiter,
            instance.description,
            version,
            instance.datetime,
        ))

        command_runner(
            'cd /var/ngfw;tar -cf {2}.tar {0} {1} info.txt {3}  {4} {5} {6} {7} {8} {9} '.format(backup_file_name,
                                                                                                 POLICY_BACK_POSTFIX,
                                                                                                 backup_file_name.replace(
                                                                                                     '.json',
                                                                                                     ''),
                                                                                                 RSYSLOG_CONFIG_FILE,
                                                                                                 IPSEC_CONF_FILE,
                                                                                                 DNSMASQ_CONFIG_FILE,
                                                                                                 IPSEC_SECRETS_FILE,
                                                                                                 GRE_CONFIGS_PATH,
                                                                                                 IPIP_CONFIGS_PATH,
                                                                                                 VTUND_CONFIGS_PATH))

        command_runner('rm /var/ngfw/{}'.format(backup_file_name))

        command_runner('rm /var/ngfw/info.txt')
        if status:
            instance.version = version
        instance.save()

        log('config', 'backup', 'add', 'success',
            username=request_username, ip=get_client_ip(self.context['request']), details=changes)


class UpdateConfigSerializer(serializers.ModelSerializer):
    def validate_update_server(self, value):
        if 'is_update_enabled' in self.initial_data and self.initial_data['is_update_enabled'] \
                and not value:
            raise serializers.ValidationError(_('This field is required'))

        if value:
            address = value.strip()
            if ':' not in address:
                if not FQDN(address).is_valid and not SingleIPSerializer(data={'ip': address}).is_valid():
                    raise serializers.ValidationError(_('Enter a valid FQDN or IP address.'))
            elif ':' in address:
                try:
                    address, port = address.split(':')
                    if not FQDN(address).is_valid and not SingleIPSerializer(data={'ip': address}).is_valid():
                        raise serializers.ValidationError(_('Enter a valid FQDN or IP address.'))
                    if int(port) > 65535 or int(port) < 0:
                        raise serializers.ValidationError(_('Port must be less than 65535'))
                except Exception as e:
                    raise serializers.ValidationError(_('Enter a valid FQDN or IP address.'))

            else:

                raise serializers.ValidationError(_('Enter a valid FQDN or IP address.'))

        return value

    def validate(self, data):
        if not self.instance and UpdateConfig.objects.all().exists():
            raise serializers.ValidationError("can't send a post request when data is exists")
        return data

    def create(self, validated_data):
        instance = super(UpdateConfigSerializer, self).create(validated_data)
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        details = {
            'items':
                {k: v for k, v in self.initial_data.items() if k not in ['schedule']}
        }
        log('config', 'update-manager-setting', 'add', 'success',
            username=request_username, ip=get_client_ip(request), details=details)

        return instance

    def update(self, instance, validated_data):
        changes = get_diff(instance, UpdateConfigSerializer, self.initial_data, ['schedule'])
        instance.is_update_enabled = validated_data.get('is_update_enabled')
        instance.update_server = validated_data.get('update_server')
        instance.schedule = validated_data.get('schedule')
        instance.save()

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        log('config', 'update-manager-setting', 'update', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)

        return instance

    class Meta:
        model = UpdateConfig
        fields = '__all__'


class NTPConfigSerializer(serializers.ModelSerializer):

    def validate_ntp_server_list(self, value):
        if 'is_enabled' in self.initial_data and self.initial_data['is_enabled']:
            if not value:
                raise serializers.ValidationError(_('This field is required'))
            if not isinstance(value, list):
                raise serializers.ValidationError(_('ntp_server should be list'))

        if value:
            for address in value:
                addr = address.strip()
                if not FQDN(addr).is_valid and not SingleIPSerializer(data={'ip': addr}).is_valid():
                    raise serializers.ValidationError(_('Enter a valid FQDN or IP address.'))

        return value

    def validate(self, data):
        if not self.instance and NTPConfig.objects.all().exists():
            raise serializers.ValidationError("can't send a post request when exist data")
        return data

    def create(self, validated_data):
        instance = super(NTPConfigSerializer, self).create(validated_data)
        changes = {'items': validated_data}
        instance.last_operation = 'add'
        instance.status = 'pending'
        instance.save()

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        if instance.is_enabled:
            try:

                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='ntp',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='tcp',
                    port='123',
                    service_list='{ntp}',
                    source=source
                )
            except:
                pass


        else:

            InputFirewall.objects.filter(service_list='{ntp}').delete()

        apply_rule(None, None)

        config_ntp_server(instance.id, request_username, request)

        log('config', 'ntp-setting', 'add', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)

        return instance

    def update(self, instance, validated_data):
        changes = get_diff(instance, NTPConfigSerializer, self.initial_data, ['last_operation', 'status'])
        instance.is_enabled = validated_data.get('is_enabled')
        instance.ntp_server_list = validated_data.get('ntp_server_list')
        instance.last_operation = 'update'
        instance.status = 'pending'
        instance.save()

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        try:

            if instance.is_enabled and not InputFirewall.objects.filter(port__exact='123'):
                source = Source.objects.create()
                InputFirewall.objects.create(
                    name='ntp',
                    is_log_enabled='False',
                    is_enabled='True',
                    permission='system',
                    protocol='tcp',
                    port='123',
                    service_list='{ntp}',
                    source=source
                )
            else:
                InputFirewall.objects.filter(service_list='{ntp}').delete()


        except:
            pass

        apply_rule(None, None)
        config_ntp_server(instance.id, request_username, request)

        log('config', 'ntp-setting', 'update', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)

        return instance

    class Meta:
        model = NTPConfig
        fields = '__all__'


class LogServerSerializer(serializers.ModelSerializer):
    def validate_service_list(self, value):
        if not value:
            raise serializers.ValidationError(_('This field is required'))

        return value

    def validate_port(self, value):
        if value > 65535:
            raise serializers.ValidationError(_('Port must be less than 65535'))

        return value


    def create(self, validated_data):
        instance = None
        if LogServer.objects.all().count() >= 3:
            raise serializers.ValidationError({
                'non_field_errors': 'Support three syslog server at the same time'})
        with transaction.atomic():
            instance = super().create(validated_data)
            details = {'items': validated_data}
            instance.last_operation = 'add'
            instance.status = 'pending'
            instance.save()

            operation = 'add'
            request_username = None
            request = None
            if 'request' in self.context and hasattr(self.context['request'], 'user'):
                request_username = self.context['request'].user.username
                request = self.context['request']

            if instance.is_enabled:
                s, content = sudo_file_reader(RSYSLOG_CONFIG_FILE)
                if s:

                    if 'defaultNetstreamDriverCAFile' not in content:
                        textCA = '\nglobal(\n defaultNetstreamDriverCAFile = "{}"\n)#CA\n\n'.format(
                            SSL_CERT_RSYSLOG_CA_FILE)
                        content += textCA

                    sudo_file_writer(RSYSLOG_CONFIG_FILE, content, 'w+')

                if not set_rsyslog_server(instance, request_username, request, details, operation):
                    instance.status = 'failed'
                    instance.save()
                    raise serializers.ValidationError({'non_field_errors': 'Error in setting syslog servers'})

                if instance.protocol == 'tcp':
                    open_port_in_iptables(new_port=str(instance.port), direction='sport')

            instance.status = 'succeeded'
            instance.save()

        return instance

    def update(self, instance, validated_data):
        changes = get_diff(self.instance, LogServerSerializer, self.initial_data, ['last_operation', 'status'])
        old_logserver = deepcopy(instance)

        operation = 'update'
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        remove_rsyslog_server(old_logserver, request_username, request, changes, operation)

        instance = super().update(instance, validated_data)
        instance.last_operation = operation
        instance.status = 'pending'

        if instance.is_enabled:
            if instance.protocol == 'tcp':
                open_port_in_iptables(old_port=str(instance.port), direction='sport')

            if not set_rsyslog_server(instance, request_username, request, changes, operation):
                instance.status = 'failed'
                instance.save()
                raise serializers.ValidationError({'non_field_errors': 'Error in setting syslog servers'})

            if instance.protocol == 'tcp':
                open_port_in_iptables(new_port=str(instance.port), direction='sport')

        instance.status = 'succeeded'
        instance.save()

        return instance

    class Meta:
        model = LogServer
        fields = '__all__'


class SetPasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate_current_password(self, password):
        username = self.context['request'].user.username
        if not sudo_pam_authenticate(username, password):
            raise serializers.ValidationError('Incorrect password')

        return password

    def validate_new_password(self, password):
        min_password_length = int(Setting.objects.get(key='min-password-length').data['value'])
        if len(password) < min_password_length:
            raise serializers.ValidationError(
                'This password is too short. .It must contain at least {} characters'.format(min_password_length))

        user = self.context['request'].user
        validate_password(password, user)
        return password


class SettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Setting
        fields = '__all__'
        read_only_fields = ('key', 'display_name', 'descriptions', 'type', 'category', 'order')

    def update(self, instance, validated_data):
        changes = get_diff(instance, SettingSerializer, self.initial_data)

        old_setting = deepcopy(self.instance)

        instance = super(SettingSerializer, self).update(instance, validated_data)

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        if instance.key == 'min-password-length':
            log('config', 'min-password-length', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)

        if instance.key == 'protection-log':
            log('config', 'protection-log', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)

        if instance.key in ['ssh-port', 'http-port', 'https-port']:
            config_narin_access_ports(instance, old_setting, request_username, request, changes)

        elif instance.key == 'login-message':
            ssh_banner_message = generate_ssh_banner(instance.data['value'])

            t = Thread(target=sudo_file_writer, args=(ISSUE_NET_FILE, ssh_banner_message, 'w'))
            t.start()

            t = Thread(target=sudo_file_writer, args=(ISSUE_FILE, ssh_banner_message, 'w'))
            t.start()

            log('config', 'login-message', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)

        elif instance.key == 'admin-session-timeout':
            status, sshd_config_content = sudo_runner('cat {}'.format(SSH_CONFIG_FILE))
            if status:
                newcontent = change_or_add_key_to_content("\s*ClientAliveInterval\s*[^\n]*\n",
                                                          "\nClientAliveInterval {}\n".format(
                                                              int(instance.data['value']) * 60),
                                                          sshd_config_content)
                sudo_file_writer(SSH_CONFIG_FILE, newcontent, 'w')
                sudo_runner('service ssh restart')

                log('config', 'admin-session-timeout', 'update', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)
            else:
                log('config', 'admin-session-timeout', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=str(sshd_config_content))

        elif instance.key == 'max-login-attempts':
            status, fail2ban_config_content = sudo_runner('cat {}'.format(FAIL_2_BAN_CONFIG_FILE))
            if status:
                newcontent = change_or_add_key_to_content("\n\s*maxretry\s*=\s*\d+\n",
                                                          "\nmaxretry = {}\n".format(instance.data['value']),
                                                          fail2ban_config_content)
                sudo_file_writer(FAIL_2_BAN_CONFIG_FILE, newcontent, 'w')
                sudo_runner('service fail2ban restart')

                log('config', 'max-login-attempts', 'update', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)
            else:
                log('config', 'max-login-attempts', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=str(fail2ban_config_content))

        elif instance.key == 'ssh-ban-time':
            status, fail2ban_config_content = sudo_runner('cat {}'.format(FAIL_2_BAN_CONFIG_FILE))
            if status:
                newcontent = change_or_add_key_to_content("\n\s*bantime\s*=\s*\d+\n",
                                                          "\nbantime = {}\n".format(instance.data['value']),
                                                          fail2ban_config_content)
                sudo_file_writer(FAIL_2_BAN_CONFIG_FILE, newcontent, 'w')
                sudo_runner('service fail2ban restart')

                log('config', 'ssh-ban-time', 'update', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)
            else:
                log('config', 'ssh-ban-time', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=str(fail2ban_config_content))

        elif instance.key == 'ssl_certificate':

            certificate_id = instance.data['certificate']

            try:
                certificate = PKI.objects.get(id=certificate_id, type='certificate')

            except:

                log('config', 'ssl_certificate', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=str('certificate not exist'))
                raise serializers.ValidationError('certificate not exist')

            s, o = sudo_file_writer('/etc/ssl/certs/nginx-selfsigned.crt', certificate.certificate, 'w')
            if not s:
                log('config', 'ssl_certificate', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=str(o))
                raise serializers.ValidationError(o)

            s, o = sudo_file_writer('/etc/ssl/private/nginx-selfsigned.key', certificate.private_key, 'w')
            if not s:
                log('config', 'ssl_certificate', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=str(0))
                raise serializers.ValidationError(o)

            sudo_runner('service nginx restart')

            log('config', 'ssl_certificate', 'update', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)

        elif instance.key == 'host-name':

            s, o = sudo_runner('hostname {}'.format(instance.data['value']))
            if not s:
                instance.data["value"] = old_setting.data["value"]
                instance.save()

                log('config', 'host_name', 'update', 'fail',
                    username=request_username, ip=get_client_ip(request), details=changes)
                raise serializers.ValidationError(
                    {
                        'data': 'this name is not valid for hostname. Valid characters for hostnames are ASCII(7) letters from a to z, the digits from 0 to 9, and the hyphen (-).  A hostname may not start with a hyphen.'})
            else:
                sudo_file_writer('/etc/hostname', instance.data['value'], 'r+')
                status, result = sudo_file_reader(HOSTS_FILE)
                if status:
                    old_host = '127.0.1.1\t{}'.format(old_setting.data["value"])
                    content = ''
                    for line in result.splitlines():
                        if old_host != line:
                            content += line + '\n'
                    new_host = '127.0.1.1\t{}'.format(instance.data['value'])
                    content += new_host
                    sudo_file_writer(HOSTS_FILE, content, 'r+')
                log('config', 'host_name', 'update', 'success',
                    username=request_username, ip=get_client_ip(request), details=changes)
        return instance

    def validate(self, data):
        if self.instance.key == 'admin-session-timeout':
            self.validate_admin_session_timeout(data['data']['value'])
        if self.instance.key == 'ssh-port' or self.instance.key == 'http-port' or self.instance.key == 'https-port':
            self.validate_setting_ports(data['data']['value'])
        if self.instance.key == 'ssl_certificate':
            self.validate_ssl_certificate(data['data'])
        if self.instance.key == 'min-password-length':
            self.validate_min_pass_length(data['data']['value'])
        if self.instance.key == 'host-name':
            self.validate_host_name(data['data']['value'])
        if self.instance.key == 'max-login-attempts':
            self.validate_max_login_attempts(data['data']['value'])
        if self.instance.key == 'ssh-ban-time':
            self.validate_ssh_ban_time(data['data']['value'])
        return data

    def validate_ssh_ban_time(self, value):
        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                'HighAvailability is configured on this system, disable HighAvailability configuration first to update ssh-ban-time.')
        return value

    def validate_max_login_attempts(self, value):
        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                'HighAvailability is configured on this system, disable HighAvailability configuration first to update max-login-attempts.')
        return value

    def validate_host_name(self, value):
        if '\n' in value or '\t' in value or ' ' in value:
            raise serializers.ValidationError('Host name should not contain white space characters')
        # if HA configurations exist then admin cannot change the hostname
        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                'HighAvailability is configured on this system, disable HighAvailability configuration first to update hostname.')
        return value

    def validate_min_pass_length(self, value):
        if int(value) < 8:
            raise serializers.ValidationError(
                {'value': 'Minimum password length should be an integer equal or bigger than 8'})
        return value

    def validate_admin_session_timeout(self, value):
        value = str(value)
        if not value.isdigit() or int(value) < 10 or int(value) > 600:
            raise serializers.ValidationError(
                {'value': 'admin-session-timeout should be an integer between 10 and 600'})
        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                'HighAvailability is configured on this system, disable HighAvailability configuration first to update admin-session-timeout.')
        return value

    def validate_setting_ports(self, value):

        if not str(value).isdigit() or int(value) < 1 or int(value) > 65535:
            raise serializers.ValidationError(
                {'non_field_errors': 'port number should be an integer between 1 and 65535'})

        if self.instance.key == 'http-port':

            ssh_instance = Setting.objects.get(key='ssh-port')
            https_instance = Setting.objects.get(key='https-port')
            if str(value) == str(ssh_instance.data["value"]):
                raise serializers.ValidationError(
                    {'non_field_errors': 'this port used before in ssh port'})
            if str(value) == str(https_instance.data["value"]):
                raise serializers.ValidationError(
                    {'non_field_errors': 'this port used before in https port'})

        if self.instance.key == 'ssh-port':

            http_instance = Setting.objects.get(key='http-port')
            https_instance = Setting.objects.get(key='https-port')
            if str(value) == str(http_instance.data["value"]):
                raise serializers.ValidationError(
                    {'non_field_errors': 'this port used before in http port'})
            if str(value) == str(https_instance.data["value"]):
                raise serializers.ValidationError(
                    {'non_field_errors': 'this port used before in https port'})

        if self.instance.key == 'https-port':

            ssh_instance = Setting.objects.get(key='ssh-port')
            http_instance = Setting.objects.get(key='http-port')
            if str(value) == str(ssh_instance.data["value"]):
                raise serializers.ValidationError(
                    {'non_field_errors': 'this port used before in ssh port'})
            if str(value) == str(http_instance.data["value"]):
                raise serializers.ValidationError(
                    {'non_field_errors': 'this port used before in http port'})

        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                'HighAvailability is configured on this system, disable HighAvailability configuration first to update {}.'.format(
                    self.instance.key))
        return value

    def validate_ssl_certificate(self, data):
        if 'certificate' not in data or not data['certificate']:
            raise serializers.ValidationError(
                {'data': 'ssl certificate must have ID'})
        if HighAvailability.objects.filter(is_enabled=True):
            raise serializers.ValidationError(
                'HighAvailability is configured on this system, disable HighAvailability configuration first to update ssl certificate.')
        return data


class DNSRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = DNSRecord
        fields = '__all__'

    def create(self, validated_data):
        instance = super().create(validated_data)
        details = {'items': validated_data}
        instance.last_operation = 'add'
        instance.status = 'pending'
        instance.save()
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        dns_record_config(instance, 'add', None, None, request_username, request, details)

        return instance

    def update(self, instance, validated_data):
        request_username = None
        request = None
        old_hostname_list = instance.hostname_list
        old_ip_address = instance.ip_address

        changes = get_diff(instance, DNSRecordSerializer, validated_data, ['last_operation', 'status'])

        instance = super(DNSRecordSerializer, self).update(instance, validated_data)
        instance.last_operation = 'update'
        instance.status = 'pending'
        instance.save()
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        Notification.objects.filter(source='dns_record', item__id=instance.id).delete()
        dns_record_config(instance, 'update', old_ip_address,
                          old_hostname_list, request_username, request, changes)
        return instance

    def validate_hostname_list(self, value):
        if not value:
            raise serializers.ValidationError(_('This field may not be blank.'))
        if not isinstance(value, list):
            raise serializers.ValidationError(_('This field should be list.'))
        instance_id = None
        if hasattr(self, 'instance') and hasattr(self.instance, 'id'):
            instance_id = self.instance.id
        list_of_hostname_list = list(
            DNSRecord.objects.filter().exclude(id=instance_id).values_list('hostname_list', flat=True))
        hostname_list = [item for sublist in list_of_hostname_list for item in sublist]
        for host in value:
            if host in hostname_list:
                raise serializers.ValidationError(_('Host \'%s\' already exsist.' % host))
            elif host == "":
                raise serializers.ValidationError(_('This field may not be blank.'))
        return list(set(value))


class DNSRecordReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = DNSRecord
        fields = '__all__'

    error = serializers.SerializerMethodField()

    def get_error(self, dns_record):
        if dns_record.status == 'failed':
            notification = Notification.objects.filter(source='dns_record', item__id=dns_record.id)
            if notification.exists():
                return notification.values('message', 'severity', 'datetime')[0]
        return None


class DNSConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = DNSConfig
        fields = '__all__'

    def update(self, instance, validated_data):
        changes = get_diff(self.instance, DNSConfigSerializer, self.initial_data, ['last_operation', 'status'])
        instance = super(DNSConfigSerializer, self).update(instance, self.validated_data)
        instance.last_operation = 'update'
        instance.status = 'pending'
        instance.save()

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']

        dns_configuration(instance, request_username, request, changes)

        return instance

    def validate_interface_list(self, value):
        for interface in value:
            if check_use_bridge(interface.name):
                raise serializers.ValidationError('interface {} is used in bridge '.format(interface.name))

            if check_use_vlan(interface.name):
                raise serializers.ValidationError('interface {} is used in vlan'.format(interface.name))

            if not IS_TEST:
                if not interface.is_enabled or interface.status == 'failed' or interface.ip_list == [] or not InterfaceRealSerializer(
                        interface).get_is_link_connected(interface):
                    raise serializers.ValidationError(
                        'This interface ({}) does not have ip address or is not enable or its link is not connected or have some problems in configuration'.format(
                            interface.name))

        if HighAvailability.objects.filter(is_enabled=True):
            peer2_interface_list = get_sorted_interface_name_list(
                get_peer2_interface_list(HighAvailability.objects.get().peer2_address,
                                         ssh_port=Setting.objects.get(key='ssh-port').data['value'],
                                         https_port=Setting.objects.get(key='https-port').data['value']))
            not_sync_interface_list = []
            for interface in value:
                if interface.name not in peer2_interface_list:
                    not_sync_interface_list.append(interface.name)
            if not_sync_interface_list:
                raise serializers.ValidationError(
                    'HighAvailability has been configured and the selected {interface} does not '
                    'exist on Node2 system, add {interface} there and then try again.'.format(
                        interface=', '.join(not_sync_interface_list)))

        return value

    def validate(self, data):
        if not self.instance and DNSConfig.objects.all().exists():
            raise serializers.ValidationError("can't send a post request when exist data")

        primary_dns = data.get('primary_dns_server', None)
        secondary_dns = data.get('secondary_dns_server', None)
        tertiary_dns = data.get('tertiary_dns_server', None)
        if self.context['request'].method == 'PATCH':
            if tertiary_dns and not self.instance.secondary_dns_server:
                raise serializers.ValidationError(_('Secondary DNS server fields has not been entered.'))
            return data

        if tertiary_dns and not secondary_dns and not primary_dns:
            raise serializers.ValidationError(_('Primary and Secondary DNS server fields has not been entered.'))
        elif tertiary_dns and not secondary_dns and primary_dns:
            raise serializers.ValidationError(_('Secondary DNS server fields has not been entered.'))
        elif not primary_dns:
            raise serializers.ValidationError(_('Primary DNS server field has not been entered.'))
        return data


class DNSConfigReadSerializer(serializers.ModelSerializer):
    interface_list = InterfaceSerializer(many=True)

    class Meta:
        model = DNSConfig
        fields = '__all__'

    error = serializers.SerializerMethodField()

    def get_error(self, dns_config):
        if dns_config.status == 'failed':
            notification = Notification.objects.filter(source='dns_config', item__id=dns_config.id)
            if notification.exists():
                return notification.values('message', 'severity', 'datetime')[0]
        return None


class SystemServiceSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = SystemService
        exclude = ('real_name',)

    def get_status(self, instance):
        command_status, output = sudo_runner('service {} status'.format(instance.real_name))

        if 'Active: active (running)' in output:
            return 'active'

        elif 'Active: failed' in output:
            return 'failed'

        elif 'Active: inactive (dead)' in output:
            return 'inactive'

        elif 'Unit {}.service could not be found.'.format(instance.real_name) in output:
            return 'unavailable'

        else:
            return 'unknown'


class UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Update
        fields = '__all__'
