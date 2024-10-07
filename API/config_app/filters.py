from django_filters import rest_framework as filters

from config_app.models import Interface, StaticRoute, DNSRecord, Backup, LogServer, SystemService, Snmp


class InterfaceFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    alias = filters.CharFilter(field_name="alias", lookup_expr='contains')
    ip_list = filters.CharFilter(field_name="ip_list", lookup_expr='contains')
    gateway = filters.CharFilter(field_name="gateway", lookup_expr='contains')
    type = filters.CharFilter(field_name="type", lookup_expr='contains')
    link_type = filters.CharFilter(field_name="link_type", lookup_expr='contains')
    pppoe_username = filters.CharFilter(field_name="pppoe_username", lookup_expr='contains')
    pppoe_password = filters.CharFilter(field_name="pppoe_password", lookup_expr='contains')
    mtu = filters.NumberFilter(field_name="mtu", lookup_expr='exact')
    is_dhcp_enabled = filters.BooleanFilter(field_name="is_dhcp_enabled", lookup_expr='exact')
    is_default_gateway = filters.BooleanFilter(field_name="is_default_gateway", lookup_expr='exact')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')
    download_bandwidth = filters.NumberFilter(field_name="download_bandwidth", lookup_expr='contains')
    upload_bandwidth = filters.NumberFilter(field_name="upload_bandwidth", lookup_expr='contains')
    mode = filters.CharFilter(field_name="mode", lookup_expr='contains')

    class Meta:
        model = Interface
        fields = ['name', 'description', 'alias', 'ip_list', 'gateway', 'is_default_gateway', 'is_dhcp_enabled',
                  'type', 'is_enabled', 'link_type', 'pppoe_username', 'pppoe_password', 'mtu', 'download_bandwidth',
                  'upload_bandwidth']


class StaticRouteFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    destination_ip = filters.CharFilter(field_name="destination_ip", lookup_expr='contains')
    destination_mask = filters.CharFilter(field_name='destination_mask', lookup_expr='contains')
    interface = filters.CharFilter(field_name="interface", lookup_expr='contains')
    gateway = filters.CharFilter(field_name="gateway", lookup_expr='contains')
    metric = filters.NumberFilter(field_name="metric", lookup_expr='exact')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')

    class Meta:
        model = StaticRoute
        fields = ['name', 'description', 'destination_ip', 'destination_mask', 'interface', 'gateway', 'metric',
                  'is_enabled']


class SNMPFilter(filters.FilterSet):
    user_name = filters.CharFilter(field_name='user_name', lookup_expr='contain')
    security_level = filters.CharFilter(field_name='security_level', lookup_expr='contain')
    private_algorithm = filters.CharFilter(field_name='private_algorithm', lookup_expr='contain')
    authentication_algorithm = filters.CharFilter(field_name='authentication_algorithm', lookup_expr='contain')
    allow_network = filters.CharFilter(field_name="allow_network", lookup_expr='contain')
    type = filters.CharFilter(field_name="type", lookup_expr='contain')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')

    class Meta:
        model = Snmp
        fields = ['user_name', 'security_level', 'private_algorithm', 'authentication_algorithm', 'allow_network',
                  'type', 'is_enabled', 'description']


class BackupFilter(filters.FilterSet):
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    version = filters.CharFilter(field_name="version", lookup_expr='contains')

    class Meta:
        model = Backup
        fields = ['version', 'description']


class LogServerFilter(filters.FilterSet):
    address = filters.CharFilter(field_name="address", lookup_expr='contains')
    port = filters.CharFilter(field_name="port", lookup_expr='contains')
    protocol = filters.CharFilter(field_name="protocol", lookup_expr='contains')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')
    is_secure = filters.BooleanFilter(field_name="is_secure", lookup_expr='exact')

    class Meta:
        model = LogServer
        fields = ['address', 'port', 'protocol', 'is_enabled', 'is_secure']


class DNSRecordFilter(filters.FilterSet):
    ip_address = filters.CharFilter(field_name="ip_address", lookup_expr='contains')
    hostname_list = filters.CharFilter(field_name='hostname_list', method='filter_data_key')

    def filter_data_key(self, qs, name, value):
        qs = DNSRecord.objects.filter(hostname_list__has_key=value)
        return qs

    class Meta:
        model = DNSRecord
        fields = ['ip_address', 'hostname_list']


class SystemServiceFilter(filters.FilterSet):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')

    class Meta:
        model = SystemService
        fields = ['name']
