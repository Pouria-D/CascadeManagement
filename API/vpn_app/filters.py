from django_filters import rest_framework as filters

from vpn_app.models import VPN


class VPNFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')
    phase1_encryption_algorithm = filters.CharFilter(field_name="phase1_encryption_algorithm", lookup_expr='contains')
    phase1_authentication_algorithm = filters.CharFilter(field_name="phase1_authentication_algorithm",
                                                         lookup_expr='contains')
    phase1_diffie_hellman_group = filters.CharFilter(field_name="phase1_diffie_hellman_group", lookup_expr='contains')
    phase1_lifetime = filters.NumberFilter(field_name='phase1_lifetime', lookup_expr='exact')

    phase2_encryption_algorithm = filters.CharFilter(field_name="phase1_encryption_algorithm", lookup_expr='contains')
    phase2_authentication_algorithm = filters.CharFilter(field_name="phase1_authentication_algorithm",
                                                         lookup_expr='contains')
    phase2_diffie_hellman_group = filters.CharFilter(field_name="phase1_diffie_hellman_group", lookup_expr='contains')
    phase2_lifetime = filters.NumberFilter(field_name='phase1_lifetime', lookup_expr='exact')

    local_network = filters.CharFilter(field_name="local_network", lookup_expr='contains')
    local_endpoint = filters.CharFilter(field_name="local_endpoint", lookup_expr='contains')
    local_id = filters.CharFilter(field_name="local_id", lookup_expr='contains')

    remote_network = filters.CharFilter(field_name="remote_network", lookup_expr='contains')
    remote_endpoint = filters.CharFilter(field_name="remote_endpoint", lookup_expr='contains')
    peer_id = filters.CharFilter(field_name="peer_id", lookup_expr='contains')

    authentication_method = filters.CharFilter(field_name="authentication_method", lookup_expr='contains')
    preshared_key = filters.CharFilter(field_name="preshared_key", lookup_expr='contains')
    dpd = filters.BooleanFilter(field_name="dpd", lookup_expr='exact')

    type = filters.CharFilter(field_name="tunnel__type", lookup_expr='contains')
    virtual_local_endpoint = filters.CharFilter(field_name="tunnel__virtual_local_endpoint", lookup_expr='contains')
    virtual_remote_endpoint = filters.CharFilter(field_name="tunnel__virtual_remote_endpoint", lookup_expr='contains')
    mtu = filters.NumberFilter(field_name="tunnel__mtu", lookup_expr='exact')
    mode = filters.CharFilter(field_name="tunnel__mode", lookup_expr='contains')
    server_endpoint = filters.CharFilter(field_name="tunnel__server_endpoint", lookup_expr='contains')
    service_protocol = filters.CharFilter(field_name="tunnel__service_protocol", lookup_expr='contains')
    service_port = filters.CharFilter(field_name="tunnel__service_port", lookup_expr='contains')
    real_local_endpoint = filters.CharFilter(field_name="tunnel__real_local_endpoint", lookup_expr='contains')
    real_remote_endpoint = filters.CharFilter(field_name="tunnel__real_remote_endpoint", lookup_expr='contains')

    class Meta:
        model = VPN
        fields = ['name', 'description', 'is_enabled', 'phase1_encryption_algorithm', 'phase1_authentication_algorithm',
                  'phase1_diffie_hellman_group', 'phase1_lifetime', 'phase2_encryption_algorithm',
                  'phase2_authentication_algorithm', 'phase2_diffie_hellman_group', 'phase2_lifetime',
                  'local_network', 'local_endpoint', 'local_id', 'remote_network', 'remote_endpoint', 'peer_id',
                  'authentication_method', 'preshared_key', 'dpd', 'type', 'virtual_local_endpoint',
                  'virtual_remote_endpoint', 'mtu', 'mode', 'server_endpoint', 'service_protocol',
                  'service_port', 'real_local_endpoint', 'real_remote_endpoint']
