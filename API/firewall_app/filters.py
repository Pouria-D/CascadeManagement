from django_filters import rest_framework as filters

from firewall_app.models import Policy


class PolicyFilter(filters.FilterSet):
    action = filters.CharFilter(field_name="action", lookup_expr='contains')
    next_policy = filters.CharFilter(field_name='next_policy__name', lookup_expr='contains')
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')
    schedule = filters.CharFilter(field_name="schedule__name", lookup_expr='contains')
    is_log_enabled = filters.BooleanFilter(field_name='is_log_enabled', lookup_expr='exact')

    src_interface_list = filters.CharFilter(field_name="source_destination__src_interface_list__name",
                                            lookup_expr='contains')
    dst_interface_list = filters.CharFilter(field_name="source_destination__dst_interface_list__name",
                                            lookup_expr='contains')
    src_network_list = filters.CharFilter(field_name="source_destination__src_network_list__name",
                                          lookup_expr='contains')
    dst_network_list = filters.CharFilter(field_name="source_destination__dst_network_list__name",
                                          lookup_expr='contains')
    service_list = filters.CharFilter(field_name="source_destination__service_list__name", lookup_expr='contains')
    # application_list = filters.CharFilter(field_name="source_destination__application_list__name", lookup_expr='contains')
    src_geoip_country_list = filters.CharFilter(field_name="source_destination__src_geoip_country_list",
                                                lookup_expr='contains')
    dst_geoip_country_list = filters.CharFilter(field_name="source_destination__dst_geoip_country_list",
                                                lookup_expr='contains')

    nat_name = filters.CharFilter(field_name="nat__name", lookup_expr='contains')
    nat_description = filters.CharFilter(field_name="nat__description", lookup_expr='contains')
    nat_type = filters.CharFilter(field_name='nat__nat_type', lookup_expr='contains')
    snat_type = filters.CharFilter(field_name='nat__snat_type', lookup_expr='contains')
    nat_ip = filters.CharFilter(field_name='nat__ip', lookup_expr='contains')
    nat_port = filters.CharFilter(field_name='nat__port', lookup_expr='contains')
    nat_is_enabled = filters.CharFilter(field_name='nat__is_enabled', lookup_expr='exact')

    pbr_is_enabled = filters.CharFilter(field_name='pbr__is_enabled', lookup_expr='exact')

    class Meta:
        model = Policy
        fields = ['action', 'next_policy', 'name', 'description', 'is_enabled', 'schedule', 'is_log_enabled',
                  'src_interface_list', 'dst_interface_list', 'src_network_list', 'dst_network_list',
                  'service_list', 'src_geoip_country_list', 'dst_geoip_country_list',
                  'nat_name', 'nat_description', 'nat_type', 'snat_type', 'nat_ip',
                  'nat_port', 'nat_is_enabled',
                  'pbr_is_enabled']
