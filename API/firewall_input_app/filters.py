from django_filters import rest_framework as filters

from firewall_input_app.models import InputFirewall


class FirewallInputFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    port = filters.CharFilter(field_name="port", lookup_expr='contains')
    protocol = filters.CharFilter(field_name="protocol", lookup_expr='contains')
    service_list = filters.CharFilter(field_name="service_list", lookup_expr='contains')
    is_enabled = filters.BooleanFilter(field_name="is_enabled", lookup_expr='exact')
    src_interface_list = filters.CharFilter(field_name="source__src_interface_list__name",
                                            lookup_expr='contains')
    src_network_list = filters.CharFilter(field_name="source__src_network_list__name",
                                          lookup_expr='contains')

    class Meta:
        model = InputFirewall
        fields = ['name', 'description', 'port', 'protocol', 'service_list', 'is_enabled', 'src_interface_list',
                  'src_network_list', ]
