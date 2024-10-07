from django.db.models.query import QuerySet
from django_filters import rest_framework as filters

from entity_app.models import Address, Service, Schedule


class AddressFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    type = filters.CharFilter(field_name="type", lookup_expr='contains')
    value_list = filters.CharFilter(field_name="value_list", lookup_expr='contains')
    is_single_ip = filters.BooleanFilter(method='is_single_ip_filter', label='is_single_ip')

    def is_single_ip_filter(self, queryset, name, value):
        id_list = []
        if value:
            for address in queryset:
                if address.type == 'ip' and len(address.value_list) == 1:
                    if '/' not in address.value_list[0] or '/32' in address.value_list[0]:
                        id_list.append(address.id)
            return queryset.filter(id__in=id_list)
        return queryset


    class Meta:
        model = Address
        fields = ['name', 'description', 'type', 'value_list']


class ServiceFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    protocol = filters.CharFilter(field_name="protocol", method='filter_data_key')

    def filter_data_key(self, qs, name, value):
        qs = Service.objects.filter(protocol__has_key=value)
        return qs

    class Meta:
        model = Service
        fields = ['name', 'description', 'protocol']


class ScheduleFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    start_date = filters.DateFilter(field_name="start_date", lookup_expr='contains')
    end_date = filters.DateFilter(field_name="end_date", lookup_expr='contains')
    start_time = filters.TimeFilter(field_name="start_time", lookup_expr='contains')
    end_time = filters.TimeFilter(field_name="end_time", lookup_expr='contains')

    class Meta:
        model = Schedule
        fields = ['name', 'description', 'start_date', 'end_date', 'start_time', 'end_time']
