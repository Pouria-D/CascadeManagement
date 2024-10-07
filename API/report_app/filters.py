from django_filters import rest_framework as filters

from report_app.models import Notification


class NotificationFilter(filters.FilterSet):
    source = filters.CharFilter(field_name="source", lookup_expr='contains')
    item = filters.CharFilter(field_name='item', lookup_expr='contains')
    message = filters.CharFilter(field_name="message", lookup_expr='contains')
    details = filters.CharFilter(field_name="details", lookup_expr='contains')
    severity = filters.CharFilter(field_name="severity", lookup_expr='exact')
    datetime = filters.DateTimeFilter(field_name="datetime", lookup_expr='contains')
    has_seen = filters.BooleanFilter(field_name='has_seen', lookup_expr='exact')

    class Meta:
        model = Notification
        fields = ['source', 'item', 'message', 'details', 'severity', 'datetime', 'has_seen']
