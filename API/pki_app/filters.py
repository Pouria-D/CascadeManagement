from django_filters import rest_framework as filters

from pki_app.models import PKI


class PKIFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="name", lookup_expr='contains')
    description = filters.CharFilter(field_name="description", lookup_expr='contains')
    data = filters.CharFilter(field_name="data", lookup_expr='contains')
    type = filters.CharFilter(field_name="type", lookup_expr='contains')

    class Meta:
        model = PKI
        fields = ['name', 'description', 'data', 'type']
