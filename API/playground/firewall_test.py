import os
import sys

import django
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api.settings")
django.setup()

from entity_app.models import Address
from entity_app.serializers import AddressSerializer

Address.objects.filter(name__contains='net').delete()

serializer = AddressSerializer(
    data={'name': 'net', 'type': 'ip', 'value_list': ["10.10.10.1", "20.20.20.1-20.20.20.30"]})
assert serializer.is_valid()
address = serializer.save()

serializer = AddressSerializer(data={'name': 'net2', 'type': 'ip', 'value_list': ["10.2.10.1"]})
assert serializer.is_valid()
address2 = serializer.save()


def post_policy_with_source_destination(id):
    url = 'http://127.0.0.1/api/firewall/policies'
    data = {
        'source_destination': {
            'src_network_list': [],
            'dst_network_list': [address2.id],
            'service_list': [],
            'src_geoip_country_list': [],
            'dst_geoip_country_list': [],
            'src_interface_list': [1],
            'dst_interface_list': []
        },
        'action': 'accept',
        'name': str(id),
        'description': 'pol1',
        'is_enabled': True,
        'is_log_enabled': False,
        'is_ipsec': False,
        'schedule': None
    }

    response = requests.post(url, json=data)
    # print(response.content)
    # sleep(0.1)


for i in range(1, 1000):
    print(i)
    post_policy_with_source_destination(i)
