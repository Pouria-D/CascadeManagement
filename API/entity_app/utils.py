from fqdn import FQDN
from rest_framework import serializers

from parser_utils.mod_policy.policy import update_policy
from utils.serializers import SingleIPSerializer
from utils.validators import mac_validator


class SubnetSerializer(serializers.Serializer):
    network_address = serializers.IPAddressField(required=True)
    mask = serializers.IntegerField(required=True, min_value=0, max_value=32)


class IPRangeSerializer(serializers.Serializer):
    start_ip = serializers.IPAddressField(required=True)
    end_ip = serializers.IPAddressField(required=True)


class MACSerializer(serializers.Serializer):
    mac = serializers.CharField(validators=(mac_validator,))


class PortSerializer(serializers.Serializer):
    port = serializers.IntegerField(min_value=0, max_value=65535)


class ProtocolNumberSerializer(serializers.Serializer):
    port = serializers.IntegerField(min_value=0, max_value=254)


class TypeCodeSerializer(serializers.Serializer):
    port = serializers.IntegerField(min_value=0, max_value=255)


class PortRangeSerializer(serializers.Serializer):
    def validate(self, data):
        if data['start_port'] > data['end_port']:
            raise serializers.ValidationError('Insert a correct range port. End port should be greater than start port')
        return data

    start_port = serializers.IntegerField(min_value=0, max_value=65535)
    end_port = serializers.IntegerField(min_value=0, max_value=65535)


def check_address_validation(addresses, type):
    if type == 'ip':
        for addr in addresses:
            addr = addr.strip()
            if '-' in addr:
                ip_range_serializer = IPRangeSerializer(
                    data={'start_ip': addr.split('-')[0], 'end_ip': addr.split('-')[1]})
                if not ip_range_serializer.is_valid():
                    return ip_range_serializer.errors

            elif '/' in addr:
                subnet_serializer = SubnetSerializer(
                    data={'network_address': addr.split('/')[0], 'mask': addr.split('/')[1]})
                if not subnet_serializer.is_valid():
                    return subnet_serializer.errors

            else:
                ip_serializer = SingleIPSerializer(data={'ip': addr})
                if not ip_serializer.is_valid():
                    return ip_serializer.errors

    elif type == 'mac':
        for addr in addresses:
            addr = addr.strip()
            mac_serializer = MACSerializer(data={'mac': addr})
            if not mac_serializer.is_valid():
                return mac_serializer.errors

    elif type == 'fqdn':
        for addr in addresses:
            addr = addr.strip()
            if not FQDN(addr).is_valid:
                return {
                    "fqdn": [
                        "Enter a valid FQDN address."
                    ]
                }

    return True


def bulk_update_policy_list(policy_list, request_user=None):
    for policy in policy_list:
        update_policy(policy, policy, request_user)
