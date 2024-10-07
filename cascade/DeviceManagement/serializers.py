from rest_framework import serializers
from DeviceManagement.models import Device
from django.contrib.auth.models import User
from utils.serializers import SingleIPSerializer, ping
#from fqdn import FQDN

class DeviceSerializer(serializers.ModelSerializer):

    owner = serializers.ReadOnlyField(source='owner.username')
    

    # Validation of name :
    def validate_name(self, value):
        if '\n' in value or '\t' in value or ' ' in value:
            raise serializers.ValidationError('Device name should not contain white space characters')
        if len(value) < 5:
            raise serializers.ValidationError('More than 5 character is required.')

        return value

    # Valdation of IP :
    def validate_ip(self, value):

        address = value.strip()

    #    if not FQDN(address).is_valid and not SingleIPSerializer(data={'ip': address}).is_valid():
        if not SingleIPSerializer(data={'ip': address}).is_valid():
            raise serializers.ValidationError('Enter a valid IP address.')

        return value
    # Validation of port input :
    def validate_port(self, value):
        if value :
            port = value.strip()
            if port:
                if int(port) > 65535 or int(port) < 0:
                    raise serializers.ValidationError('Port must be less than 65535')
        return value
    class Meta:
        model = Device
        #fields = ['id', 'name', 'owner', 'ip', 'address', 'port']
        #read_only_fields = ['status']
        fields = '__all__'


    def create(self, validated_data):
        instance = super(DeviceSerializer, self).create(validated_data)
        instance.status = ping(instance.ip)
        instance.save()
        return instance
    
    def update(self, instance, validated_data):
        instance = super(DeviceSerializer, self).update(instance, validated_data)
        instance.status = ping(instance.ip)
        instance.save()
        return instance

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'username']


class ChangePasswordSerializer(serializers.Serializer):
    model = User
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
