from django.contrib.humanize.templatetags.humanize import naturaltime
from rest_framework import serializers
from rest_framework import serializers as rest_serializers

from report_app.models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'


class NotificationReadSerializer(serializers.ModelSerializer):
    # name = serializers.SerializerMethodField()
    time_since = serializers.SerializerMethodField()

    def get_time_since(self, notification):
        return naturaltime(notification.datetime)

    # def get_name(self, notification):
    #     if notification.source == 'policy':
    #         policies = Policy.objects.filter(id=int(notification.item))
    #         if policies.exists():
    #             return policies[0].name
    #
    #     elif notification.source == 'interface':
    #         interfaces = Interface.objects.filter(id=int(notification.item))
    #         if interfaces.exists():
    #             return interfaces[0].name
    #
    #     elif notification.source == 'vpn':
    #         vpns = VPN.objects.filter(id=int(notification.item))
    #         if vpns.exists():
    #             return vpns[0].name
    #
    #     return None

    class Meta:
        model = Notification
        exclude = ('details',)
        # fields = '__all__'


class DHCPLeaseInfoSerializer(rest_serializers.Serializer):
    interface = serializers.CharField()
    lease_time = serializers.DateTimeField()
    mac_address = serializers.IPAddressField()
    ip_address = serializers.IPAddressField()
