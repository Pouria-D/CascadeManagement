from rest_framework import serializers

from user_app.models import User, AccessTime, Group, Accounting, Membership


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'


class AccessTimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessTime
        fields = '__all__'


class AccountingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Accounting
        fields = '__all__'


class MembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Membership
        fields = '__all__'
