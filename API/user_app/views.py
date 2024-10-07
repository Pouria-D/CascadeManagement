from rest_framework import viewsets

from user_app.models import User, AccessTime, Group, Accounting, Membership
from user_app.serializers import UserSerializer, AccessTimeSerializer, GroupSerializer, AccountingSerializer, \
    MembershipSerializer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class GroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


class AccessTimeViewSet(viewsets.ModelViewSet):
    queryset = AccessTime.objects.all()
    serializer_class = AccessTimeSerializer


class AccountingViewSet(viewsets.ModelViewSet):
    queryset = Accounting.objects.all()
    serializer_class = AccountingSerializer


class MembershipViewSet(viewsets.ModelViewSet):
    queryset = Membership.objects.all()
    serializer_class = MembershipSerializer


