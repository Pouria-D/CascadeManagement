from django.db.models import Q
from rest_framework import viewsets, status, serializers
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from auth_app.utils import get_client_ip
from config_app.models import UpdateConfig
from entity_app.filters import AddressFilter, ServiceFilter, ScheduleFilter
from entity_app.models import Address, Service, Schedule, Application, CountryCode
from entity_app.serializers import AddressSerializer, ServiceSerializer, ScheduleSerializer, ApplicationSerializer, \
    CountryCodeSerializer
from firewall_app.models import NAT, Policy, PBR
from utils.log import log
from vpn_app.models import VPN


class AddressViewSet(viewsets.ModelViewSet):
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    filter_class = AddressFilter
    search_fields = ('name', 'description', 'type', 'value_list')
    ordering_fields = '__all__'
    ordering = ('id',)
    http_method_names = ['get', 'put', 'post', 'delete']

    def list(self, request, *args, **kwargs):
        response = super(AddressViewSet, self).list(request, *kwargs, **kwargs)
        log('entity', 'address', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(AddressViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('entity', 'address', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def delete(self, request):
        if not isinstance(request.data, list):
            raise serializers.ValidationError('data should be list of integers')

        for item in request.data:
            if not isinstance(item, int):
                raise serializers.ValidationError('data should be list of integers')

        Address.objects.filter(id__in=request.data).delete()
        return Response(status=204)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        result = dict()

        policy_list = Policy.objects.filter(
            Q(source_destination__src_network_list=instance) | Q(source_destination__dst_network_list=instance)) \
            .distinct('id')

        nat_list = NAT.objects.filter(
            Q(source_destination__src_network_list=instance) | Q(source_destination__dst_network_list=instance)) \
            .distinct('id')

        pbr_list = PBR.objects.filter(
            Q(source_destination__src_network_list=instance) | Q(source_destination__dst_network_list=instance)) \
            .distinct('id')

        vpn_list = VPN.objects.filter(
            Q(local_network=instance) | Q(remote_network=instance) | Q(remote_endpoint=instance) \
            | Q(local_endpoint=instance) | Q(tunnel__real_local_endpoint=instance) | Q(
                tunnel__real_remote_endpoint=instance) \
            | Q(tunnel__virtual_local_endpoint=instance) | Q(tunnel__virtual_remote_endpoint=instance)).distinct('id')
        if policy_list.exists():
            result['policy'] = [{'id': policy[0], 'name': policy[1]} for policy in
                                list(policy_list.values_list('id', 'name'))]

        if nat_list.exists():
            result['nat'] = [{'id': nat[0], 'name': nat[1]} for nat in list(nat_list.values_list('id', 'name'))]

        if pbr_list.exists():
            result['pbr'] = [{'id': pbr[0]} for pbr in list(pbr_list.values_list('id'))]

        if vpn_list.exists():
            result['vpn'] = [{'id': vpn[0], 'name': vpn[1]} for vpn in list(vpn_list.values_list('id', 'name'))]

        if result:
            details = {
                'items': {
                    'id': instance.id,
                    'name': instance.name
                }
            }
            log('entity', 'address', 'delete', 'fail',
                username=request.user.username, ip=get_client_ip(request), details=details)
            raise ValidationError({'error': 'This object has been used in one or more item(s).', 'items': result})

        serializer = AddressSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['is_user_defined']}
        }
        log('entity', 'address', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        instance.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.all().order_by('is_user_defined')
    serializer_class = ServiceSerializer
    filter_class = ServiceFilter
    search_fields = ('name', 'description', 'protocol')
    ordering_fields = '__all__'
    http_method_names = ['get', 'put', 'post', 'delete']

    def list(self, request, *args, **kwargs):
        response = super(ServiceViewSet, self).list(request, *kwargs, **kwargs)
        log('entity', 'service', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(ServiceViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('entity', 'service', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def delete(self, request):
        # TODO: handle possible errors
        Service.objects.filter(id__in=request.data).delete()
        return Response(status=204)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        result = dict()

        policy_list = Policy.objects.filter(source_destination__service_list=instance)

        if policy_list.exists():
            result['policy'] = [{'id': policy[0], 'name': policy[1]}
                                for policy in list(policy_list.values_list('id', 'name'))]

        if result:
            details = {
                'items': {
                    'id': isinstance.id,
                    'name': isinstance.name
                }
            }
            log('entity', 'service', 'delete', 'fail',
                username=request.user.username, ip=get_client_ip(request), details=details)
            raise ValidationError({'error': 'This object has been used in one or more item(s).', 'items': result})

        serializer = ServiceSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['is_user_defined']}
        }

        instance.delete()
        log('entity', 'service', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ScheduleViewSet(viewsets.ModelViewSet):
    queryset = Schedule.objects.all()
    serializer_class = ScheduleSerializer
    filter_class = ScheduleFilter
    search_fields = ('name', 'description', 'start_date', 'end_date', 'start_time', 'end_time')
    ordering_fields = '__all__'
    ordering = ('id',)
    http_method_names = ['get', 'put', 'post', 'delete']

    def list(self, request, *args, **kwargs):
        response = super(ScheduleViewSet, self).list(request, *kwargs, **kwargs)
        log('entity', 'schedule', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(ScheduleViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('entity', 'schedule', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        instance_id = kwargs['pk']
        instance = self.get_object()

        result = dict()

        policy_list = Policy.objects.filter(schedule__id=instance_id)
        nat_list = NAT.objects.filter(schedule__id=instance_id)
        update_config_list = UpdateConfig.objects.filter(schedule__id=instance_id)

        if policy_list.exists():
            result['policy'] = [{'id': policy[0], 'name': policy[1]}
                                for policy in list(policy_list.values_list('id', 'name'))]
        if nat_list.exists():
            result['nat'] = [{'id': nat[0], 'name': nat[1]} for nat in list(nat_list.values_list('id', 'name'))]

        if update_config_list.exists():
            result['update_config'] = []

        if result:
            details = {
                'items': {
                    'id': instance.id,
                    'name': instance.name
                }
            }
            log('entity', 'schedule', 'delete', 'fail',
                username=request.user.username, ip=get_client_ip(request), details=details)
            raise ValidationError({'error': 'This object has been used in one or more item(s).', 'items': result})

        serializer = ScheduleSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['is_user_defined']}
        }
        instance.delete()
        log('entity', 'schedule', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def delete(self, request):
        # TODO: handle possible errors
        Schedule.objects.filter(id__in=request.data).delete()
        return Response(status=204)


class ApplicationViewSet(viewsets.ModelViewSet):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer


class CountryCodeViewSet(viewsets.ModelViewSet):
    queryset = CountryCode.objects.all()
    http_method_names = ('get',)
    serializer_class = CountryCodeSerializer
    search_fields = ('name', 'code')
    ordering_fields = '__all__'
    ordering = ('id',)
