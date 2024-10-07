import threading

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from auth_app.utils import get_client_ip
from firewall_app.filters import PolicyFilter
from firewall_app.models import Policy, NAT, PBR, QOS
from firewall_app.serializers import PolicySerializer, NATSerializer, PBRSerializer, PolicyReadSerializer, \
    PolicyRealSerializer, QOSSerializer
from parser_utils.mod_policy.policy import update_policy
from qos_utils.utils import apply_qos_policy
from report_app.models import Notification
from utils.log import log


class PolicyViewSet(viewsets.ModelViewSet):
    http_method_names = ['post', 'get', 'put', 'delete']

    filter_class = PolicyFilter
    search_fields = ('action', 'name', 'description', 'schedule__name',
                     'source_destination__src_interface_list__name',
                     'source_destination__dst_interface_list__name',
                     'source_destination__src_network_list__name',
                     'source_destination__dst_network_list__name',
                     'source_destination__service_list__name',
                     'source_destination__src_geoip_country_list__name',
                     'source_destination__dst_geoip_country_list__name',
                     'nat__name', 'nat__description', 'nat__nat_type', 'nat__snat_type', 'nat__ip',
                     'nat__port', 'qos__download_max_bw', 'qos__download_guaranteed_bw',
                     'qos__traffic_priority', 'qos__shape_type')

    ordering_fields = '__all__'

    def get_queryset(self):
        exclude_params = ['real', 'limit', 'offset', 'format']

        policy_list = Policy.objects.select_related(
            'source_destination',
            'nat',
            'pbr',
            'qos',
            'schedule',
            'nat__source_destination',
            'nat__schedule'
        ).prefetch_related(
            'source_destination__src_interface_list',
            'source_destination__dst_interface_list',
            'source_destination__src_network_list',
            'source_destination__dst_network_list',
            'source_destination__src_geoip_country_list',
            'source_destination__dst_geoip_country_list',
            'source_destination__service_list'
        ).all()

        for item in self.request.query_params:
            if item not in exclude_params:
                return policy_list

        all_policy_list = list(Policy.objects.filter(next_policy__isnull=False).values_list('next_policy', flat=True))
        first_policy = Policy.objects.only('id').exclude(id__in=all_policy_list)

        if first_policy:
            first_policy = first_policy[0]
        else:
            return Policy.objects.none()

        all_policy_list = list(Policy.objects.filter(next_policy__isnull=False).values_list('id', 'next_policy'))
        policy_dict = dict()

        for item in all_policy_list:
            policy_dict[item[0]] = item[1]

        sorted_policy = list()
        policy_id = first_policy.id

        while True:
            sorted_policy.append(policy_id)
            if policy_id not in policy_dict:
                sorted_policy.append(policy_id)
                break

            sorted_policy.append(policy_id)
            policy_id = policy_dict[policy_id]

        clauses = ' '.join(['WHEN firewall_app_policy.id=%s THEN %s' % (pk, i) for i, pk in enumerate(sorted_policy)])
        ordering = 'CASE %s END' % clauses

        queryset = policy_list.filter(pk__in=sorted_policy).extra(
            select={'ordering': ordering},
            order_by=('ordering',)
        )
        return queryset

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return PolicySerializer

        real = self.request.query_params.get('real', None)

        if real:
            return PolicyRealSerializer

        return PolicyReadSerializer

    def list(self, request, *args, **kwargs):
        response = super(PolicyViewSet, self).list(request, *kwargs, **kwargs)
        log('firewall', 'policy', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(PolicyViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('firewall', 'policy', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):

        policy = self.get_object()
        serializer = PolicyReadSerializer(policy)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        Notification.objects.filter(source='policy', item__id=policy.id).delete()
        if policy.is_enabled:
            request_username = None
            policy.last_operation = 'delete'
            policy.status = 'pending'
            policy.save()

            if request and hasattr(request, 'user'):
                request_username = request.user.username

            # delete_policy(policy, '', True, request_username)
            t = threading.Thread(target=self.iptables_delete, args=(policy, True, request_username, request, details))
            t.start()
        else:
            policy.delete()
            log('firewall', 'policy', 'delete', 'success',
                username=request.user.username, ip=get_client_ip(request), details=details)

        return Response(status=status.HTTP_204_NO_CONTENT)

    def iptables_delete(self, policy, delete_from_db, request_username, request=None, details=None):
        from parser_utils.mod_policy.policy import delete_policy
        from utils.utils import run_thread
        
        run_thread(delete_policy, name='policy_{}'.format(policy.id),
                   args=(policy, '', delete_from_db, request_username, False, request, details))

    @action(methods=['post', 'put', 'patch'], detail=True)
    def retry(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.last_operation = 'update'
        instance.status = 'pending'
        instance.save()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }

        t = threading.Thread(target=self.iptables_update,
                             args=(instance, instance, request.user.username, request, details))
        t.start()

        return Response(status=200)

    def iptables_update(self, old_policy, new_policy, request_username, request=None, changes=None):
        try:
            update_policy(old_policy, new_policy, request_username)
            log('firewall', 'policy', 'retry', 'success',
                username=request_username, ip=get_client_ip(request), details=changes)
        except Exception as e:
            log('firewall', 'policy', 'retry', 'fail',
                username=request_username, ip=get_client_ip(request), details={'error': str(e)})
            new_policy.status = 'failed'
            new_policy.save()
            raise e


class NATViewSet(viewsets.ModelViewSet):
    queryset = NAT.objects.all()
    serializer_class = NATSerializer


class PBRViewSet(viewsets.ModelViewSet):
    queryset = PBR.objects.all()
    serializer_class = PBRSerializer


class QOSViewSet(viewsets.ModelViewSet):
    queryset = QOS.objects.all()
    serializer_class = QOSSerializer



