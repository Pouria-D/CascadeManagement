from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from auth_app.utils import get_client_ip
from firewall_input_app.models import InputFirewall
from firewall_input_app.tests import FirewallInputTest
from firewall_input_app.utils import apply_rule
from utils.log import log
from utils.utils import run_thread
from vpn_app.filters import VPNFilter
from vpn_app.models import VPN, l2VPNServer, l2VPNBridge
from vpn_app.serializers import VPNRealSerializer, VPNWriteSerializer, VPNReadSerializer, l2VPNServerSerilizer, \
    l2VPNBridgeSerilizer, VPNChangesSerializer
from vpn_app.utils import delete_vpn, restart_vpn


class VPNViewSet(viewsets.ModelViewSet):
    queryset = VPN.objects.all()
    http_method_names = ['post', 'get', 'put', 'delete', 'patch']

    filter_class = VPNFilter
    search_fields = ('name', 'description', 'is_enabled', 'phase1_encryption_algorithm',
                     'phase1_authentication_algorithm', 'phase1_diffie_hellman_group', 'phase1_lifetime',
                     'phase2_encryption_algorithm', 'phase2_authentication_algorithm', 'phase2_diffie_hellman_group',
                     'phase2_lifetime', 'local_network__name', 'local_endpoint__value_list', 'local_endpoint__name'
                     , 'local_id', 'remote_network__name', 'remote_endpoint__name',
                     'remote_endpoint__value_list', 'peer_id', 'authentication_method', 'preshared_key', 'dpd',
                     'tunnel__type', 'tunnel__virtual_local_endpoint__name', 'tunnel__virtual_remote_endpoint__name',
                     'tunnel__mtu', 'tunnel__mode', 'tunnel__server_endpoint__name', 'tunnel__service_protocol',
                     'tunnel__service_port', 'tunnel__real_local_endpoint__name',
                     'tunnel__real_local_endpoint__value_list',
                     'tunnel__real_remote_endpoint__name', 'tunnel__real_remote_endpoint__value_list')
    ordering_fields = '__all__'
    ordering = ('id',)

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return VPNWriteSerializer

        real = self.request.query_params.get('real', None)
        if real:
            return VPNRealSerializer
        else:
            return VPNReadSerializer

    def list(self, request, *args, **kwargs):
        response = super(VPNViewSet, self).list(request, *kwargs, **kwargs)
        log('vpn', 'vpn', 'list', 'success', username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(VPNViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('vpn', 'vpn', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        request_username = None
        if request and hasattr(request, 'user'):
            request_username = request.user.username
        vpn = self.get_object()
        if vpn.is_enabled:
            vpn.last_operation = 'delete'
            vpn.status = 'pending'
            vpn.save()

            run_thread(target=delete_vpn, name='vpn_{}'.format(vpn.id), args=(vpn, request_username))

        serializer = VPNChangesSerializer(vpn)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        log('vpn', 'vpn', 'delete', 'success',
            username=request_username, ip=get_client_ip(request), details=details)
        vpn.status = 'failed'
        vpn.save()
        vpn.delete()

        if not VPN.objects.filter(is_enabled=True) and InputFirewall.objects.filter(service_list__exact=['ipsec']):
            InputFirewall.objects.filter(service_list__exact=['ipsec']).delete()
            apply_rule(None, None)

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['patch', 'post', 'put'])
    def restart(self, request, pk=None, *args, **kwargs):
        vpn = VPN.objects.get(id=pk)
        vpn.last_operation = 'restart'
        vpn.status = 'pending'
        vpn.save()

        request_username = None
        if request and hasattr(request, 'user'):
            request_username = request.user.username

        restart_vpn(vpn, request_username)

        if vpn.status == 'pending':
            print("the status remained pending, try to fail it!")
            vpn.status = 'failed'
            vpn.save()

        details = {
            'items': {
                'id': vpn.id,
                'name': vpn.name
            }
        }
        log('vpn', 'vpn', 'restart', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        return Response(status=status.HTTP_200_OK)


class l2VPNServerViewSet(viewsets.ModelViewSet):
    queryset = l2VPNServer.objects.all()
    serializer_class = l2VPNServerSerilizer
    lookup_field = 'cascade_name'
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']

    # def destroy(self, request, *args, **kwargs):
    #     type_connection = request['type_connection']
    #     vpnserver_interface = request['vpnserver_interface']
    #     cascade_name = request['cascade_name']
    #
    #     delete_file = L2VPNServerDeleteFile(type_connection, vpnserver_interface, cascade_name)
    #     delete_file.delete_config_file()


class l2VPNBridgeViewSet(viewsets.ModelViewSet):
    queryset = l2VPNBridge.objects.all()
    serializer_class = l2VPNBridgeSerilizer
    lookup_field = 'cascade_name'
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']

