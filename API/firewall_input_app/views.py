import re

from requests import Response
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from auth_app.utils import get_client_ip
from firewall_input_app.filters import FirewallInputFilter
from firewall_input_app.models import InputFirewall, Apply, Source
from firewall_input_app.serializers import InputFirewallSerializer, ApplySerializer, InputFirewallReadSerializer
from firewall_input_app.utils import wait_until, apply_rule
from utils.log import log


class InputFirewallViewSet(viewsets.ModelViewSet):
    http_method_names = ['post', 'get', 'put', 'delete']
    filter_class = FirewallInputFilter
    search_fields = ('name', 'description', 'port', 'protocol', 'service_list', 'is_enabled',
                     'source__src_interface_list__name',
                     'source__src_network_list__name',

                     )

    ordering = ('id')

    def get_queryset(self):
        queryset = InputFirewall.objects.select_related(
            'source',

        ).prefetch_related(
            'source__src_interface_list',

            'source__src_network_list',

        ).all().order_by('id')

        return queryset

    def get_serializer_class(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return InputFirewallSerializer

        return InputFirewallReadSerializer

    def list(self, request, *args, **kwargs):
        response = super(InputFirewallViewSet, self).list(request, *kwargs, **kwargs)

        log('firewall', 'policy', 'list', 'success', username=request.user.username, ip=get_client_ip(request))

        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(InputFirewallViewSet, self).retrieve(request, *kwargs, **kwargs)
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
        serializer = InputFirewallSerializer(policy)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        request_username = None
        policy.last_operation = 'delete'
        policy.status = 'pending'
        policy.save()

        policy.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


    @action(detail=False, methods=['POST', 'DELETE'])
    def ha_firewall_input(self, *args, **kwargs):

        if self.request.method == 'POST':
            try:
                if not InputFirewall.objects.filter(port__exact='2224', protocol__exact='tcp', name__exact='HA1'):
                    source = Source.objects.create()
                    InputFirewall.objects.create(
                        name='HA1',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        protocol='tcp',
                        port='2224',
                        service_list='{ha}',
                        source=source
                    )
            except:
                pass

            try:
                if not InputFirewall.objects.filter(port__exact='3121', protocol__exact='tcp', name__exact='HA2'):
                    source = Source.objects.create()
                    InputFirewall.objects.create(
                        name='HA2',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        protocol='tcp',
                        port='3121',
                        service_list='{ha}',
                        source=source
                    )
            except:
                pass

            try:

                if not InputFirewall.objects.filter(port__exact='21064', protocol__exact='tcp', name__exact='HA3'):
                    source = Source.objects.create()
                    InputFirewall.objects.create(
                        name='HA3',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        protocol='tcp',
                        port='21064',
                        service_list='{ha}',
                        source=source
                    )
            except:
                pass

            try:
                if not InputFirewall.objects.filter(port__exact='5405', protocol__exact='udp', name__exact='HA4'):
                    source = Source.objects.create()
                    InputFirewall.objects.create(
                        name='HA4',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        protocol='udp',
                        port='5405',
                        service_list='{ha}',
                        source=source
                    )
            except:
                pass

            try:
                # this rule is for connecting peers.
                # because the link between the peers is dedicated we don't need to specify network list for this rule
                data = self.request.data.dict().__str__()
                ssh_port = re.search('"?ssh_port"?:\s*"?(\d+)"?', data).group(1)
                interface = re.search('"?interface"?:\s*"?(\w+)"?', data).group(1)
                if not InputFirewall.objects.filter(port__exact=ssh_port, protocol__exact='tcp', name__exact='HA5'):
                    source = Source.objects.create()
                    source.src_interface_list.set([interface])
                    InputFirewall.objects.create(
                        name='HA5',
                        is_log_enabled='False',
                        is_enabled='True',
                        permission='system',
                        service_list=['cli'],
                        source=source
                    )
            except Exception as e:
                print(e)
                pass

            apply_rule(None, None)

            return Response('open HA port')

        elif self.request.method == 'DELETE':
            InputFirewall.objects.filter(name='HA1', port__exact='2224').delete()
            InputFirewall.objects.filter(name='HA2', port__exact='3121').delete()
            InputFirewall.objects.filter(name='HA3', port__exact='21064').delete()
            InputFirewall.objects.filter(name='HA4', port__exact='5405').delete()
            InputFirewall.objects.filter(name='HA5', permission='system', service_list=['cli']).delete()
            apply_rule(None, None)
            return Response('close HA port')

    @action(detail=False, methods=['GET', 'POST'])
    def reset_firewall_input(self, *args, **kwargs):

        InputFirewall.objects.all().delete()
        apply_rule(None, None)
        return Response('firewall input reset')


class ApplyViewSet(viewsets.ModelViewSet):
    queryset = Apply.objects.all()
    serializer_class = ApplySerializer

    def list(self, request, *args, **kwargs):
        wait_until(3, period=0.25, *args, **kwargs)
        apply = Apply.objects.all()

        unapplied = InputFirewall.objects.filter(status='unapplied')
        for obj in apply:
            for unobj in unapplied:
                obj.unapplied_role.add(unobj)

        response = super(ApplyViewSet, self).list(request, *kwargs, **kwargs)
        return response
