from rest_framework import viewsets, status
from rest_framework.response import Response

from auth_app.utils import get_client_ip
from diagnosis_app.models import Diagnosis
from diagnosis_app.serializers import DiagnosisSerializer
from utils.log import log
from utils.utils import stop_thread


class DiagnosisViewSet(viewsets.ModelViewSet):
    queryset = Diagnosis.objects.all()
    serializer_class = DiagnosisSerializer
    search_fields = ('name', 'type', 'remote_endpoint_report', 'local_host_report', 'remote_host_report')
    # ordering_fields = '__all__'
    ordering = ('id',)
    http_method_names = ['get', 'put', 'post', 'delete', 'patch']

    def list(self, request, *args, **kwargs):
        response = super(DiagnosisViewSet, self).list(request, *kwargs, **kwargs)
        log('diagnosis', 'diagnosis_report', 'list', 'success', username=request.user.username,
            ip=get_client_ip(request))
        return response

    def destroy(self, request, *args, **kwargs):
        request_username = None
        if request and hasattr(request, 'user'):
            request_username = request.user.username

        instance = self.get_object()

        serializer = DiagnosisSerializer(instance)
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }

        instance.status = 'succeeded'
        instance.last_operation = 'delete'
        instance.save()
        instance.delete()

        log('diagnosis', 'diagnosis_report', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        # return super(DiagnosisViewSet, self).destroy(request, *kwargs, **kwargs)

        return Response(status=status.HTTP_204_NO_CONTENT)

    # stop by patch
    def partial_update(self, request, pk=None, *args, **kwargs):
        stop_thread()
        instance = Diagnosis.objects.get(id=pk)
        serializer = DiagnosisSerializer(instance, data=request.data,
                                         partial=True)  # set partial=True to update a data partially

        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }

        try:
            # if serializer.is_valid():
            #     serializer.save()

            instance.status = 'stopped'
            instance.last_operation = 'stop'
            instance.save()

            log('diagnosis', 'diagnosis_report', 'stop', 'success',
                username=request.user.username, ip=get_client_ip(request), details=details)
            return Response(status=status.HTTP_200_OK)

        except Exception as e:

            log('diagnosis', 'diagnosis_report', 'stop', 'fail',
                username=request.user.username, ip=get_client_ip(request), details=str(e))
            return Response({'content': "error in stop : {}".format(details)}, status.HTTP_400_BAD_REQUEST)

    # @action(detail=True, methods=['patch', 'put'])
    # def stop(self, request, pk=None, *args, **kwargs):
    #     print(request.data)
    #
    #     request_username = None
    #     if request and hasattr(request, 'user'):
    #         request_username = request.user.username
    #     instance = Diagnosis.objects.get(id=pk)
    #     instance.last_operation = 'stop'
    #     instance.status = 'stopped'
    #     instance.save()
    #
    #     stop_thread(True)
    #     flag = kill_command_runner()
    #
    #     serializer = DiagnosisSerializer(instance)
    #     # details = {
    #     #     'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
    #     # }
    #     # log('vpn', 'vpn', 'delete', 'success',
    #     #     username=request_username, ip=get_client_ip(request), details=details)
    #
    #     print(instance.status)
    #     if instance == 'pending':
    #         instance.status = 'stopped'
    #         instance.save()
    #
    #     return Response(status=status.HTTP_200_OK)

# class IPTablesView(APIView):
#     def get(self, request, *args, **kwargs):
#
#         command = 'iptables -nvL'
#
#         t = request.query_params.get('t', None)
#         if t == 'nat':
#             command += ' -t nat'
#
#         s, o = sudo_runner(command)
#         if not s:
#             raise serializers.ValidationError(o)
#
#         return Response(o.split('\n'))
#
#
# class SyslogView(APIView):
#     def get(self, request, *args, **kwargs):
#         s, o = sudo_runner('cat /var/log/syslog')
#         if not s:
#             raise serializers.ValidationError(o)
#
#         return Response(o.split('\n'))
#
#
# class APILogView(APIView):
#     def get(self, request, *args, **kwargs):
#         s, o = sudo_runner('cat /var/log/api.log')
#         if not s:
#             raise serializers.ValidationError(o)
#
#         return Response(o.split('\n'))
#
#
# class RootRunnerLogView(APIView):
#     def get(self, request, *args, **kwargs):
#         s, o = sudo_runner('cat /var/log/root_runner.log')
#         if not s:
#             raise serializers.ValidationError(o)
#
#         return Response(o.split('\n'))
#
#
# class IPSecView(APIView):
#     def get(self, request, *args, **kwargs):
#         s, o = sudo_runner('ipsec statusall')
#         if not s:
#             raise serializers.ValidationError(o)
#
#         return Response(o.split('\n'))
