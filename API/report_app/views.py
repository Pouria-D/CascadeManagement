from django.shortcuts import render
from rest_framework import viewsets, permissions, serializers, status
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from auth_app.utils import get_client_ip
from config_app.models import Backup
from config_app.utils import dhcp_lease_information
from report_app.filters import NotificationFilter
from report_app.models import Notification
from report_app.serializers import NotificationSerializer, NotificationReadSerializer, DHCPLeaseInfoSerializer
from utils.log import log


class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    http_method_names = ['get', 'delete']
    ordering_fields = '__all__'
    ordering = ('id',)
    filter_class = NotificationFilter
    search_fields = ('source', 'item', 'message', 'details', 'severity', 'datetime', 'has_seen')

    def get_serializer_class(self):
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)("notification", {
            "type": "notification.new",
            "record": "test cibn"
        })

        if self.request.method not in permissions.SAFE_METHODS:
            return NotificationSerializer

        return NotificationReadSerializer

    def get_queryset(self):
        if Backup.objects.filter(status='pending', last_operation='restore'):
            raise serializers.ValidationError({'restore': 'System restore is in progress. Please wait ...'})

        queryset = Notification.objects.all()

        has_seen = self.request.query_params.get('has_seen', None)

        if has_seen == 'false':
            queryset = queryset.filter(has_seen=False)
        elif has_seen == 'true':
            queryset = queryset.filter(has_seen=True)

        return queryset

    @action(detail=False, methods=['get'])
    def mark_all_as_read(self, request):
        Notification.objects.filter(has_seen=False).update(has_seen=True)
        return Response(status=status.HTTP_200_OK)

    def get_object(self):
        obj = get_object_or_404(Notification, id=self.kwargs['pk'])

        Notification.objects.filter(id=self.kwargs['pk'], has_seen=False).update(has_seen=True)

        return obj

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        details = {
            'items': {
                'details': instance.details,
                'source': instance.source,
                'notification message': instance.message,
                'id': instance.id

            }
        }

        log('report', 'notification', 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class DHCPLeasesInfoView(APIView):
    http_method_names = ['get']

    def get(self, request, format=None):
        try:
            info_list = dhcp_lease_information()
            paginator = LimitOffsetPagination()
            get_data = request.query_params
            tmp_list = info_list.copy()

            if 'interface' in get_data and get_data['interface']:
                for info in info_list:
                    if not info['interface'].__contains__(get_data['interface'].strip()):
                        tmp_list.remove(info)
            info_list = tmp_list.copy()
            if 'ip_address' in get_data and get_data['ip_address']:
                for info in info_list:
                    if not info['ip_address'].__contains__(get_data['ip_address'].strip()):
                        tmp_list.remove(info)
            info_list = tmp_list.copy()
            if 'mac_address' in get_data and get_data['mac_address']:
                for info in info_list:
                    if not info['mac_address'].__contains__(get_data['mac_address'].strip()):
                        tmp_list.remove(info)
            info_list = tmp_list.copy()

            result_page = paginator.paginate_queryset(info_list, request)
            results = DHCPLeaseInfoSerializer(result_page, many=True, context={'request': request})
            data = {"count": info_list.__len__(), "next": None, "previous": None,
                    "results": results.data}
        except:
            data = None

        return Response(data, status=status.HTTP_200_OK)

    @classmethod
    def get_extra_actions(cls):
        return []


def index(request):
    return render(request, 'test_notification.html')
