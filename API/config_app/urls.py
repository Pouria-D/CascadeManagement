from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

from config_app import views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
router.register('interfaces', views.InterfaceViewSet, base_name='interface')
router.register('static_routes', views.StaticRouteViewSet, base_name='static-route')
router.register('dhcp_servers', views.DHCPServerConfigViewSet, base_name='dhcp-server')
router.register('backups', views.BackupViewSet, base_name='backup')
router.register('ntp', views.NTPConfigViewSet, base_name='ntp')
router.register('update_manager', views.UpdateConfigViewSet, base_name='update-manager')
router.register('log_servers', views.LogServerViewSet, base_name='log-server')
router.register('settings', views.SettingViewSet, base_name='setting')
router.register('dns_configs', views.DNSConfigViewSet, base_name='dns-config')
router.register('dns_records', views.DNSRecordViewSet, base_name='dns-record')
router.register('system_services', views.SystemServiceViewSet, base_name='system-service')
router.register('updates', views.UpdateViewSet, base_name='update')
router.register('snmp', views.SnmpViewset, base_name='snmp')
router.register('highavailability', views.HighAvailabilityViewSet, base_name='highavailability')


class ConfigViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))
