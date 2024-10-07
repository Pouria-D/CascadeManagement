from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

from diagnosis_app import views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
# router.register('iptables', views.IPTablesView, base_name='iptables')
# router.register('syslog', views.SyslogView, base_name='syslog')
# router.register('api_log', views.SyslogView, base_name='api_log')
# router.register('root_runner_log', views.SyslogView, base_name='root-runner-log')
# router.register('ipsec', views.IPSecView, base_name='ipsec')
router.register(r'diagnosis_report', views.DiagnosisViewSet, base_name='diagnosis-report')


class DiagnosisURLViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))
