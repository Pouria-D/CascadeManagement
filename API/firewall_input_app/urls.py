from rest_framework import routers, viewsets
from rest_framework.response import Response

from firewall_input_app import views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'inputpolicies', views.InputFirewallViewSet, base_name='input-policy')
router.register(r'apply', views.ApplyViewSet, base_name='apply')


class InputFirewallURLViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))
