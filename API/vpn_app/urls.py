from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

from utils.urls import sub_router
from vpn_app import views

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'site-to-sites', views.VPNViewSet, base_name='site-to-site')
router.register(r'layer2-vpn-server', views.l2VPNServerViewSet, base_name='layer2-vpn-server')
router.register(r'layer2-vpn-bridge', views.l2VPNBridgeViewSet, base_name='layer2-vpn-bridge')


class VPNURLViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))
