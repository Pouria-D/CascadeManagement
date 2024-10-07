from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

from firewall_app import views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'policies', views.PolicyViewSet, base_name='policy')


class FirewallViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))
