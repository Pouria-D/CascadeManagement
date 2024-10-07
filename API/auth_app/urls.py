from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

import auth_app.views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
router.register('admin', auth_app.views.AdminViewSet, base_name='admin')


class AuthViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))
