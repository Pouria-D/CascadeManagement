from django.urls import path
from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

from report_app import views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'notifications', views.NotificationViewSet, base_name='notification')


class ReportURLViewSet(viewsets.ViewSet):
    def list(self, request):
        return Response(sub_router(router, request))


urlpatterns = [
    path('', views.index, name='index'),
]
