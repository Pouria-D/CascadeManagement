from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response

from entity_app import views
from utils.urls import sub_router

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'addresses', views.AddressViewSet, base_name='address')
router.register(r'services', views.ServiceViewSet, base_name='service')
router.register(r'schedules', views.ScheduleViewSet, base_name='schedule')
router.register(r'applications', views.ApplicationViewSet, base_name='application')
router.register(r'country-codes', views.CountryCodeViewSet, base_name='country-code')


class EntityViewSet(viewsets.ViewSet):
    def list(self, request):
        urls = sub_router(router, request)
        return Response(urls)
