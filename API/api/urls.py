from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter

import dashboard_app.urls
from api import settings
from auth_app.rest_captcha.views import RestCaptchaView
from auth_app.urls import router as auth_router, AuthViewSet
from auth_app.views import ObtainExpiringAuthToken, logout
from config_app.urls import router as config_router, ConfigViewSet
from diagnosis_app.urls import router as diagnosis_router, DiagnosisURLViewSet
from entity_app.urls import router as entity_router, EntityViewSet
from firewall_app.urls import router as firewall_router, FirewallViewSet
from firewall_input_app.urls import InputFirewallURLViewSet
from firewall_input_app.urls import router as firewall_input_router
from pki_app.urls import router as pki_router
from pki_app.views import PKIViewSet
from report_app.urls import ReportURLViewSet, router as report_router
from report_app.views import DHCPLeasesInfoView
from update_app import views as updateAppView
from utils.version import http_get_version, http_get_login_message
from vpn_app.urls import router as vpn_router, VPNURLViewSet

router = DefaultRouter(trailing_slash=False)
router.register(r'entity', EntityViewSet, base_name='entity')
router.register(r'config', ConfigViewSet, base_name='config')
router.register(r'firewall', FirewallViewSet, base_name='firewall')
router.register(r'vpn', VPNURLViewSet, base_name='vpn')
# router.register(r'log', LogURLTa, base_name='log')
router.register(r'report', ReportURLViewSet, base_name='report')
router.register(r'auth', AuthViewSet, base_name='auth')
router.register(r'diagnosis', DiagnosisURLViewSet, base_name='diagnosis')
router.register(r'input-firewall', InputFirewallURLViewSet, base_name='input firewall')
router.register('updates', updateAppView.UpdateViewSet, base_name='update')
router.register(r'pki', PKIViewSet, base_name='pki')

urlpatterns = [

    path('api/public_key', updateAppView.public_key),
    path('api-token-auth/', ObtainExpiringAuthToken.as_view(), name='api-token-auth'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('api/auth/', include(auth_router.urls), name='auth-root'),
    path('api/entity/', include(entity_router.urls), name='entity-root'),
    path('api/diagnosis/', include(diagnosis_router.urls), name='diagnosis-root'),
    path('api/config/', include(config_router.urls), name='config-root'),
    path('api/firewall/', include(firewall_router.urls), name='firewall-root'),
    path('api/input-firewall/', include(firewall_input_router.urls), name='firewall-input-root'),
    path('api/dashboard/', include(dashboard_app.urls), name='dashboard-root'),
    path('api/vpn/', include(vpn_router.urls), name='vpn-root'),
    path('api/log/', include('logging_app.urls'), name='log-root'),
    path('api/report/', include(report_router.urls), name='report-root'),
    path('api/captcha/', RestCaptchaView.as_view(), name='rest_captcha'),
    path('api/version', http_get_version, name='get_version'),
    path('api/login-message', http_get_login_message, name='get_login_message'),
    path('api/', include(router.urls), name='api-root'),
    path('api/notification/', include('report_app.urls')),
    path('api/config/logout', logout),
    path('api/report/dhcp-leases-info', DHCPLeasesInfoView.as_view(), name='dhcp-leases-info'),
    path('api/pki/', include(pki_router.urls), name='pki'),
]

if settings.DEBUG:
    urlpatterns += [
        path('api/test/dashboard/', include('dashboard_app.urls')),
        # path('api/test/', include('diagnosis_app.urls'))
    ]

if settings.ADMIN_ENABLED:
    urlpatterns += [
        path('admin/', admin.site.urls),

    ]
    # urlpatterns = [path('__debug__/', include(debug_toolbar.urls)), ] + urlpatterns
    # urlpatterns += [path('api/silk/', include('silk.urls', namespace='silk'))]
