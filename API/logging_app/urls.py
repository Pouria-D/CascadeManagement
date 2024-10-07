from django.urls import path

from logging_app.views import FirewallLogView, VPNLogView, AdminLogView, GeneralLogView

urlpatterns = [
    path('vpn-logs', VPNLogView.as_view(), name='vpn-log'),
    path('firewall-logs', FirewallLogView.as_view(), name='firewall-log'),
    path('admin-logs', AdminLogView.as_view(), name='admin-log'),
    path('general-logs', GeneralLogView.as_view(), name='general-log'),

]
