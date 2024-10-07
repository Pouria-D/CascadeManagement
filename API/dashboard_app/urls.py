from django.urls import path

from dashboard_app.views import *

urlpatterns = [
    path('', main, name='dashboard-test-page'),
    # path('cpu', CPUViewSet.as_view(), name='cpu'),
    # path('disk', DiskViewSet.as_view(), name='disk'),
    # path('ram', RAMViewSet.as_view(), name='ram'),
    # path('network', NetworkViewSet.as_view(), name='network'),
    # path('interrupts', InterruptsViewSet.as_view(), name='interrupts'),
    # path('softirqs', SoftirqsViewSet.as_view(), name='softirqs'),
    # path('softnet', SoftnetViewSet.as_view(), name='softnet'),
    # path('uptime', UptimeViewSet.as_view(), name='uptime'),
    # path('packets', PacketsViewSet.as_view(), name='packets'),
    # path('error-packets', ErrorPacketsViewSet.as_view(), name='error-packets'),
    # path('tcp-connections', TCPConnectionsViewSet.as_view(), name='ptime'),
    # path('tcp-packets', TCPPacketsViewSet.as_view(), name='tcp-packets'),
    # path('udp-sockets', UDPSocketsViewSet.as_view(), name='udp-sockets'),
    # path('udp-packets', UDPPacketsViewSet.as_view(), name='udp-packets'),
    # path('firewall', FirewallViewSet.as_view(), name='firewall'),
    path('bandwidth', BandwidthViewSet.as_view(), name='bandwidth'),
    path('system-info', SystemInfoViewset.as_view(), name='system-info'),
]
