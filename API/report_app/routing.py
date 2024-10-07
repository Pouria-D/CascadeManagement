from django.urls import path

from dashboard_app.consumers import *
from report_app.consumers import *

websocket_urlpatterns = [
    path('ws/notifications', NotificationConsumer),
    path('ws/dashboard/cpu', CPUPercentConsumer),
    path('ws/dashboard/ram', RAMConsumer),
    path('ws/dashboard/system-io', SystemIOConsumer),
    path('ws/dashboard/network', NetworkConsumer),
    path('ws/dashboard/disk', DiskIOConsumer),
    path('ws/dashboard/interrupts', InterruptsConsumer),
    path('ws/dashboard/softirqs', SoftirqsConsumer),
    path('ws/dashboard/softnet', SoftnetConsumer),
    path('ws/dashboard/uptime', UptimeConsumer),
    path('ws/dashboard/packets', PacketsConsumer),
    path('ws/dashboard/error-packets', ErrorPacketsConsumer),
    path('ws/dashboard/tcp-connections', TCPConnectionsConsumer),
    path('ws/dashboard/tcp-packets', TCPPacketsConsumer),
    path('ws/dashboard/udp-sockets', UDPSocketsConsumer),
    path('ws/dashboard/udp-packets', UDPPacketsConsumer),
    path('ws/dashboard/firewall', FirewallConsumer),
    path('ws/dashboard/diskusage', DiskUsageConsumer),
    path('ws/dashboard/system-info', SystemInfoConsumers),
    path('ws/dashboard/is-master', HAMasterConsumer),
]
