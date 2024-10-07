from django.urls import path

from dashboard_app import consumers

websocket_urlpatterns = [
    path('ws/dashboard/cpu', consumers.CPUPercentConsumer),

]
