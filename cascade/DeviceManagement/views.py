from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from DeviceManagement.models import Device
from DeviceManagement.serializers import DeviceSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import Http404
from rest_framework.views import APIView
from rest_framework import generics
from django.contrib.auth.models import User
from DeviceManagement.serializers import UserSerializer
from rest_framework import permissions
from DeviceManagement.permissions import IsOwnerOrReadOnly
from rest_framework.reverse import reverse
from rest_framework import renderers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import viewsets, mixins, status
from rest_framework.request import Request
from .serializers import ChangePasswordSerializer
from rest_framework.permissions import IsAuthenticated
from django.views.generic import TemplateView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework import filters
#from django_filters import rest_framework as DRFfilters
from django_filters.rest_framework import DjangoFilterBackend
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
#import websocket

# Create your views here.
"""
class AboutView(TemplateView):
    template_name = "about.html"
"""

"""class DeviceFilter(DRFfilters.FilterSet):
    class Meta:
        model = Device
        fields = ('name', 'ip', 'port', 'status', 'address', 'created', 'id', 'owner', 'url')
class DeviceSearch(filters.):
    class Meta:
        model = Device
        fields = 
"""
#@method_decorator(login_required, name='dispatch')
class DeviceViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, `retrieve`,
    `update` and `destroy` actions.

    Additionally we also provide an extra `highlight` action.
    """
    
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    """
    from websocket import create_connection
    ws = create_connection("ws://127.0.0.1:8000")
    ws.send("Hello, World")
    """
    channel_layer = get_channel_layer()
   # channel_name = get_channel_name()
    #channel_layer.group_add("DeviceManagement")
    
    """
    async_to_sync(channel_layer.group_send)("notification", {
        "type": "notification.new",
        "record": "test cibn"
    })
    """
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
   # http_method_names = ['get', 'put', 'post', 'delete', 'patch']
    filter_backends = (filters.SearchFilter, DjangoFilterBackend)
    #filterset_class = DeviceFilter
    search_fields = ('name', 'ip', 'port', 'status', 'address', 'created', 'id', 'owner__username', 'Description')
    filter_fields = ('name', 'ip', 'port', 'status', 'address', 'created', 'id', 'owner', 'Description')
    
    #new WebSocket((window.location.protocol == 'http') ? 'ws://' : 'ws://' +  window.location.host + '/remote/Devices/' )
    """
    ws = new WebSocket((window.location.protocol == 'http') ? 'ws://' : 'ws://' +  window.location.host + '/remote/Devices/' )
    // Make it show an alert when a message is received
    ws.onmessage = function(message) {
    alert(message.data);
    }
    // Send a new message when the WebSocket opens
    ws.onopen = function() {
        ws.send('Hello, world');
    }
    """
    #permission_classes = [permissions.IsAuthenticatedOrReadOnly,
    #                     IsOwnerOrReadOnly]
    permission_classes = [IsAuthenticated]
    """
    const statusSocket = new WebSocket(
            'ws://'
            + window.location.host
            + '/ws/Devices/'
        )

    statusSocket.onmessage = function(e) {
        const data = JSON.parse(e.data);
        document.querySelector('#chat-log').value += (data.message + '\n');
    }

    statusSocket.onclose = function(e) {
        console.error('Status socket closed unexpectedly');
    }
    """
    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

#@method_decorator(login_required, name='dispatch')
class UserViewSet(viewsets.ReadOnlyModelViewSet):
    # class UserViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list` and `detail` actions.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    #permission_classes = [permissions.IsAuthenticatedOrReadOnly,
    #                     IsOwnerOrReadOnly]
    permission_classes = [IsAuthenticated]
    #filter_backends = [filters.SearchFilter]
    #search_fields = ['username', 'email']
#@method_decorator(login_required, name='dispatch')
class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    #permission_classes = [permissions.IsAuthenticatedOrReadOnly,
    #                      IsOwnerOrReadOnly]
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

