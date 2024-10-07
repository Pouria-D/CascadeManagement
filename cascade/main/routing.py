from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import DeviceManagement.routing

application = ProtocolTypeRouter({

    # (http->django views is added by default)
    'websocket': AuthMiddlewareStack(
        URLRouter(
            DeviceManagement.routing.websocket_urlpatterns
        )
    ),
})