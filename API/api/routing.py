from channels.routing import ProtocolTypeRouter, URLRouter

import report_app.routing
from auth_app.models import Token


def get_client_ip_from_websocket(scope):
    ip = '127.0.0.1'

    for item in scope['headers']:
        if b'x-forwarded-for' in item:
            ip = item[1].decode()

    return ip


class TokenAuthMiddleware:
    """
    Token authorization middleware for Django Channels 2
    """

    def __init__(self, inner):
        self.inner = inner

    def __call__(self, scope):
        if 'query_string' in scope and b'token' in scope['query_string']:
            try:
                query_params = scope['query_string'].decode().split('&')
                for item in query_params:
                    if '=' in item:
                        param_key, param_value = item.split('=')
                        if param_key == 'token':
                            token = Token.objects.get(key=param_value, ip=get_client_ip_from_websocket(scope))
                            scope['user'] = token.user
            except Token.DoesNotExist:
                pass

        return self.inner(scope)


application = ProtocolTypeRouter({
    # (http->django views is added by default)
    'websocket': TokenAuthMiddleware(
        URLRouter(report_app.routing.websocket_urlpatterns)
    ),
})
