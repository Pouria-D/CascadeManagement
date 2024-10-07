from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.urls import resolve
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication, BaseAuthentication, TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from api.settings import IGNORE_SESSION_RENEW_URLS
from auth_app.models import Token
from root_runner.sudo_utils import sudo_pam_authenticate
from utils.log import log
from utils.utils import print_if_debug


class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # To not perform the csrf check previously happening


class IgnoreAuthForLocalhost(BaseAuthentication):
    def authenticate(self, request):
        ip = get_client_ip(request)
        if ip == '127.0.0.1':
            try:
                user = User.objects.get(username='admin')
            except User.DoesNotExist:
                user = User.objects.create_superuser(username='admin', email=None, password=None)
            try:
                User.objects.get(username='ngfw')
            except User.DoesNotExist:
                User.objects.create_superuser(username='ngfw', email=None, password=None)
            return user, None


def get_client_ip(request):
    if not request:  # Just for unit test
        print_if_debug('Request is None ...!')
        return

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    if request.META.get('SERVER_NAME') == 'localhost':
        ip = '127.0.0.1'
    return ip


class ExpiringTokenAuthentication(TokenAuthentication):
    request = None

    def authenticate(self, request):
        self.request = request
        return super(ExpiringTokenAuthentication, self).authenticate(request)

    def authenticate_credentials(self, key):
        from config_app.models import Setting

        try:
            token = Token.objects.get(key=key, ip=get_client_ip(self.request))
        except Token.DoesNotExist:
            log('security', 'admin', 'logout', 'invalid-session', ip=get_client_ip(self.request))
            raise AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            log('security', 'admin', 'logout', 'invalid-user', ip=get_client_ip(self.request))
            raise AuthenticationFailed('User inactive or deleted')

        now = timezone.now()
        admin_session_timeout = Setting.objects.get(key='admin-session-timeout').data['value']

        if token.created < now - timedelta(minutes=int(admin_session_timeout)):
            # Uncomment if token need to be renewed each time.
            token.delete()

            log('security', 'admin', 'logout', 'token-expired', ip=get_client_ip(self.request))
            raise AuthenticationFailed('Token has expired')

        else:
            url_name = resolve(self.request.path_info).url_name
            if url_name not in IGNORE_SESSION_RENEW_URLS:
                token.created = now
                token.save()

        return token.user, token


class PAMBackend:
    def authenticate(self, request, username=None, password=None):
        if not sudo_pam_authenticate(username, password):
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            if not getattr(settings, "PAM_CREATE_USER", True):
                return None
            user = User(username=username, password='not stored here')
            user.set_unusable_password()

            if getattr(settings, 'PAM_IS_SUPERUSER', False):
                user.is_superuser = True

            if getattr(settings, 'PAM_IS_STAFF', user.is_superuser):
                user.is_staff = True

            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
