import base64
import uuid

from django.core.cache import caches
from rest_framework import views, response, serializers, status
from rest_framework.response import Response

from auth_app.models import AdminLoginLock
from auth_app.rest_captcha import captcha
from auth_app.rest_captcha import utils
from auth_app.rest_captcha.serializers import RestCaptchaSerializer
from auth_app.rest_captcha.settings import api_settings
from auth_app.utils import get_client_ip
from config_app.models import Setting

cache = caches[api_settings.CAPTCHA_CACHE]


class RestCaptchaView(views.APIView):
    authentication_classes = ()
    permission_classes = ()

    def get(self, request):
        try:
            admin_login_lock = AdminLoginLock.objects.get(ip=get_client_ip(request))
        except AdminLoginLock.DoesNotExist:
            admin_login_lock = AdminLoginLock.objects.create(ip=get_client_ip(request))

        try:
            max_login_attempts = int(Setting.objects.get(key='max-login-attempts').data['value'])
        except Setting.DoesNotExist:
            return Response({'message': 'please wait. Restore process is running', 'code': 'restore'}, status=400)

        if admin_login_lock.num_of_retry < max_login_attempts:
            raise serializers.ValidationError('You don\'t need to solve captcha :)')

        key = str(uuid.uuid4())
        value = utils.random_char_challenge(api_settings.CAPTCHA_LENGTH)
        cache_key = utils.get_cache_key(key)
        cache.set(cache_key, value, api_settings.CAPTCHA_TIMEOUT)

        # generate image
        image_bytes = captcha.generate_image(value)
        image_b64 = base64.b64encode(image_bytes)

        data = {
            api_settings.CAPTCHA_KEY: key,
            api_settings.CAPTCHA_IMAGE: image_b64,
            'image_type': 'image/png',
            'image_decode': 'base64'
        }
        return response.Response(data)

    def post(self, request):
        serializer = RestCaptchaSerializer(data=request.data)
        if not serializer.is_valid():
            raise serializers.ValidationError(serializer.errors)

        try:
            admin_login_lock = AdminLoginLock.objects.get(ip=get_client_ip(request))
        except AdminLoginLock.DoesNotExist:
            admin_login_lock = AdminLoginLock.objects.create(ip=get_client_ip(request))

        admin_login_lock.num_of_retry = 0
        admin_login_lock.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
