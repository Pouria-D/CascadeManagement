from datetime import datetime

from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status, viewsets, serializers
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import api_view, action
from rest_framework.response import Response

from auth_app.models import AdminLoginLock, Token
from auth_app.utils import get_client_ip
#from config_app.models import Setting
#from config_app.serializers import SetPasswordSerializer
#from root_runner.sudo_utils import sudo_runner
#from utils.log import log


class ObtainExpiringAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):

        # delete login lock records created past days.
        AdminLoginLock.objects.filter(datetime_created__lt=timezone.now().date()).delete()

        try:
            admin_login_lock = AdminLoginLock.objects.get(ip=get_client_ip(request))
        except AdminLoginLock.DoesNotExist:
            admin_login_lock = AdminLoginLock.objects.create(ip=get_client_ip(request))
        except AdminLoginLock.MultipleObjectsReturned:
            AdminLoginLock.objects.filter(ip=get_client_ip(request)).delete()
            admin_login_lock = AdminLoginLock.objects.create(ip=get_client_ip(request))

       # try:
       #     max_login_attempts = int(Setting.objects.get(key='max-login-attempts').data['value'])
       # except Setting.DoesNotExist:
       #     return Response(status=status.HTTP_423_LOCKED)

        if admin_login_lock.num_of_retry >= max_login_attempts:
            return Response(status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']

            try:
                # update the created time of the token to keep it valid
                token = Token.objects.get(user=user, ip=get_client_ip(request))
                token.created = datetime.utcnow()
                token.save()
            except Token.DoesNotExist:
                # delete expired token related to this user
                token = Token.objects.create(user=user, ip=get_client_ip(request))

            #log('security', 'admin', 'login', 'success', username=user.username, ip=get_client_ip(request))

            return Response({'token': token.key})

        admin_login_lock.num_of_retry += 1
        admin_login_lock.save()

        #log('security', 'admin', 'login', 'fail', ip=get_client_ip(request))
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
def logout(request):
    if request.user.is_authenticated:
        Token.objects.filter(key=request.data['token']).delete()
        AdminLoginLock.objects.filter(ip=get_client_ip(request)).delete()
        #log('security', 'admin', 'logout', 'success', username=request.user.username, ip=get_client_ip(request))
        return HttpResponse(status=status.HTTP_204_NO_CONTENT)
    else:
        return HttpResponse(status=status.HTTP_403_FORBIDDEN)


