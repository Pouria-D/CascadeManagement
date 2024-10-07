import os

from django.http import JsonResponse
from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from api.settings import BACKUP_DIR
from config_app.models import Setting
from root_runner.utils import command_runner


def get_version():
    status, version = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
        os.path.join(BACKUP_DIR, 'currentversion.yml')))

    if status:
        return version


def http_get_version(request):
    from utils.system_info import SystemInfo
    data = {
        'version': get_version(),
        'host_name': getattr(SystemInfo, 'get_{}'.format('hostname'))()
    }
    return JsonResponse(data)


@api_view(['GET'])
@permission_classes((permissions.AllowAny,))
def http_get_login_message(request):
    try:
        login_message = Setting.objects.get(key='login-message').data['value']
    except Setting.DoesNotExist:
        return Response(status=status.HTTP_423_LOCKED)

    data = {
        'login-message': login_message
    }
    return JsonResponse(data)
