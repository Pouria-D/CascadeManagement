import json

import requests
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView

from auth_app.models import Token
from auth_app.utils import get_client_ip
from utils.system_info import SystemInfo

data = dict()


class BandwidthViewSet(APIView):

    def get(self, request):
        interface = self.request.GET.get('interface')
        req = requests.get('http://127.0.0.1:19999/api/v1/data?chart=net.{}'.format(interface))
        data['labels'] = json.loads(req.content.decode())["labels"]
        try:
            limit = int(self.request.GET.get('limit'))
        except:
            data['data'] = json.loads(req.content.decode())["data"]
            return Response(data)
        else:
            data['data'] = json.loads(req.content.decode())["data"][0:limit]
            return Response(data)


def main(request):
    token = Token.objects.create(user_id=1, ip=get_client_ip(request)).key
    return render(request, 'test_dashboard_ws.html', {'token': token})


class SystemInfoViewset(APIView):
    http_method_names = ['get']

    def get(self, *args, **kwargs):
        item = self.request.query_params.get('item')

        if item:
            result = getattr(SystemInfo, 'get_{}'.format(item))()
            return Response(result)


        result = dict()
        system_info = []

        for item in ['hostname', 'uptime', 'servertime', 'timezone','last_login_ip', 'last_login_time',
                         'serial_number', 'token_number',
                         'release_version', 'module_list']:

            key = dict()
            key_str = item
            key['display_name'] = key_str.replace('hostname', 'Host Name').replace('release_version', 'Release Version')\
                .replace('serial_number', 'Serial Number') .replace('servertime', 'Server Time').replace('uptime', 'Uptime')\
                .replace('token_number', 'Token Number').replace('timezone', 'Timezone').replace('last_login_ip', 'Last Login IP')\
                .replace('last_login_time', 'Last Login Time')

            key['value'] = getattr(SystemInfo, 'get_{}'.format(item))()
            key['key'] = item
            system_info.append(key)
            result['system_info'] = system_info

        return Response(result)
