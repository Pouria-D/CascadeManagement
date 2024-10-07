from rest_framework import routers
from rest_framework import viewsets
from rest_framework.response import Response
from collections import OrderedDict
from rest_framework.reverse import reverse_lazy
import auth_app.views


router = routers.DefaultRouter(trailing_slash=False)
#router.register('admin', auth_app.views.AdminViewSet, base_name='admin')


class AuthViewSet(viewsets.ViewSet):
    def list(self, request):
      return Response(sub_router(router, request))



def sub_router(router, request):
    url_names = list()
    for item in router.urls:
        if '-list' in item.name and '/' not in str(item.pattern):
            url_names.append({
                "pattern": str(item.pattern)[1:-1],
                "name": item.name
            })

    api_sub_root = OrderedDict()
    for item in url_names:
        api_sub_root[item['pattern']] = reverse_lazy(item['name'], request=request)

    return api_sub_root
