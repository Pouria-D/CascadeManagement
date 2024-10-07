import os
import re

from django.http import HttpResponse
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response

from config_app import models
from update_app.models import Update
from update_app.serializers import UpdateSerializer

UPDATE_KEY_DIR = '/var/ngfw/'


class UpdateViewSet(viewsets.ModelViewSet):
    queryset = Update.objects.all()
    serializer_class = UpdateSerializer

    def list(self, request, *args, **kwargs):

        try:
            avalible_update = models.Update.objects.filter(status='completed').last()
            if not Update.objects.filter(new_version=avalible_update.version):
                Update.objects.create(
                    new_version=avalible_update.version,
                    file='/var/ngfw/narin.v{}.tar.xz.enc.gpg'.format(avalible_update.version),
                    key='/var/ngfw/narin.v{}.tar.xz.key.enc'.format(avalible_update.version),
                    description=avalible_update.description,
                    status='ready'

                )

            current_customer_version = request.query_params.get('previous_version')
            update = None
            if not current_customer_version:
                queryset = Update.objects.all().order_by('-id')
                serializer = UpdateSerializer(queryset, many=True)
                return Response(serializer.data)

            try:
                search_res = re.search("\d+\.\d+\.\d+\.\d+-?(.*)", current_customer_version)
                if search_res:
                    if search_res.group(1):
                        update = Update.objects.filter(new_version__icontains=search_res.group(1)).order_by(
                            '-new_version')
                    else:
                        update = Update.objects.all().order_by('-new_version')
                if update:
                    update = update[0]
                    if update.new_version == current_customer_version or update.status != "ready":
                        return Response(status=status.HTTP_204_NO_CONTENT)

            except Update.DoesNotExist:
                return Response(status=status.HTTP_204_NO_CONTENT)
            except Exception:
                return Response(status=status.HTTP_204_NO_CONTENT)

            serializer = UpdateSerializer(update)
            return Response(serializer.data)

        except:
            return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['GET', 'POST'], detail=True)
    def file(self, *args, **kwargs):

        instance = self.get_object()

        if self.request.method == 'GET':
            if not instance.file:
                return Response('Update has no file.', status=status.HTTP_404_NOT_FOUND)

            fsock = open('/var/ngfw/narin.v{}.tar.xz.enc.gpg'.format(instance.new_version), "rb")
            response = HttpResponse(fsock, content_type='application/pgp-encrypted')
            response['Content-Disposition'] = 'attachment; filename=narin.v{}.tar.xz.enc.gpg'.format(
                instance.new_version)

            return response

    @action(methods=['GET'], detail=True)
    def key(self, request, *args, **kwargs):
        token_number = (request.query_params.get('token_number'))

        instance = self.get_object()

        if self.request.method == 'GET':
            if not instance.file:
                return Response('Update has no Key.', status=status.HTTP_404_NOT_FOUND)

            fsock = open('/var/ngfw/narin.v{}.tar.xz.key.enc'.format(instance.new_version), "rb")
            response = HttpResponse(fsock, content_type='application/pgp-encrypted')
            response['Content-Disposition'] = 'attachment; filename=narin.{}.tar.xz.key.enc'.format(
                instance.new_version)

            return response


@api_view(['GET'])
def public_key(request):
    with open(os.path.join('installer', 'keys', 'narin-update-public.key')) as f:
        content = f.read()

    return HttpResponse(content)
