from rest_framework import viewsets, serializers

from auth_app.utils import get_client_ip
from pki_app.filters import PKIFilter
from pki_app.models import PKI
from pki_app.serializers import PKISerializer
from pki_app.utils import delete_local_ca_certificate, delete_certificate_request, delete_certificate
from utils.log import log


class PKIViewSet(viewsets.ModelViewSet):
    queryset = PKI.objects.all()
    serializer_class = PKISerializer
    http_method_names = ['get', 'put', 'post', 'delete', 'patch']
    filter_class = PKIFilter
    search_fields = ('name', 'description', 'type',)
    ordering = ('type',)

    def list(self, request, *args, **kwargs):
        response = super(PKIViewSet, self).list(request, *kwargs, **kwargs)
        log('pki', 'pki', 'list', 'success',
            username=request.user.username, ip=get_client_ip(request))
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super(PKIViewSet, self).retrieve(request, *kwargs, **kwargs)
        instance = self.get_object()
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }

        log('pki', 'pki', 'retrieve', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)
        return response

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if instance.default_local_ca:
            raise serializers.ValidationError('This Local certificate authority is root CA. for deleting this CA'
                                              ' you should first add a new Local certificate authority.')
        details = {
            'items': {
                'id': instance.id,
                'name': instance.name
            }
        }
        log('pki', instance.type, 'delete', 'success',
            username=request.user.username, ip=get_client_ip(request), details=details)

        if instance.type == 'local_certificate_authority':
            delete_local_ca_certificate(instance)
        elif instance.type == 'certificate_request':
            delete_certificate_request(instance)
        elif instance.type == 'certificate':
            delete_certificate(instance)

        response = super().destroy(request, *args, **kwargs)

        return response
