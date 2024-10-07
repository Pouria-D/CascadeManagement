from django.db import transaction
from rest_framework import serializers

from auth_app.utils import get_client_ip
from entity_app.models import CountryCode
from pki_app.models import PKI
from pki_app.utils import create_local_ca_certificate, create_certificate_request, create_certificate, \
    get_info_from_cert, get_expire_date_from_cert, import_certificate, import_certificate_authority, \
    get_raw_subject_from_cert
from root_runner.utils import command_runner
from utils.config_files import PKI_DIR
from utils.log import log
from utils.serializers import get_diff
from utils.utils import run_thread


class PKIChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PKI
        fields = '__all__'


class PKISerializer(serializers.ModelSerializer):
    fingerprint = serializers.SerializerMethodField()
    issuer = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    expire_date = serializers.SerializerMethodField()
    raw_subject = serializers.SerializerMethodField()

    class Meta:
        model = PKI
        fields = '__all__'
        # read_only_fields = ('private_key', 'certificate', 'certificate_request')

    @staticmethod
    def get_fingerprint(instance):
        algorithm_list = ['sha256', 'sha1', 'md5']
        fingerprint_list = []
        path = ''
        if instance.type == 'local_certificate_authority':
            path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate':
            path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate_request':
            path = '{}/{}/csr_{}.csr'.format(PKI_DIR, instance.type, instance.name)
        for algorithm in algorithm_list:
            status, fingerprint = command_runner(
                'openssl x509 -noout -fingerprint -{algorithm} -in {cert_file}'.
                    format(algorithm=algorithm, cert_file=path))
            if status:
                fingerprint_list.append({algorithm: fingerprint.split('=')[1]})
        return fingerprint_list

    @staticmethod
    def get_issuer(instance):
        path = ''
        if instance.type == 'local_certificate_authority':
            path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate':
            path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate_request':
            path = '{}/{}/csr_{}.csr'.format(PKI_DIR, instance.type, instance.name)
        issuer_list = get_info_from_cert(path, 'Issuer', instance.type)
        if issuer_list:
            common_name = ''
            for item in issuer_list:
                if item.__contains__('common_name'):
                    common_name = item
                    issuer_list.remove(item)
                    break
            issuer_list.insert(0, common_name)
        return issuer_list

    @staticmethod
    def get_subject(instance):
        path = ''
        if instance.type == 'local_certificate_authority':
            path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate':
            path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate_request':
            path = '{}/{}/csr_{}.csr'.format(PKI_DIR, instance.type, instance.name)
        subject_list = get_info_from_cert(path, 'Subject', instance.type)
        if subject_list:
            common_name = ''
            for item in subject_list:
                if item.__contains__('common_name'):
                    common_name = item
                    subject_list.remove(item)
                    break
            subject_list.insert(0, common_name)

        return subject_list

    @staticmethod
    def get_raw_subject(instance):
        path = ''
        if instance.type == 'local_certificate_authority':
            path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate':
            path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate_request':
            path = '{}/{}/csr_{}.csr'.format(PKI_DIR, instance.type, instance.name)
        raw_subject = get_raw_subject_from_cert(path, instance.type)

        return raw_subject

    @staticmethod
    def get_expire_date(instance):
        path = ''
        if instance.type == 'local_certificate_authority':
            path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        elif instance.type == 'certificate':
            path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
        return get_expire_date_from_cert(path)

    def validate(self, data):
        try:
            data['name'].encode(encoding='utf-8').decode('ascii')
        except UnicodeDecodeError:
            raise serializers.ValidationError('set a correct name')
        if ',' in data['name'] or '[' in data['name'] or ']' in data['name'] or ' ' in data['name'] or ':' in data[
            'name'] or '"' in data['name']:
            raise serializers.ValidationError(
                'name should not contain :, ", [, ] ,white space and comma characters')

        if self.instance and data['name'] != self.instance.name:
            raise serializers.ValidationError('The value of name cannot change.')

        if self.instance and data['data'] != self.instance.data:
            raise serializers.ValidationError('The value of data cannot change.')

        if self.instance and data['type'] != self.instance.type:
            raise serializers.ValidationError('The value of type cannot change.')

        if self.instance and self.instance.certificate \
                and data['certificate'] != self.instance.certificate:
            raise serializers.ValidationError('The value of certificate cannot change.')

        if self.instance and self.instance.certificate_request \
                and data['certificate_request'] != self.instance.certificate_request:
            raise serializers.ValidationError('The value of certificate request cannot change.')

        if self.instance and self.instance.private_key \
                and data['private_key'] != self.instance.private_key:
            raise serializers.ValidationError('The value of private key cannot change.')

        days = ''
        country = ''
        common_name = ''
        if 'data' in dict(data) and ('is_uploaded' not in data or not data['is_uploaded']):
            for item in data['data']:
                if 'days' in item and item.get('days'):
                    days = item.get('days')
                if 'country' in item and item.get('country'):
                    country = item.get('country')
                if 'common_name' in item and item.get('common_name'):
                    common_name = item.get('common_name')
            if not common_name:
                raise serializers.ValidationError('common name is required.')

            if country and not CountryCode.objects.filter(code=country):
                raise serializers.ValidationError('country not exist with this code')

            if dict(data).get('type') != 'certificate_request' and not days:
                raise serializers.ValidationError('Days field may not be blank.')

            if dict(data).get('type') == 'certificate' and \
                    not PKI.objects.filter(type='local_certificate_authority', default_local_ca=True).exists():
                raise serializers.ValidationError('You must at least have a Local Certificate Authority '
                                                  'for creating certificate.')
        if 'is_uploaded' in dict(data) and data['is_uploaded']:  # validate imported certificate
            if data['type'] == 'certificate' or data['type'] == 'local_certificate_authority':
                cert_file = '/tmp/__cert_file'
                private_key_file = '/tmp/__private_key_file'
                command_runner('echo \"{}\" > {}'.format(data['certificate'], cert_file))
                status, result = command_runner('openssl x509 -in {} -text -noout'.format(cert_file))
                if not status:
                    raise serializers.ValidationError('certificate is not valid.')
                if data['type'] == 'certificate' and 'CA:TRUE' in result:
                    raise serializers.ValidationError('certificate is not valid. This is a CA certificate.')
                if data['type'] == 'local_certificate_authority' and 'CA:TRUE' not in result:
                    raise serializers.ValidationError('certificate is not valid. This is not a CA certificate.')
                command_runner('echo \"{}\" > {}'.format(data['private_key'], private_key_file))
                status, result = command_runner('openssl rsa -in {} -check'.format(private_key_file))
                if not status:
                    raise serializers.ValidationError('private key is not valid.')
                s, result1 = command_runner(
                    'openssl x509 -noout -modulus -in {cert} | openssl md5'.format(cert=cert_file))
                s, result2 = command_runner(
                    'openssl rsa -noout -modulus -in {private_key} | openssl md5'.format(private_key=private_key_file))
                if result1 != result2:
                    raise serializers.ValidationError('private key and certificate mismatch.')
                command_runner('rm -rf {} {}'.format(cert_file, private_key_file))

        return data

    def create(self, validated_data):
        instance = super(PKISerializer, self).create(validated_data)
        command_runner('mkdir {}'.format(PKI_DIR))
        with transaction.atomic():
            instance.last_operation = 'add'
            instance.status = 'pending'
            instance.save()

        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        serializer = PKIChangeSerializer()
        details = {
            'items': {x: serializer.data[x] for x in serializer.data if x not in ['last_operation', 'status']}
        }
        if not instance.is_uploaded:
            if instance.type == 'local_certificate_authority':
                run_thread(target=create_local_ca_certificate, name='local_ca_cert_{}'.format(instance.name),
                           args=(instance, request_username, request, details))
            elif instance.type == 'certificate_request':
                run_thread(target=create_certificate_request, name='cert_request_{}'.format(instance.name),
                           args=(instance, request_username, request, details))
            elif instance.type == 'certificate':
                run_thread(target=create_certificate, name='cert_{}'.format(instance.name),
                           args=(instance, request_username, request, details))
        else:  # certificate and private key that are uploaded by user
            if instance.type == 'certificate':
                run_thread(target=import_certificate, name='import_cert_{}'.format(instance.name),
                           args=(instance, request_username, request, details))
            if instance.type == 'local_certificate_authority':
                run_thread(target=import_certificate_authority, name='import_ca_{}'.format(instance.name),
                           args=(instance, request_username, request, details))
        return instance

    def update(self, instance, validated_data):
        changes = get_diff(self.instance, PKIChangeSerializer, self.initial_data,
                           ['last_operation', 'status'])
        instance = super(PKISerializer, self).update(instance, validated_data)
        instance.last_operation = 'update'
        instance.status = 'succeeded'
        instance.save()
        request_username = None
        request = None
        if 'request' in self.context and hasattr(self.context['request'], 'user'):
            request_username = self.context['request'].user.username
            request = self.context['request']
        log('pki', instance.type, 'update', 'success',
            username=request_username, ip=get_client_ip(request), details=changes)
        return instance
