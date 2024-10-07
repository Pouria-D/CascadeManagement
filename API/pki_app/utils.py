import re

from auth_app.utils import get_client_ip
from pki_app.models import PKI
from report_app.utils import create_notification
from root_runner.sudo_utils import sudo_runner
from root_runner.utils import command_runner, file_reader, file_writer
from utils.config_files import PKI_DIR, SSL_CERT_RSYSLOG_CA_FILE, CA_CERT_VPN_FILE
from utils.log import log

days = '365'


def get_info_from_cert(file, key, type):
    info_list = []
    try:
        if type != 'certificate_request':
            status, result = command_runner('openssl x509 -in {} -text -noout'.format(file))
        else:
            status, result = command_runner('openssl req -text -noout -verify -in {}'.format(file))
        if status:
            if key in ['Issuer', 'Subject']:
                res = re.search('{}:\s*(.*)'.format(key), result).group(1)
                res_list = res.split(', ')
                for info in res_list:
                    if info.split('=')[0] == 'CN':
                        info_list.append({'common_name': info.split('=')[1]})
                    if info.split('=')[0] == 'C':
                        info_list.append({'country': info.split('=')[1]})
                    if info.split('=')[0] == 'ST':
                        info_list.append({'state': info.split('=')[1]})
                    if info.split('=')[0] == 'L':
                        info_list.append({'city': info.split('=')[1]})
                    if info.split('=')[0] == 'O':
                        info_list.append({'organization_name': info.split('=')[1]})
                    if info.split('=')[0] == 'OU':
                        info_list.append({'organization_unit': info.split('=')[1]})
    except:
        info_list = []
    return info_list


def get_raw_subject_from_cert(file, type):
    if type != 'certificate_request':
        status, result = command_runner('openssl x509 -in {} -text -noout'.format(file))
    else:
        status, result = command_runner('openssl req -text -noout -verify -in {}'.format(file))
    if status:
        return re.search('Subject:\s*(.*)', result).group(1)
    return ''


def get_expire_date_from_cert(cert_file):
    expire_date = ''
    try:
        status, result = command_runner('openssl x509 -in {} -text -noout'.format(cert_file))
        if status:
            expire_date = re.search('\s*Not After\s*:\s*(.*)', result).group(1)
    except:
        expire_date = ''
    return expire_date


def create_subject(instance):
    subject = ''

    for item in instance.data:
        if 'country' in item and item['country']:
            subject += '/C={}'.format(item['country'])
        if 'state' in item and item['state']:
            subject += '/ST={}'.format(item['state'])
        if 'city' in item and item['city']:
            subject += '/L={}'.format(item['city'])
        if 'organization_name' in item and item['organization_name']:
            subject += '/O={}'.format(item['organization_name'])
        if 'organization_unit' in item and item['organization_unit']:
            subject += '/OU={}'.format(item['organization_unit'])
        if 'common_name' in item and item['common_name']:
            subject += '/CN={}'.format(item['common_name'])
        if 'days' in item and item['days']:
            global days
            days = item['days']
    return subject


def add_CA_to_system_certificates(instance):
    # RSYSLOG
    content = file_reader(SSL_CERT_RSYSLOG_CA_FILE)
    if content:
        content += '\n{}'.format(instance.certificate)
        file_writer(SSL_CERT_RSYSLOG_CA_FILE, content, 'w+')
    # VPN
    if not instance.is_uploaded:
        cert_path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
    else:
        cert_path = '{}/{}/ca_{}.crt'.format(PKI_DIR, instance.type, instance.name)
    sudo_runner('cp {} {}'.format(cert_path, CA_CERT_VPN_FILE))


def remove_CA_from_system_certificates(instance):
    # RSYSLOG
    content = file_reader(SSL_CERT_RSYSLOG_CA_FILE)
    if content:
        ss = content.replace('{}'.format(instance.certificate), '')
        # ss = re.sub(instance.certificate, '', content)
        file_writer(SSL_CERT_RSYSLOG_CA_FILE, ss, 'w+')

    # VPN
    sudo_runner('rm {}ca_cert_{}.crt'.format(CA_CERT_VPN_FILE, instance.name))


def create_local_ca_certificate(instance, request_username=None, request=None, details=None):
    try:
        command_runner('mkdir {}/{}'.format(PKI_DIR, instance.type))
        private_key_path = '{}/{}/ca_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
        # create root key
        status, result = command_runner('openssl genrsa -out {} 4096'.format(private_key_path))
        if status:
            s, instance.private_key = command_runner('cat {}'.format(private_key_path))

            # Create and self sign the Root Certificate
            subject = create_subject(instance)
            cert_path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)

            status, o = command_runner('openssl req -x509 -new -subj "{subj}" -nodes -key {private_key}'
                                    ' -sha256 -days {days} -out {certificate}'.format(subj=subject,
                                                                                      private_key=private_key_path,
                                                                                      certificate=cert_path,
                                                                                      days=days))
            if status:
                s, instance.certificate = command_runner('cat {}'.format(cert_path))
                PKI.objects.filter(default_local_ca=True).update(default_local_ca=False)
                instance.default_local_ca = True
                instance.status = 'succeeded'
                instance.save()
                add_CA_to_system_certificates(instance)
                log('pki', instance.type, 'add', 'success',
                    username=request_username, ip=get_client_ip(request), details=details)
                return
        raise Exception
    except Exception as e:
        print(e)
        instance.private_key = ''
        instance.certificate = ''
        instance.status = 'failed'
        instance.save()
        create_notification(source='pki', item={},
                            message=str('Error in adding Local Certificate Authority'), severity='e',
                            request_username=request_username)
        log('pki', instance.type, 'add', 'fail',
            username=request_username, ip=get_client_ip(request), details=details)


def create_certificate(instance, request_username=None, request=None, details=None):
    try:
        command_runner('mkdir {}/{}'.format(PKI_DIR, instance.type))
        private_key_path = '{}/{}/cert_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
        # create root key
        status, result = command_runner('openssl genrsa -out {} 2048'.format(private_key_path))
        if status:
            s, instance.private_key = command_runner('cat {}'.format(private_key_path))

            # Create and self sign the Root Certificate

            subject = create_subject(instance)
            csr_path = '{}/temp_csr_{}.csr'.format(PKI_DIR, instance.name)
            command_runner('openssl req -new -sha256 -key {private_key} -subj "{subj}" '
                                    ' -out {csr}'.format(subj=subject,
                                                         private_key=private_key_path,
                                                         csr=csr_path))
            root_ca_name = PKI.objects.get(type='local_certificate_authority', default_local_ca=True).name
            root_ca_private_key_path = '{}/local_certificate_authority/ca_private_{}.key'.format(PKI_DIR, root_ca_name)
            root_ca_cert_path = '{}/local_certificate_authority/ca_cert_{}.crt'.format(PKI_DIR, root_ca_name)

            cert_path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)

            status, o = command_runner(
                'openssl x509 -req -in {csr} -CA {root_ca_cert_path} -CAkey {root_ca_private_key_path}'
                ' -CAcreateserial -out {cert_path} -days {days} -sha256'.format(csr=csr_path,
                                                                                root_ca_private_key_path=root_ca_private_key_path,
                                                                                root_ca_cert_path=root_ca_cert_path,
                                                                                cert_path=cert_path,
                                                                                days=days))

            if status:
                s, instance.certificate = command_runner('cat {}'.format(cert_path))
                sudo_runner('rm -rf {}'.format(csr_path))
                instance.local_certificate_authority = PKI.objects.filter(default_local_ca=True)[0]
                instance.status = 'succeeded'
                instance.save()
                log('certificate', 'certificate', 'add', 'success',
                    username=request_username, ip=get_client_ip(request), details=details)
                return
        raise Exception
    except Exception as e:
        print(e)
        instance.private_key = ''
        instance.certificate = ''
        instance.status = 'failed'
        instance.save()
        create_notification(source='Certificate', item={},
                            message=str('Error in adding Certificate'), severity='e',
                            request_username=request_username)
        log('certificate', 'certificate', 'add', 'fail',
            username=request_username, ip=get_client_ip(request), details=details)


def create_certificate_request(instance, request_username=None, request=None, details=None):
    try:
        command_runner('mkdir {}/{}'.format(PKI_DIR, instance.type))
        private_key_path = '{}/{}/csr_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
        # create root key
        status, result = command_runner('openssl genrsa -out {} 2048'.format(private_key_path))
        if status:
            s, instance.private_key = command_runner('cat {}'.format(private_key_path))

            # Create and self sign the Root Certificate
            subject = create_subject(instance)
            csr_path = '{}/{}/csr_{}.csr'.format(PKI_DIR, instance.type, instance.name)
            status, o = command_runner('openssl req -new -sha256 -key {private_key} -subj "{subj}" '
                                    ' -out {csr}'.format(subj=subject,
                                                         private_key=private_key_path,
                                                         csr=csr_path))

            if status:
                s, instance.certificate_request = command_runner('cat {}'.format(csr_path))
                instance.status = 'succeeded'
                instance.save()
                log('pki', instance.type, 'add', 'success',
                    username=request_username, ip=get_client_ip(request), details=details)
                return
        raise Exception
    except Exception as e:
        instance.private_key = ''
        instance.certificate_request = ''
        instance.status = 'failed'
        instance.save()
        create_notification(source='pki', item={},
                            message=str('Error in adding Certificate Signing Request'), severity='e',
                            request_username=request_username)
        log('pki', instance.type, 'add', 'fail',
            username=request_username, ip=get_client_ip(request), details=details)


def delete_local_ca_certificate(instance):
    private_key_path = '{}/{}/ca_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
    cert_path = '{}/{}/ca_cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
    sudo_runner('rm {}'.format(private_key_path))
    sudo_runner('rm {}'.format(cert_path))
    remove_CA_from_system_certificates(instance)


def delete_certificate_request(instance):
    private_key_path = '{}/{}/csr_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
    csr_path = '{}/{}/csr_{}.csr'.format(PKI_DIR, instance.type, instance.name)
    sudo_runner('rm {}'.format(private_key_path))
    sudo_runner('rm {}'.format(csr_path))


def delete_certificate(instance):
    private_key_path = '{}/{}/cert_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
    cert_path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)
    sudo_runner('rm {}'.format(private_key_path))
    sudo_runner('rm {}'.format(cert_path))


def import_certificate(instance, request_username=None, request=None, details=None):
    try:
        command_runner('mkdir {}/{}'.format(PKI_DIR, instance.type))
        private_key_path = '{}/{}/cert_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
        cert_path = '{}/{}/cert_{}.crt'.format(PKI_DIR, instance.type, instance.name)

        status, result = command_runner('echo \"{}\" > {} ; echo \"{}\" > {}'.format(
            instance.private_key, private_key_path, instance.certificate, cert_path))
        if status:
            instance.status = 'succeeded'
            instance.save()
            log('certificate', 'certificate', 'import', 'success',
                username=request_username, ip=get_client_ip(request), details=details)
            return
        raise Exception
    except Exception as e:
        print(e)
        instance.status = 'failed'
        instance.save()
        create_notification(source='Certificate', item={},
                            message=str('Error in importing Certificate'), severity='e',
                            request_username=request_username)
        log('certificate', 'certificate', 'import', 'fail',
            username=request_username, ip=get_client_ip(request), details=details)


def import_certificate_authority(instance, request_username=None, request=None, details=None):
    try:
        command_runner('mkdir {}/{}'.format(PKI_DIR, instance.type))
        private_key_path = '{}/{}/ca_private_{}.key'.format(PKI_DIR, instance.type, instance.name)
        cert_path = '{}/{}/ca_{}.crt'.format(PKI_DIR, instance.type, instance.name)

        status, result = command_runner('echo \"{}\" > {} ; echo \"{}\" > {}'.format(
            instance.private_key, private_key_path, instance.certificate, cert_path))
        if status:
            PKI.objects.filter(default_local_ca=True).update(default_local_ca=False)
            instance.default_local_ca = True
            instance.status = 'succeeded'
            instance.save()
            add_CA_to_system_certificates(instance)
            log('certificate', 'local_certificate_authority', 'import', 'success',
                username=request_username, ip=get_client_ip(request), details=details)
            return
        raise Exception
    except Exception as e:
        print(e)
        instance.status = 'failed'
        instance.save()
        create_notification(source='Certificate', item={},
                            message=str('Error in importing local certificate authority'), severity='e',
                            request_username=request_username)
        log('certificate', 'local_certificate_authority', 'import', 'fail',
            username=request_username, ip=get_client_ip(request), details=details)
