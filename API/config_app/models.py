import re

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields.jsonb import JSONField
from django.core.files.storage import FileSystemStorage
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models, transaction
from django.utils.translation import gettext as _
from rest_framework.authtoken.models import Token as RestToken

from api.settings import BACKUP_DIR
from report_app.models import Notification
from utils.validators import alphanumeric_validator, mac_validator

fs = FileSystemStorage(location=BACKUP_DIR)


class HighAvailability(models.Model):
    peer1_address = models.GenericIPAddressField(_('peer1 address'))
    peer2_address = models.GenericIPAddressField(_('peer2 address'))
    cluster_address_list = JSONField(_('cluster address'))
    configured_peer_interface_mac = JSONField(_('configured system'), null=True, blank=True)
    is_enabled = models.BooleanField(_('Is enabled'), default=True)
    description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('delete', 'delete'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)


class NaturalSortField(models.CharField):
    def __init__(self, for_field, *args, **kwargs):
        self.for_field = for_field
        kwargs.setdefault('db_index', True)
        kwargs.setdefault('editable', False)
        kwargs.setdefault('max_length', 255)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs['for_field'] = self.for_field
        return name, path, args, kwargs

    def pre_save(self, model_instance, add):
        return self.naturalize(getattr(model_instance, self.for_field))

    def naturalize(self, string):
        def naturalize_int_match(match):
            return '%08d' % (int(match.group(0)),)

        string = string.lower()
        string = string.strip()
        string = re.sub(r'\d+', naturalize_int_match, string)

        return string



class Interface(models.Model):
    mac = models.CharField(_('Mac address'), max_length=20, validators=(mac_validator,), blank=True, null=True)
    name = models.CharField(_('Name'), max_length=10, unique=True, validators=[alphanumeric_validator],
                            primary_key=True)
    name_sort = NaturalSortField(for_field='name', blank=True, null=True)
    description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
    alias = models.CharField(_('Alias'), max_length=10, unique=True, blank=True, null=True,
                             validators=[alphanumeric_validator])

    ip_list = JSONField(_('IP address list'), null=True, blank=True)  # [{'ip': '10.10.10.10', 'mask': '255.255.255.0'}]
    gateway = models.GenericIPAddressField(_('Gateway address'), null=True, blank=True)
    is_default_gateway = models.BooleanField(_('Is default gateway'), default=False)
    is_dhcp_enabled = models.BooleanField(_('Is DHCP enabled'), default=False)

    INTERFACE_TYPE_CHOICES = (
        ('WAN', _('WAN')),
        ('LAN', _('LAN'))
    )
    type = models.CharField(_('Type'), choices=INTERFACE_TYPE_CHOICES, max_length=3, default='LAN')
    is_enabled = models.BooleanField(_('Is enabled'), default=False)

    LINK_TYPE_CHOICES = (
        ('Ethernet', _('Ethernet')),
        ('PPPOE', _('PPPoE'))
    )
    link_type = models.CharField(_('Link type'), choices=LINK_TYPE_CHOICES, default='Ethernet', max_length=10)

    pppoe_username = models.CharField(_('PPPOE username'), max_length=255, null=True, blank=True,
                                      validators=[alphanumeric_validator])
    pppoe_password = models.CharField(_('PPPOE password'), max_length=255, blank=True, null=True)
    mtu = models.PositiveSmallIntegerField(default=1500)

    LAST_OPERATION_CHOICES = (
        ('save_in_db', 'Save in DB'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)
    qos_status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, default='disabled')
    download_bandwidth = models.PositiveIntegerField(_('Download bandwidth'), null=True, blank=True)
    upload_bandwidth = models.PositiveIntegerField(_('Upload bandwidth'), null=True, blank=True)

    INTERFACE_MODE_CHOICES = (
        ('interface', _('interface')),
        ('bridge', _('bridge')),
        ('vlan', _('vlan'))

    )
    mode = models.CharField(_('Mode'), choices=INTERFACE_MODE_CHOICES, max_length=10, default='interface')
    data = JSONField(_('Data'), null=True, blank=True)  # this field use for Bridge & VLAN

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _('Interface')
        verbose_name_plural = _('Interfaces')

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            Notification.objects.filter(source='interface', item__id=self.name).delete()
            super().delete(*args, **kwargs)

    def save(self, *args, **kwargs):

        if self.mode:

            if self.mode == 'vlan':
                self.name = '{0}.{1}'.format(self.data[0]['interface'][0], self.data[0]['vlan_id'])
        return super(Interface, self).save(*args, **kwargs)

# class WanInterfacePolicy(models.Model):

#     description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
#     interface = models.ForeignKey('Interface', related_name='multi_wan_interface', on_delete=models.CASCADE)
#     weight = models.PositiveIntegerField(_('weight (percent)'), default=100, blank=False)
#     # ??????? was in interface
#     is_enabled = models.BooleanField(_('enable'), default=True, blank=True)
#
#     class Meta:
#         verbose_name = _('WAN Link')
#         verbose_name_plural = _('WAN Links')

class StaticRoute(models.Model):
    name = models.CharField(_('Name'), max_length=100, unique=True, validators=[alphanumeric_validator])
    description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
    is_enabled = models.BooleanField(_('Is enabled'), default=True)
    # destination_ip_list = JSONField(
    #     _('Destination IP address list'))  # {"ip": "10.10.10.10", "mask": "255.255.255.0"}

    destination_ip = models.GenericIPAddressField(_('Destination IP'))
    destination_mask = models.CharField(_('Destination mask'), blank=True, null=True, max_length=255)

    interface = models.ForeignKey('Interface', verbose_name=_('Interface'),
                                  related_name='static_route', on_delete=models.CASCADE, blank=True, null=True)
    gateway = models.GenericIPAddressField(_('Gateway'))
    metric = models.PositiveIntegerField(_('Metric'), blank=True, null=True)

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('delete', 'delete'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _('Static route')
        verbose_name_plural = _('Static routes')

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            Notification.objects.filter(source='static_route', item__id=self.id).delete()
            super().delete(*args, **kwargs)


class DHCPServerConfig(models.Model):
    name = models.CharField(_('Name'), max_length=100, unique=True, validators=[alphanumeric_validator])
    description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
    is_enabled = models.BooleanField(_('Is enabled'), default=True)
    start_ip = models.GenericIPAddressField(_('Start IP address'), max_length=240)
    end_ip = models.GenericIPAddressField(_('End IP address'), max_length=240)
    subnet_mask = models.PositiveIntegerField(_('Subnet mask'), null=True, blank=True)
    exclude_ip_list = JSONField(_('Exclude IP address list'), null=True, blank=True)
    gateway = models.GenericIPAddressField(_('Gateway address'), max_length=240, blank=True, null=True)
    dns_server_list = JSONField(_('DNS server list'), blank=True, null=True)
    lease_time = models.PositiveIntegerField(_('Lease time'),
                                             validators=[MinValueValidator(2), MaxValueValidator(1000)],
                                             default=72)  # hour
    interface = models.ForeignKey('Interface', on_delete=models.CASCADE)
    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('delete', 'delete'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    class Meta:
        verbose_name = _('DHCP server configuration')
        verbose_name_plural = _('DHCP servers configuration')


class Backup(models.Model):
    file = models.FileField(_('File'), storage=fs, null=True, blank=True)
    description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
    datetime = models.DateTimeField(_('Datetime'), auto_now_add=True)
    version = models.CharField(_('Version'), max_length=100, null=True, blank=True)
    is_uploaded_by_user = models.BooleanField(default=False)
    LAST_OPERATION_CHOICES = (
        ('backup', 'backup'),
        ('restore', 'restore')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=7, null=True, blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, default='succeeded')

    class Meta:
        verbose_name = _('Backup')
        verbose_name_plural = _('Backups')

    def __str__(self):
        if self.file:
            return self.file.name

        return str(self.id)


class NTPConfig(models.Model):
    is_enabled = models.BooleanField(_('Is NTP enabled'), default=False)
    ntp_server_list = JSONField(_('NTP server address'), blank=True, null=True,
                                max_length=255)  # ['200.20.20.2', 'time.ir']

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=7, null=True, blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    class Meta:
        verbose_name = _('NTP configuration')
        verbose_name_plural = _('NTP configurations')


class UpdateConfig(models.Model):
    is_update_enabled = models.BooleanField(_('Update status'), default=False)
    update_server = models.CharField(_('Update server address'), blank=True, null=True, max_length=255)
    schedule = models.ForeignKey('entity_app.Schedule', blank=True, null=True, verbose_name=_('Schedule'),
                                 on_delete=models.CASCADE)

    is_offline = models.BooleanField(_('Is offline mode'), default=False)
    offline_file_update = models.FileField(_("Offline File Update"), storage=fs, default=None,
                                           null=True, blank=True, help_text=_("Upload files for offline update."))

    class Meta:
        verbose_name = _('Update configuration')
        verbose_name_plural = _('Update configurations')


class LogServer(models.Model):
    address = models.GenericIPAddressField(_('Address'), max_length=255)
    port = models.IntegerField(_('Port'))
    PROTOCOL_CHOICES = (
        ('udp', _('udp')),
        ('tcp', _('tcp'))
    )
    protocol = models.CharField(_('Protocol type'), choices=PROTOCOL_CHOICES, default='udp', max_length=3)
    SERVICE_CHOICES = (
        ('admin-log', 'admin-log'),
        ('vpn', 'vpn'),
        ('ssh', 'ssh'),
        ('firewall', 'firewall')
    )
    service_list = ArrayField(
        models.CharField(choices=SERVICE_CHOICES, max_length=10)
    )

    is_enabled = models.BooleanField(default=True)
    is_secure = models.BooleanField(_('Secure'), default=False)

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('update', 'update'),
        ('delete', 'delete')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=7, null=True, blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    class Meta:
        verbose_name = _('Log Server')
        verbose_name_plural = _('Log Servers')
        unique_together = (('address', 'port', 'protocol'),)

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            Notification.objects.filter(source='rsyslog', item__id=self.id).delete()
            super().delete(*args, **kwargs)


class Setting(models.Model):
    key = models.CharField(max_length=255, primary_key=True)
    data = JSONField(null=True, blank=True)
    display_name = models.TextField(null=True, blank=True)
    descriptions = models.TextField(null=True, blank=True)

    TYPE_CHOICES = (
        ('number', 'number'),
        ('bool', 'bool'),
        ('string', 'string'),
        ('certificate', 'certificate')
    )
    type = models.CharField(_('Type'), max_length=20, choices=TYPE_CHOICES, null=True, blank=True)
    order = models.IntegerField(default=0)
    category = models.TextField(null=False, blank=False, default="Other")

    def __str__(self):
        return self.key


class Hostname(models.Model):
    key = models.CharField(max_length=255, primary_key=True)
    data = JSONField(null=True, blank=True)
    display_name = models.TextField(null=True, blank=True)
    descriptions = models.TextField(null=True, blank=True)

    TYPE_CHOICES = (
        ('number', 'number'),
        ('bool', 'bool'),
        ('string', 'string'),
        ('certificate', 'certificate')
    )
    type = models.CharField(_('Type'), max_length=20, choices=TYPE_CHOICES, null=True, blank=True)
    order = models.IntegerField(default=0)
    category = models.TextField(null=False, blank=False, default="Other")

    def __str__(self):
        return self.key


class DNSRecord(models.Model):
    ip_address = models.GenericIPAddressField(_('ip_address'), max_length=255)
    hostname_list = JSONField(_('hostname_list'))

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('update', 'update'),
        ('delete', 'delete')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    # def delete(self, *args, **kwargs):
    #     request_username = None
    #     # if 'request' in self.context and hasattr(self.context['request'], 'user'):
    #     #     request_username = self.context['request'].user.username
    #     task = DNSRecordTask()
    #     task.apply_async((self.id, 'delete', None, None, request_username)).get(interval=0.01)
    #     super(DNSRecord, self).delete(*kwargs, **kwargs)

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            Notification.objects.filter(source='dns_record', item__id=self.id).delete()
            super().delete(*args, **kwargs)


class DNSConfig(models.Model):
    primary_dns_server = models.GenericIPAddressField(_('primary_dns_server'), max_length=255, blank=True, null=True)
    secondary_dns_server = models.GenericIPAddressField(_('secondary_dns_server'), max_length=255, blank=True,
                                                        null=True)
    tertiary_dns_server = models.GenericIPAddressField(_('tertiary_dns_server'), max_length=255, blank=True, null=True)
    local_domain = models.CharField(_('local_domain'), max_length=255, blank=True, null=True)
    interface_list = models.ManyToManyField('config_app.Interface', blank=True, related_name='+')
    is_strict_order = models.BooleanField(_('Is DNS servers in strict order'), default=True)
    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            Notification.objects.filter(source='dns_config', item__id=self.id).delete()
            super().delete(*args, **kwargs)


class SystemService(models.Model):
    name = models.CharField(max_length=100, primary_key=True)
    real_name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Update(models.Model):
    version = models.CharField(max_length=20, unique=True)
    STATUS_CHOICES = (
        ('available', 'available'),
        ('downloading', 'downloading'),
        ('downloaded', 'downloaded'),
        ('validating', 'validating'),
        ('validated', 'validated'),
        ('restore_point', 'restore_point'),
        ('installing', 'installing'),
        ('completed', 'completed'),
        ('rollback', 'rollback'),
        ('failed', 'failed')
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='available')
    description = models.TextField(blank=True, null=True)
    server_id = models.IntegerField()
    install_progress = models.IntegerField(default=100)
    update_log_flag = models.NullBooleanField(default=0)

    def __str__(self):
        return self.version


class Snmp(models.Model):
    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('update', 'update')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=20, choices=LAST_OPERATION_CHOICES, null=True,
                                      blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)
    description = models.TextField(_('Description'), blank=True, null=True, max_length=255)
    snmp_type = models.CharField(_("SNMP Type"), max_length=20, default="v3")  # {"v2" , v3"}
    community_name = models.CharField(_("Community Name"), max_length=255, blank=True, null=True, )
    is_enabled = models.BooleanField(_("Is_Enable"), default=True)
    allow_network = models.GenericIPAddressField(_("Allow Network"), blank=True, null=True, unique=True)
    # interface = models.ForeignKey('Interface', verbose_name=_('LAN Interface'), on_delete=None)

    SECURITY_LEVEL = (
        ('noauth', 'No Autentication,No Encryption'),
        ('auth', 'Autentication No Encryption '),
        ('priv', 'Authnetication Encryption ')
    )

    PRIVATE_ALGORITHM_CHOICES = (
        ("des", "DES"),
        ("aes", "AES")
    )
    AUTHENTICATION_ALGORITHM_CHOICES = (
        ("md5", "MD5"),
        ("sha", "SHA")

    )
    user_name = models.CharField(_('User Name'), max_length=30, blank=True, null=True, unique=True,
                                 validators=[alphanumeric_validator])
    security_level = models.CharField(_('Security Level'), choices=SECURITY_LEVEL, null=True, blank=True, max_length=30
                                      )
    private_algorithm = models.CharField(_('Encryption Algorithm'), choices=PRIVATE_ALGORITHM_CHOICES,
                                         max_length=20, blank=True, null=True)
    authentication_algorithm = models.CharField(_('Authentication Algorithm'), max_length=20,
                                                choices=AUTHENTICATION_ALGORITHM_CHOICES, blank=True, null=True)
    authentication_password = models.CharField(_("Authentication Password"), max_length=255, blank=True, null=True,
                                               validators=[alphanumeric_validator])
    private_password = models.CharField(_("Private Password"), max_length=255, blank=True, null=True,
                                        validators=[alphanumeric_validator])
