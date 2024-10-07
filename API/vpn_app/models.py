import django
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models, transaction
from django.db.models.fields import PositiveSmallIntegerField
from django.utils.translation import gettext as _
from rest_framework import serializers

from report_app.models import Notification
from root_runner.sudo_utils import sudo_runner


class VPN(models.Model):
    name = models.CharField(_('Name'), max_length=15, unique=True)
    description = models.TextField(_('Description'), null=True, blank=True)
    is_enabled = models.BooleanField(_('Is Enabled'), default=True)

    ENCRYPTION_ALGORITHM_CHOICES = (
        ("paya256", "PAYA-256"),
        ("sabah256", "SABAH-256"),
        ("3des", "3DES"),
        ("aes128", "AES-128"),
        ("aes192", "AES-192"),
        ("aes256", "AES-256")
    )
    AUTHENTICATION_ALGORITHM_CHOICES = (
        ("md5", "MD5"),
        ("md5_128", "md5_128"),
        ("sha1", "sha1"),
        ("sha256", "sha256")
    )
    DIFFIE_HELLMAN_GROUP_CHOICES = (
        ("1", "DH768"),
        ("2", "DH1024"),
        ("5", "DH1536"),
        ("14", "DH2048"),
        ("15", "DH3072"),
        ("16", "DH4096")
    )
    phase1_encryption_algorithm = models.CharField(_('Phase1 Encryption Algorithm'), max_length=20,
                                                   choices=ENCRYPTION_ALGORITHM_CHOICES)
    phase1_authentication_algorithm = models.CharField(_('Phase1 Authentication Algorithm'), max_length=20,
                                                       choices=AUTHENTICATION_ALGORITHM_CHOICES)
    phase1_diffie_hellman_group = models.CharField(_('Phase1 Diffie Hellman Group'), max_length=2,
                                                   choices=DIFFIE_HELLMAN_GROUP_CHOICES)
    phase1_lifetime = models.PositiveIntegerField(_('Phase1 Lifetime'), validators=[MinValueValidator(1),
                                                                                    MaxValueValidator(999)])  # hour

    phase2_encryption_algorithm = models.CharField(_('Phase2 Encryption Algorithm'), max_length=20,
                                                   choices=ENCRYPTION_ALGORITHM_CHOICES)
    phase2_authentication_algorithm = models.CharField(_('Phase2 Authentication Algorithm'), max_length=20,
                                                       choices=AUTHENTICATION_ALGORITHM_CHOICES)
    phase2_diffie_hellman_group = models.CharField(_('Phase2 Diffie Hellman Group'), max_length=2,
                                                   choices=DIFFIE_HELLMAN_GROUP_CHOICES)
    phase2_lifetime = models.PositiveIntegerField(_('Phase2 Lifetime'), validators=[MinValueValidator(1),
                                                                                    MaxValueValidator(999)])

    local_network = models.ManyToManyField('entity_app.Address', related_name='+')
    local_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                       on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    local_id = models.CharField(_('Local ID'), max_length=100)

    remote_network = models.ManyToManyField('entity_app.Address', related_name='+')
    remote_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                        on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    peer_id = models.CharField(_('Peer ID'), max_length=100, unique=True)

    AUTHENTICATION_METHOD = (
        ('preshared', 'Preshared'),
        ('RSA', 'RSA')
    )

    authentication_method = models.CharField(_('Authentication Method'), max_length=15, choices=AUTHENTICATION_METHOD,
                                             default='preshared')
    preshared_key = models.CharField(_('Preshared Key'), max_length=30, blank=True, null=True)
    preshared_key_expire_date = models.DateTimeField(_('Preshared Key Expire Date'), null=True, blank=True)

    dpd = models.BooleanField(_('Dead Peer Detection'), default=True)
    is_on_demand = models.BooleanField(_('on demand'), default=False)

    is_backup_enabled = models.BooleanField(_('Backup tunnel'), default=False)
    local_endpoint_backup = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                              on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    remote_endpoint_backup = models.ForeignKey('entity_app.Address', blank=True, null=True,

                                               on_delete=django.db.models.deletion.SET_NULL, related_name='+')

    tunnel = models.OneToOneField('vpn_app.Tunnel', on_delete=models.CASCADE, null=True, blank=True)

    certificate = models.ForeignKey('pki_app.PKI', on_delete=django.db.models.deletion.SET_NULL, related_name='+',
                                    blank=True, null=True)

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('delete', 'delete'),
        ('update', 'update'),
        ('restart', 'restart')
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

    def delete(self, *args, **kwargs):
        with transaction.atomic():
            if self.tunnel:
                self.tunnel.delete()

            Notification.objects.filter(source='vpn', item__id=self.id).delete()

            super(VPN, self).delete(*args, **kwargs)


class Tunnel(models.Model):
    ENCAPSULATION_TYPE_CHOICES = (
        ('gre', 'GRE'),
        ('ipip', 'IPIP'),
        ('vtun', 'VTUN')
    )
    type = models.CharField(_('Encapsulation Type'), max_length=20, choices=ENCAPSULATION_TYPE_CHOICES)

    virtual_local_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                               on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    virtual_remote_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                                on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    mtu = PositiveSmallIntegerField(_('MTU'), default=1500, validators=[MinValueValidator(647),
                                                                        MaxValueValidator(1500)])

    # vtun
    ENCAPSULATION_MODE_CHOICES = (
        ('server', 'Server'),
        ('client', 'Client')
    )
    mode = models.CharField(_('VTUN Mode'), max_length=20, choices=ENCAPSULATION_MODE_CHOICES, blank=True, null=True)
    server_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                        on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    SERVICE_PROTOCOL_CHOICES = (
        ('tcp', 'TCP'),
        ('udp', 'UDP')
    )
    service_protocol = models.CharField(_('Service Protocol'), max_length=3, choices=SERVICE_PROTOCOL_CHOICES,
                                        blank=True, null=True)
    service_port = models.PositiveIntegerField(_('Service Port'), blank=True, null=True,
                                               validators=[MinValueValidator(1),
                                                           MaxValueValidator(65535)])

    # gre, ipip
    real_local_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                            on_delete=django.db.models.deletion.SET_NULL, related_name='+')
    real_remote_endpoint = models.ForeignKey('entity_app.Address', blank=True, null=True,
                                             on_delete=django.db.models.deletion.SET_NULL, related_name='+')

    def __str__(self):
        return '{}.{} {} -> {}'.format(self.id, self.type, self.virtual_local_endpoint, self.virtual_remote_endpoint)


class l2VPNServer(models.Model):
    cascade_name = models.CharField(_('Cascade Name'), max_length=50, unique=True)
    SERVICE_CHOICES = (
        ("tcp", "TCP"),
        ("udp", "UDP")
    )
    type_connection = models.CharField(_('Service Protocole'), max_length=5, choices=SERVICE_CHOICES, default="udp")
    vpnserver_interface = models.CharField(_('Local Bridge Interface'), max_length=20)

    def delete(self, *args, **kwargs):
        server_delete_file = open(
            "/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt".format(
                self.cascade_name, self.cascade_name), "w+")
        server_delete_file.write(
            "BridgeDelete VirtualHub_{} /DEVICE:{}\n".format(self.cascade_name, self.vpnserver_interface))
        server_delete_file.write("HubDelete VirtualHub_{}\n".format(self.cascade_name))
        server_delete_file.close()

        cmd1 = '/usr/local/vpnserver/vpncmd localhost /SERVER /PASSWORD:123456 /in:/usr/local/vpnserver/config/{}/server_configuration_file_{}.txt'.format(
            self.cascade_name, self.cascade_name)
        s, o = sudo_runner(cmd1)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t stop L2VPN'})

        cmd2 = 'rm -rf /usr/local/vpnserver/config/{}'.format(self.cascade_name)
        s, o = sudo_runner(cmd2)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t remove L2VPN Config files'})

        super(l2VPNServer, self).delete(*args, **kwargs)

    def __str__(self):
        return self.cascade_name


class l2VPNBridge(models.Model):
    cascade_name = models.CharField(_('Cascade Name'), max_length=50, unique=True)
    SERVICE_CHOICES = (
        ("tcp", "TCP"),
        ("udp", "UDP")
    )
    type_connection = models.CharField(_('Service Protocole'), max_length=5, choices=SERVICE_CHOICES, default="udp")
    vpnserver_ip = models.GenericIPAddressField(_('VPN Server IP'))
    vpnbridge_interface = models.CharField(_('Local Bridge Interface'), max_length=20)

    def delete(self, *args, **kwargs):
        bridge_delete_file = open(
            "/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt".format(
                self.cascade_name, self.cascade_name), "w+")
        bridge_delete_file.write(
            "BridgeDelete BRIDGE /DEVICE:{}\n".format(self.vpnbridge_interface))
        bridge_delete_file.write("Hub BRIDGE\n")
        bridge_delete_file.write("CascadeDelete TO_VPNServer\n")
        bridge_delete_file.close()

        cmd1 = '/usr/local/vpnbridge/vpncmd localhost /SERVER /PASSWORD:123456 /in:/usr/local/vpnbridge/config/{}/bridge_configuration_file_{}.txt'.format(
            self.cascade_name, self.cascade_name)
        s, o = sudo_runner(cmd1)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t stop L2VPN'})

        cmd2 = 'rm -rf /usr/local/vpnbridge/config/{}'.format(self.cascade_name)
        s, o = sudo_runner(cmd2)
        if not s:
            raise serializers.ValidationError({'non_field_errors': 'Can\'t remove L2VPN Config files'})

        super(l2VPNBridge, self).delete(*args, **kwargs)

    def __str__(self):
        return self.cascade_name
