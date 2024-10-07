from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.utils.translation import gettext as _
from rest_framework.compat import MaxValueValidator, MinValueValidator


class InputFirewall(models.Model):
    # ACTION_CHOISE = (
    #     ('accept', 'accept'),
    #     ('drop', 'drop'),
    # )
    # action = models.CharField(verbose_name='Action', max_length=6, null=True, blank=True, choices=ACTION_CHOISE)

    name = models.CharField(_('Name'), max_length=15)
    description = models.TextField(_('Description'), null=True, blank=True)

    is_enabled = models.BooleanField(_('Is enabled'), default=True)

    source = models.ForeignKey('Source', on_delete=models.CASCADE, related_name='+', null=True, blank=True)

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
        ('disabled', 'disabled'),
        ('unapplied', 'unapplied')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    STATUS_CHOICES = (
        ('admin', 'admin'),
        ('system', 'system'),
        ('hidden', 'hidden'),
    )

    permission = models.CharField(_('Permission'), max_length=10, choices=STATUS_CHOICES, default='admin')

    is_log_enabled = models.BooleanField(_('Is Log Enabled'), default=True)

    SERVICE_CHOICES = (
        ('web', 'https'),
        ('cli', 'ssh'),
        ('ping', 'ping'),
        ('ipsec', 'ipsec'),
        ('ha', 'ha'),
        ('dns', 'dns'),
        ('snmp', 'snmp'),
        ('ntp', 'ntp'),
        ('dhcp', 'dhcp')
    )

    service_list = ArrayField(
        models.CharField(choices=SERVICE_CHOICES, max_length=10, null=True, blank=True)
    )

    port = models.SmallIntegerField(_('service port'), blank=True, null=True)

    PROTOCOL_CHOICES = (

        ('udp', 'udp'),
        ('tcp', 'tcp')

    )
    protocol = models.CharField(_('protocol'), max_length=4, blank=True, null=True, choices=PROTOCOL_CHOICES)

    class Meta:
        verbose_name = 'Firewall Input'
        verbose_name_plural = 'Firewall Inputs'

    def __str__(self):
        return self.name


class Source(models.Model):
    src_interface_list = models.ManyToManyField('config_app.Interface', blank=True, related_name='+')

    src_network_list = models.ManyToManyField('entity_app.Address', blank=True, related_name='+')

    # src_geoip_country_list = models.ManyToManyField('entity_app.CountryCode', blank=True, related_name='+')


class Apply(models.Model):
    STATUS_CHOICES = (

        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
    )

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    time = models.PositiveSmallIntegerField(validators=[MaxValueValidator(100),
                                                        MinValueValidator(1)],
                                            verbose_name='Duration Time for Drop log', default=1)

    is_log_enabled = models.BooleanField(verbose_name='Is Log Enabled', default=False)

    unapplied_role = models.ManyToManyField('firewall_input_app.InputFirewall', blank=True)
