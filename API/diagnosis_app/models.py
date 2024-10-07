from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.utils.translation import gettext as _

from utils.validators import alphanumeric_validator


class Diagnosis(models.Model):
    name = models.CharField(_('Name'), max_length=20, unique=True, validators=[alphanumeric_validator])

    TYPE_CHOICES = (
        ('ping', 'Ping'),
        ('mtr', 'Mtr'),
        ('conntrack', 'Conntrack'),
        ('ram_cpu', 'RAM & CPU'),

    )

    type = ArrayField(
        models.CharField(choices=TYPE_CHOICES, max_length=10)
    )

    datetime = models.DateTimeField(_('Datetime'), auto_now_add=True)
    duration = models.IntegerField(_('Duration'), null=True, blank=True)

    remote_endpoint_report = models.GenericIPAddressField(_('Remote Endpoint'), null=True, blank=True)
    local_host_report = models.GenericIPAddressField(_('Local Host'), null=True, blank=True)
    remote_host_report = models.GenericIPAddressField(_('Remote Host'), null=True, blank=True)

    result = JSONField(_('Result'), null=True, blank=True)

    LAST_OPERATION_CHOICES = (
        ('add', 'add'),
        ('update', 'update'),
        ('delete', 'delete'),
        ('stop', 'stop')
    )
    last_operation = models.CharField(_('Last Operation'), max_length=7, null=True, blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('succeeded', 'succeeded'),
        ('disabled', 'disabled'),
        ('stopped', 'stopped')
    )
    status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    class Meta:
        verbose_name = _('Diagnosis Report')
        verbose_name_plural = _('Diagnosis Reports')
        # unique_together = (('type', 'port', 'protocol'),)
