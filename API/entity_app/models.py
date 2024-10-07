from django.contrib.postgres.fields import JSONField
from django.db import models
from django.utils.translation import gettext as _

from config_app.models import UpdateConfig
from firewall_app.models import Policy, NAT
from utils.validators import alphanumeric_validator


class Address(models.Model):
    name = models.CharField(_('Name'), max_length=20, unique=True, validators=[alphanumeric_validator])
    description = models.CharField(_('Description'), blank=True, null=True, max_length=80)
    TYPE_CHOICES = (
        ('ip', 'IP Address'),
        ('mac', 'MAC Address'),
        ('fqdn', 'FQDN')
    )
    type = models.CharField(_('Type'), max_length=4, choices=TYPE_CHOICES)
    value_list = JSONField(_('List of addresses'), unique=True)  # ["10.10.10.1", "20.20.20.1-20.20.20.30"]
    is_user_defined = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Address')
        verbose_name_plural = _('Addresses')


class Service(models.Model):
    """This is a example of this model:
      "name": "service55",
      "description": null,
      "is_visible": "True",
      "protocol": {
          "tcp": {"src": ["82-92"], "dst": ["8432"]},
          "udp": {"src": ["8432"], "dst": ["8432"]}
      }"""

    name = models.CharField(_('Name'), max_length=20, unique=True, validators=[alphanumeric_validator])
    description = models.CharField(_('Description'), blank=True, null=True, max_length=80)
    protocol = JSONField(_('Protocol'), null=True, blank=True)
    is_user_defined = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Service')
        verbose_name_plural = _('Services')


# class L4Protocol(models.Model):
#     src_port_list = models.TextField(null=True, blank=True)
#     dst_port_list = models.TextField(null=True, blank=True)


class Schedule(models.Model):
    name = models.CharField(_('Name'), max_length=20, unique=True, validators=[alphanumeric_validator])
    description = models.CharField(_('Description'), blank=True, null=True, max_length=80)
    start_date = models.DateField(_('Start date'), blank=True, null=True)
    end_date = models.DateField(_('End date'), blank=True, null=True)
    start_time = models.TimeField(_('Start time'), blank=True, null=True)
    end_time = models.TimeField(_('End time'), blank=True, null=True)
    days_of_week = JSONField(_('Days of week'))
    is_user_defined = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Schedule')
        verbose_name_plural = _('Schedules')
        unique_together = ('start_date', 'end_date', 'start_time', 'end_time', 'days_of_week')


class Application(models.Model):
    name = models.CharField(_('Name'), max_length=255, unique=True, validators=[alphanumeric_validator])
    description = models.TextField(_('Description'), blank=True, null=True)
    protocol = models.CharField(_('Protocol'), max_length=100)
    is_user_defined = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Application')
        verbose_name_plural = _('Applications')


class CountryCode(models.Model):
    code = models.CharField(max_length=2)
    name = models.CharField(max_length=100)
