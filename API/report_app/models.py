from django.contrib.postgres.fields.jsonb import JSONField
from django.db import models
from django.utils.translation import gettext as _


class Notification(models.Model):
    SOURCE_CHOICES = (
        ('interface', 'interface'),
        ('static_route', 'static_route'),
        ('policy', 'policy'),
        ('vpn', 'vpn'),
        ('service', 'service')
    )
    source = models.CharField(_('Source'), choices=SOURCE_CHOICES, max_length=15)
    item = JSONField(_('Item'), null=True, blank=True)
    message = models.TextField(_('Message'), max_length=300)
    details = JSONField(_('Detail'), null=True, blank=True)
    SEVERITY_CHOICES = (
        ('w', 'warning'),
        ('i', 'info'),
        ('e', 'error')
    )
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    datetime = models.DateTimeField(_('Datetime'), auto_now=True)
    has_seen = models.BooleanField(_('Has Seen'), default=False)
    user = models.CharField(_('User'), max_length=30, default='system')
    is_deletable = models.BooleanField(_('Is Deletable'), default=True)
