from django.contrib.postgres.fields.jsonb import JSONField
from django.db import models
from django.utils.translation import gettext as _


class PKI(models.Model):
    name = models.CharField(max_length=100, unique=True, blank=False)
    description = models.CharField(_('Description'), blank=True, null=True, max_length=255)
    data = JSONField(_('data'))
    default_local_ca = models.BooleanField(default=False)
    private_key = models.TextField(_('private key'), null=True, blank=True, max_length=6000)
    certificate = models.TextField(_('certificate'), null=True, blank=True, max_length=6000)
    certificate_request = models.TextField(_('certificate request'), null=True, blank=True, max_length=6000)
    is_uploaded = models.BooleanField(default=False)
    TYPE_CHOICES = (
        ('certificate', 'certificate'),
        ('certificate_request', 'certificate_request'),
        ('local_certificate_authority', 'local_certificate_authority'),
    )
    type = models.CharField(_('Type'), max_length=30, choices=TYPE_CHOICES)

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
