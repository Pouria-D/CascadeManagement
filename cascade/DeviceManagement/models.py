from django.db import models
from django.core.validators import RegexValidator
from django.urls import reverse

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token



@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
    for user in User.objects.all():
        Token.objects.get_or_create(user=user)
    

"""
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

for user in User.objects.all():
    Token.objects.get_or_create(user=user)

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
"""
alphanumeric_validator = RegexValidator(r'^[0-9a-zA-Z\,_.-]*$', 'Only alphanumeric characters are allowed.')
numeric_validator = RegexValidator(r'^[0-9]*$', 'Only positive numbers are allowed.')

class Device(models.Model):

    created = models.DateTimeField(auto_now_add=True)
    name = models.CharField("Name", max_length=20, unique=True, validators=[alphanumeric_validator])
    owner = models.ForeignKey('auth.User', related_name='Device', default='1', on_delete=models.CASCADE)

    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('failed', 'failed'),
        ('enabled', 'enabled'),
        ('disabled', 'disabled'),
        ('stopped', 'stopped')
    )
    status = models.CharField("Status", max_length=20, null=True, blank=True, choices=STATUS_CHOICES)
    #status = models.CharField(_('Status'), max_length=20, choices=STATUS_CHOICES, null=True, blank=True)

    ip = models.GenericIPAddressField("IP Address", unique=True)
    #ip = models.GenericIPAddressField(_("IP Address"), blank=True, null=True)
    address = models.CharField("Address", blank=True, null=True, max_length=80)

    port = models.CharField("Port", blank=True, null=True, max_length=10, validators=[numeric_validator])

    #url = models.URLField(max_length=500, default=' http://192.168.203.139')
    Description = models.CharField("Description", blank=True, null=True, max_length=1024)
    """
    def get_absolute_url(self):
        return reverse(Device.url)
    """
    # ID default has been set in Django :
    # id = models.AutoField(primary_key=True)
    class Meta:
        verbose_name = 'Device Management'
        verbose_name_plural = 'Device Managements'
        ordering = ['created']
