import binascii
import os

from django.conf import settings
from django.db import models
from django.utils.translation import gettext as _


class Token(models.Model):
    """
    Customized authorization token model with ip.
    """
    key = models.CharField(_("Key"), max_length=40, primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='auth_app_token', on_delete=models.CASCADE, verbose_name=_("User")
    )
    created = models.DateTimeField(_("Created"), auto_now_add=True)
    ip = models.GenericIPAddressField()

    class Meta:
        verbose_name = _("Token")
        verbose_name_plural = _("Tokens")

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key


class AdminLoginLock(models.Model):
    ip = models.GenericIPAddressField()
    num_of_retry = models.IntegerField(default=0)
    datetime_created = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip
