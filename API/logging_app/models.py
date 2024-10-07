from django.db import models


class LastLog(models.Model):
    ip = models.GenericIPAddressField()
    username = models.CharField(max_length=255)
    item = models.CharField(max_length=255)

    def __str__(self):
        return str(self.ip)

