from django.core.files.storage import FileSystemStorage
from django.core.validators import FileExtensionValidator
from django.db import models

fs = FileSystemStorage(location='/var/ngfw')
fs_secure = FileSystemStorage(location='/var/ngfw')


class Update(models.Model):
    new_version = models.CharField(max_length=20, unique=True)
    file = models.FileField(storage=fs_secure,
                            validators=[FileExtensionValidator(allowed_extensions=['xz'])], null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    STATUS_CHOICES = (
        ('pending', 'pending'),
        ('ready', 'ready')
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    key = models.FileField(storage=fs,
                           validators=[FileExtensionValidator(allowed_extensions=['key'])], null=True, blank=True)

    def __str__(self):
        return '{}....{}'.format(self.new_version, self.description)
