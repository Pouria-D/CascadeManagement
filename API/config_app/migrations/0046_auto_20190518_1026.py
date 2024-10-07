# Generated by Django 2.1.3 on 2019-05-18 10:26

import django.core.files.storage
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0045_highavailability'),
    ]

    operations = [
        migrations.AddField(
            model_name='updateconfig',
            name='is_offline',
            field=models.BooleanField(default=False, verbose_name='Is offline mode'),
        ),
        migrations.AddField(
            model_name='updateconfig',
            name='offline_file_update',
            field=models.FileField(blank=True, default=None, help_text='Upload files for offline update.', null=True,
                                   storage=django.core.files.storage.FileSystemStorage(location='/var/ngfw/'),
                                   upload_to='', verbose_name='Offline File Update'),
        ),
    ]
