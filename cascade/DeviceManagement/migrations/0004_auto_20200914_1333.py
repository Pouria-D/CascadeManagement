# Generated by Django 3.1 on 2020-09-14 13:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DeviceManagement', '0003_auto_20200914_1231'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='status',
            field=models.CharField(blank=True, choices=[('pending', 'pending'), ('failed', 'failed'), ('enabled', 'enabled'), ('disabled', 'disabled'), ('stopped', 'stopped')], max_length=20, null=True, verbose_name='Status'),
        ),
    ]
