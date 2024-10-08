# Generated by Django 3.1 on 2020-08-12 09:39

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceManagement',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('name', models.CharField(max_length=20, unique=True, validators=[django.core.validators.RegexValidator('^[0-9a-zA-Z\\,_.-]*$', 'Only alphanumeric characters are allowed.')], verbose_name='Name')),
                ('status', models.CharField(choices=[('pending', 'pending'), ('failed', 'failed'), ('succeeded', 'succeeded'), ('disabled', 'disabled'), ('stopped', 'stopped')], max_length=20, verbose_name='Status')),
                ('ip', models.GenericIPAddressField(verbose_name='IP Address')),
                ('address', models.CharField(blank=True, max_length=80, null=True, verbose_name='Description')),
                ('port', models.CharField(blank=True, max_length=10, null=True, verbose_name='Port')),
            ],
            options={
                'verbose_name': 'Device Management',
                'verbose_name_plural': 'Device Managements',
                'ordering': ['created'],
            },
        ),
    ]
