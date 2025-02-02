# Generated by Django 3.1 on 2020-08-22 05:15

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('name', models.CharField(max_length=20, unique=True, validators=[django.core.validators.RegexValidator('^[0-9a-zA-Z\\,_.-]*$', 'Only alphanumeric characters are allowed.')], verbose_name='Name')),
                ('status', models.CharField(choices=[('pending', 'pending'), ('failed', 'failed'), ('enabled', 'enabled'), ('disabled', 'disabled'), ('stopped', 'stopped')], max_length=20, verbose_name='Status')),
                ('ip', models.GenericIPAddressField(unique=True, verbose_name='IP Address')),
                ('address', models.CharField(blank=True, max_length=80, null=True, verbose_name='Address')),
                ('port', models.CharField(blank=True, max_length=10, null=True, validators=[django.core.validators.RegexValidator('^[0-9]*$', 'Only positive numbers are allowed.')], verbose_name='Port')),
                ('url', models.URLField(default=' http://192.168.203.139', max_length=250)),
                ('owner', models.ForeignKey(default='1', on_delete=django.db.models.deletion.CASCADE, related_name='Device', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Device Management',
                'verbose_name_plural': 'Device Managements',
                'ordering': ['created'],
            },
        ),
    ]
