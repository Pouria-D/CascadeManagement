# Generated by Django 2.1.3 on 2019-04-20 10:02

import django.contrib.postgres.fields.jsonb
from django.core.management import call_command
from django.db import migrations, models


def load_new_settings(apps, schema_editor):
    call_command('loaddata', 'config_app/fixtures/initial_data.json')


def move_setting_hostname_to_hostname_model(apps, schema_editor):
    Setting_Model = apps.get_model('config_app', 'Setting')
    host_name_instance = Setting_Model.objects.filter(key='host-name')
    Hostname_Model = apps.get_model('config_app', 'Hostname')
    Hostname_Model.objects.bulk_create(host_name_instance)
    host_name_instance.delete()


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0043_auto_20190407_1744'),
    ]

    operations = [
        migrations.CreateModel(
            name='Hostname',
            fields=[
                ('key', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('data', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('display_name', models.TextField(blank=True, null=True)),
                ('descriptions', models.TextField(blank=True, null=True)),
                ('type', models.CharField(blank=True,
                                          choices=[('number', 'number'), ('bool', 'bool'), ('string', 'string'),
                                                   ('certificate', 'certificate')], max_length=20, null=True,
                                          verbose_name='Type')),
                ('order', models.IntegerField(default=0)),
                ('category', models.TextField(default='Other')),
            ],
        ),
        migrations.RunPython(move_setting_hostname_to_hostname_model),
        migrations.RunPython(load_new_settings)
    ]
