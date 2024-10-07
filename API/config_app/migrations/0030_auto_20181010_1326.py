# Generated by Django 2.1 on 2018-10-10 13:26

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0029_update_update_log_flag'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logserver',
            name='service_list',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(
                choices=[('admin-log', 'admin-log'), ('vpn', 'vpn'), ('ssh', 'ssh'), ('firewall', 'firewall')],
                max_length=10), size=None),
        ),
    ]
