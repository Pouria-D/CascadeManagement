# Generated by Django 2.0.4 on 2018-04-22 07:21

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('firewall_app', '0004_sourcedestination_application_list'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='sourcedestination',
            name='application_list',
        ),
    ]
