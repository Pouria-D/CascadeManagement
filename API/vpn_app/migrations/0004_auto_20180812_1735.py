# Generated by Django 2.1 on 2018-08-12 13:05

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('vpn_app', '0003_auto_20180702_1642'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tunnel',
            name='real_local_endpoint',
        ),
        migrations.RemoveField(
            model_name='tunnel',
            name='real_remote_endpoint',
        ),
        migrations.RemoveField(
            model_name='tunnel',
            name='server_endpoint',
        ),
        migrations.RemoveField(
            model_name='tunnel',
            name='virtual_local_endpoint',
        ),
        migrations.RemoveField(
            model_name='tunnel',
            name='virtual_remote_endpoint',
        ),
        migrations.RemoveField(
            model_name='vpn',
            name='local_endpoint',
        ),
        migrations.RemoveField(
            model_name='vpn',
            name='remote_endpoint',
        ),
    ]
