# Generated by Django 2.1.3 on 2019-05-04 11:24

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('config_app', '0044_hostname'),
    ]

    operations = [
        migrations.CreateModel(
            name='HighAvailability',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('peer1_address', models.GenericIPAddressField(verbose_name='peer1 address')),
                ('peer2_address', models.GenericIPAddressField(verbose_name='peer2 address')),
                (
                'cluster_address_list', django.contrib.postgres.fields.jsonb.JSONField(verbose_name='cluster address')),
                ('configured_peer_interface_mac', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True,
                                                                                                 verbose_name='configured system')),
                ('is_enabled', models.BooleanField(default=True, verbose_name='Is enabled')),
                ('description', models.CharField(blank=True, max_length=255, null=True, verbose_name='Description')),
                ('last_operation',
                 models.CharField(blank=True, choices=[('add', 'add'), ('delete', 'delete'), ('update', 'update')],
                                  max_length=20, null=True, verbose_name='Last Operation')),
                ('status', models.CharField(blank=True, choices=[('pending', 'pending'), ('failed', 'failed'),
                                                                 ('succeeded', 'succeeded'), ('disabled', 'disabled')],
                                            max_length=20, null=True, verbose_name='Status')),
            ],
        ),
    ]
