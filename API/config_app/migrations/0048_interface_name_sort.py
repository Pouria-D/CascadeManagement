# Generated by Django 2.1.3 on 2019-07-15 10:50

from django.db import migrations

import config_app.models


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0047_dhcpserverconfig_lease_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='interface',
            name='name_sort',
            field=config_app.models.NaturalSortField(blank=True, db_index=True, editable=False, for_field='name',
                                                     max_length=255, null=True),
        ),
    ]
