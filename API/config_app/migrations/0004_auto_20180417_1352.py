# Generated by Django 2.0.4 on 2018-04-17 13:52

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0003_auto_20180417_1231'),
    ]

    operations = [
        migrations.RenameModel(old_name="DNSServer", new_name="DNSConfig"
                               ),

    ]
