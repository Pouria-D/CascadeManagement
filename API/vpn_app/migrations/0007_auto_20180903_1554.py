# Generated by Django 2.1 on 2018-09-03 15:54

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('vpn_app', '0006_auto_20180903_1031'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vpn',
            name='local_id',
            field=models.CharField(max_length=30, verbose_name='Local ID'),
        ),
    ]
