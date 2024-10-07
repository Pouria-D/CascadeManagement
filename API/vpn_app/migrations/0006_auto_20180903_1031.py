# Generated by Django 2.1 on 2018-09-03 10:31

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('vpn_app', '0005_auto_20180812_1736'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vpn',
            name='local_id',
            field=models.CharField(max_length=30, unique=True, verbose_name='Local ID'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='name',
            field=models.CharField(max_length=15, unique=True, verbose_name='Name'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='peer_id',
            field=models.CharField(max_length=30, unique=True, verbose_name='Peer ID'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='preshared_key',
            field=models.CharField(max_length=30, verbose_name='Preshared Key'),
        ),
    ]
