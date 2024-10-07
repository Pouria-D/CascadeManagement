# Generated by Django 2.1.3 on 2019-09-25 10:57

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('pki_app', '0004_auto_20190923_0946'),
        ('vpn_app', '0011_auto_20190813_1444'),
    ]

    operations = [
        migrations.AddField(
            model_name='vpn',
            name='certificate',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name='+', to='pki_app.PKI'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='local_id',
            field=models.CharField(max_length=100, verbose_name='Local ID'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='peer_id',
            field=models.CharField(max_length=100, unique=True, verbose_name='Peer ID'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='preshared_key',
            field=models.CharField(blank=True, max_length=30, null=True, verbose_name='Preshared Key'),
        ),
    ]
