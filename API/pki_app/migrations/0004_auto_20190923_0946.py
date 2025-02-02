# Generated by Django 2.1.3 on 2019-09-23 09:46

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('pki_app', '0003_auto_20190921_1504'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pki',
            name='certificate',
            field=models.TextField(blank=True, max_length=6000, null=True, verbose_name='certificate'),
        ),
        migrations.AlterField(
            model_name='pki',
            name='certificate_request',
            field=models.TextField(blank=True, max_length=6000, null=True, verbose_name='certificate request'),
        ),
        migrations.AlterField(
            model_name='pki',
            name='private_key',
            field=models.TextField(blank=True, max_length=6000, null=True, verbose_name='private key'),
        ),
    ]
