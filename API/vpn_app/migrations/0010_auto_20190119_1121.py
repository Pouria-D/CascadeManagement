# Generated by Django 2.1.3 on 2019-01-19 11:21

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('vpn_app', '0009_auto_20190116_0912'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vpn',
            name='phase1_encryption_algorithm',
            field=models.CharField(
                choices=[('paya256', 'PAYA-256'), ('sabah256', 'SABAH-256'), ('3des', '3DES'), ('aes128', 'AES-128'),
                         ('aes192', 'AES-192'), ('aes256', 'AES-256')], max_length=20,
                verbose_name='Phase1 Encryption Algorithm'),
        ),
        migrations.AlterField(
            model_name='vpn',
            name='phase2_encryption_algorithm',
            field=models.CharField(
                choices=[('paya256', 'PAYA-256'), ('sabah256', 'SABAH-256'), ('3des', '3DES'), ('aes128', 'AES-128'),
                         ('aes192', 'AES-192'), ('aes256', 'AES-256')], max_length=20,
                verbose_name='Phase2 Encryption Algorithm'),
        ),
    ]
