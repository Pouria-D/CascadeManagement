# Generated by Django 2.0.7 on 2018-07-28 13:47

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('config_app', '0019_auto_20180718_1306'),
    ]

    operations = [
        migrations.AddField(
            model_name='interface',
            name='mac',
            field=models.CharField(blank=True, max_length=20, null=True, validators=[django.core.validators.RegexValidator('^[0-9a-fA-F]{2}([-:])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}$')], verbose_name='Mac address'),
        ),
    ]
