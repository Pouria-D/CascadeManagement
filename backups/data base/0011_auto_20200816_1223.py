# Generated by Django 3.1 on 2020-08-16 12:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DeviceManagement', '0010_auto_20200816_1215'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='url',
            field=models.URLField(default='http;//192.168.203.139', max_length=250),
        ),
    ]
