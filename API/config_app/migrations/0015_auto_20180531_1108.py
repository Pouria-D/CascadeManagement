# Generated by Django 2.0.5 on 2018-05-31 06:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('config_app', '0014_adminloginlock_datetime_created'),
    ]

    operations = [
        migrations.AlterField(
            model_name='adminloginlock',
            name='datetime_created',
            field=models.DateField(auto_now=True),
        ),
    ]
