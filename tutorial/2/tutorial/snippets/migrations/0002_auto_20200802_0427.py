# Generated by Django 3.0.8 on 2020-08-02 04:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('snippets', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='snippet',
            options={'ordering': ['created']},
        ),
    ]
