# Generated by Django 2.1.3 on 2019-04-29 09:30

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('firewall_input_app', '0002_inputfirewall_protocol'),
    ]

    operations = [
        migrations.AddField(
            model_name='apply',
            name='unapplied_role',
            field=models.ManyToManyField(blank=True, to='firewall_input_app.InputFirewall'),
        ),
    ]
