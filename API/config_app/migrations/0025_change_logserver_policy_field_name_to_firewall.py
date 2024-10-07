from django.db import migrations


def change_log_server_policy_field_name(apps, schema_editor):
    log_server_model = apps.get_model('config_app', 'LogServer')
    model_data = log_server_model.objects.all()
    for data in model_data:
        if 'policy' in data.service_list:
            data.service_list.remove('policy')
            data.service_list.append('firewall')
            data.save()


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0024_auto_20180905_0923'),
    ]

    operations = [
        migrations.RunPython(change_log_server_policy_field_name)
    ]
