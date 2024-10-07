from django.db import migrations


def delete_extra(model):
    model_data = model.objects.all()
    count_data = model_data.count()
    if count_data != 0:
        last_data = model.objects.last().id
        for data in model_data:
            if data.id != last_data:
                data.delete()


def remove_extra_ntp_config(apps, schema_editor):
    ntp_model = apps.get_model('config_app', 'NTPConfig')
    delete_extra(ntp_model)


def remove_extra_update_manager_config(apps, schema_editor):
    update_manager_model = apps.get_model('config_app', 'UpdateConfig')
    delete_extra(update_manager_model)


def remove_extra_dns_server_config(apps, schema_editor):
    dns_server_model = apps.get_model('config_app', 'DNSConfig')
    delete_extra(dns_server_model)


def remove_extra_log_server_config(apps, schema_editor):
    log_server_model = apps.get_model('config_app', 'LogServerConfig')
    delete_extra(log_server_model)


class Migration(migrations.Migration):
    dependencies = [
        ('config_app', '0022_auto_20180806_1413'),
    ]

    operations = [
        migrations.RunPython(remove_extra_ntp_config),
        migrations.RunPython(remove_extra_update_manager_config),
        migrations.RunPython(remove_extra_dns_server_config),
        migrations.RunPython(remove_extra_log_server_config)
    ]
