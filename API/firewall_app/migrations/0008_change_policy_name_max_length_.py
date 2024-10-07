from django.db import migrations


def change_policy_name_max_length(apps, schema_editor):
    policy = apps.get_model('firewall_app', 'Policy')
    if policy.objects.exists():
        policy_data = policy.objects.all()
        for policy in policy_data:
            if len(policy.name) > 15:
                policy.name = policy.name[:15]
                policy.save()


class Migration(migrations.Migration):
    dependencies = [
        ('firewall_app', '0007_auto_20180814_1217'),
    ]

    operations = [
        migrations.RunPython(change_policy_name_max_length)
    ]
