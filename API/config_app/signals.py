import os

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from config_app.models import Backup


@receiver(pre_delete, sender=Backup, dispatch_uid='backup_listener')
def backup_listener(sender, instance, **kwargs):
    if instance.file:
        json_file_path = os.path.join(instance.file.path.replace('.json', '.tar'))
        bak_file_path = os.path.join(instance.file.path.replace('.json', '.bak'))

        if os.path.exists(json_file_path):
            os.remove(json_file_path)

        if os.path.exists(bak_file_path):
            os.remove(bak_file_path)


def dummy_function():
    # this is just for preventing pycharm from remove signal import in apps.py
    pass
