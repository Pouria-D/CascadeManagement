import channels.layers
from asgiref.sync import async_to_sync
from django.db.models.signals import post_save
from django.dispatch import receiver

from report_app.models import Notification
from report_app.serializers import NotificationReadSerializer


@receiver(post_save, sender=Notification, dispatch_uid='notification_listener')
def notification_listener(sender, instance, **kwargs):
    """
    Sends Notification to the browser when a Notification is modified
    """

    group_name = 'notification'
    serializer = NotificationReadSerializer(instance)
    channel_layer = channels.layers.get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            'type': 'send_notification',
            'text': serializer.data
        }
    )
