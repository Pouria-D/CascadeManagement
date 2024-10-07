import json

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer


class NotificationConsumer(WebsocketConsumer):
    groups = ['notification']

    def connect(self):
        self.accept()
        async_to_sync(self.channel_layer.group_add)("notification", self.channel_name)

    def disconnect(self, close_code):
        print('close :))')

    def send_notification(self, event):
        self.send(text_data=json.dumps(event['text']))
