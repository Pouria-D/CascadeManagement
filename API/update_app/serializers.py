from rest_framework import serializers

from update_app.models import Update


class UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Update
        exclude = ('file', 'key')
