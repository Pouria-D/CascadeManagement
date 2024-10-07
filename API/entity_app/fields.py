# from django.shortcuts import get_object_or_404
# from rest_framework import serializers
#
# from entity_app.models import Schedule
# from entity_app.serializers import ScheduleSerializer
#
#
# class ScheduleField(serializers.Field):
#
#     def to_representation(self, obj):
#         serializer = ScheduleSerializer(instance=obj)
#         return serializer.data
#
#     def to_internal_value(self, data):
#
#         if type(data) is int:
#             schedule = get_object_or_404(Schedule, pk=data)
#         else:
#             serializer = ScheduleSerializer(data=data, context=self.context)
#             if not serializer.is_valid():
#                 raise serializers.ValidationError(serializer.errors)
#
#             schedule = serializer.save()
#
#         return schedule
