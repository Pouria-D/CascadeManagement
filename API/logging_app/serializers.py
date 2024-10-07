from rest_framework import serializers as rest_serializers
from rest_framework_mongoengine.fields import ObjectIdField


class ResultsSerializer(rest_serializers.Serializer):
    message = rest_serializers.StringRelatedField()
    user = rest_serializers.StringRelatedField()
    ip = rest_serializers.StringRelatedField()
    details = rest_serializers.StringRelatedField()
    operation = rest_serializers.StringRelatedField()
    timestamp = rest_serializers.DateTimeField()
    sender = rest_serializers.StringRelatedField()
    dst_mac = rest_serializers.StringRelatedField()
    protocol = rest_serializers.StringRelatedField()
    action = rest_serializers.StringRelatedField()
    input_interface = rest_serializers.StringRelatedField()
    l7_app = rest_serializers.StringRelatedField()
    output_interface = rest_serializers.StringRelatedField()
    src_ip = rest_serializers.StringRelatedField()
    dst_ip = rest_serializers.StringRelatedField()
    dst_port = rest_serializers.StringRelatedField()
    src_port = rest_serializers.StringRelatedField()
    src_mac = rest_serializers.StringRelatedField()
    policy_id = rest_serializers.StringRelatedField()
    policy_name = rest_serializers.StringRelatedField()
    _id = ObjectIdField()


class LogSerializer(rest_serializers.Serializer):
    count = rest_serializers.IntegerField()
    next = rest_serializers.StringRelatedField()
    previous = rest_serializers.StringRelatedField()
    results = ResultsSerializer(many=True)
