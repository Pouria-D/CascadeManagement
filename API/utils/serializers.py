from rest_framework import serializers


class SingleIPSerializer(serializers.Serializer):
    ip = serializers.IPAddressField(required=True)


class MaskSerializer(serializers.Serializer):
    mask = serializers.IPAddressField(required=True)


class IntegerMaskSerializer(serializers.Serializer):
    mask = serializers.IntegerField(min_value=0, max_value=32, required=True)


class IPMaskSerializer(serializers.Serializer):
    ip = serializers.IPAddressField(required=True)
    mask = serializers.IPAddressField(required=True)


class IPIntegerMaskSerializer(serializers.Serializer):
    ip = serializers.IPAddressField(required=True)
    mask = serializers.IntegerField(min_value=0, max_value=32, required=True)


def get_diff(instance, serializer_class, data, exclude=None):
    if exclude is None:
        exclude = []

    serializer = serializer_class(instance=instance)

    change_list = list()

    for item in data:
        if item in exclude:
            continue

        if item not in serializer.data:
            continue

        field_change = dict()
        if isinstance(serializer.data[item], dict):
            d = dict(serializer.data[item])
            if 'id' in d:
                del d['id']

            if data[item] != d:
                field_change['field'] = item
                field_change['before'] = serializer.data[item]
                field_change['after'] = data[item]
                change_list.append(field_change)

        elif data[item] != serializer.data[item]:
            field_change['field'] = item
            field_change['before'] = serializer.data[item]
            field_change['after'] = data[item]
            change_list.append(field_change)

    if change_list:
        changes = dict()
        # changes['table'] = instance.__class__.__name__
        # changes['fields'] = change_list
        changes['items'] = change_list
        return changes
