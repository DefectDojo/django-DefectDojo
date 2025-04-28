from rest_framework import serializers


class ManagerCacheSerializers(serializers.Serializer):
    pattern = serializers.CharField(required=True)

