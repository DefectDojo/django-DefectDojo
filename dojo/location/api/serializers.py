from __future__ import annotations

from rest_framework.serializers import CharField

from dojo.api_helpers.serializers import BaseModelSerializer
from dojo.api_v2.serializers import TagListSerializerField
from dojo.location.models import (
    Location,
    LocationFindingReference,
    LocationProductReference,
)


class AbstractedLocationSerializer(BaseModelSerializer):
    string = CharField(source="location.location_value", read_only=True)
    type = CharField(source="location.location_type", read_only=True)
    tags = TagListSerializerField(source="location.tags", required=False)


class LocationSerializer(BaseModelSerializer):

    """Serializer for the Location model with serializers for the related objects."""

    tags = TagListSerializerField(required=False)

    class Meta:

        """Meta class for the Location model."""

        model = Location
        fields = "__all__"


class LocationFindingReferenceSerializer(BaseModelSerializer):

    """Serializer for the LocationFindingReference model with serializers for the related objects."""

    location_type = CharField(read_only=True)
    location_value = CharField(read_only=True)

    class Meta:

        """Meta class for the Location model."""

        model = LocationFindingReference
        fields = "__all__"


class LocationProductReferenceSerializer(BaseModelSerializer):

    """Serializer for the LocationProductReference model with serializers for the related objects."""

    location_type = CharField(read_only=True)
    location_value = CharField(read_only=True)

    class Meta:

        """Meta class for the Location model."""

        model = LocationProductReference
        fields = "__all__"
