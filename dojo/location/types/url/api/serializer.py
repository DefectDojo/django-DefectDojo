from dojo.location.api.serializers import AbstractedLocationSerializer
from dojo.location.types.url.models import URL


class URLSerializer(AbstractedLocationSerializer):

    """Serializer for the URL model with primary keys for related objects."""

    class Meta:

        """Meta class for the URL model."""

        model = URL
        fields = "__all__"
