from dojo.location.api.serializers import AbstractedLocationSerializer
from dojo.url.models import URL


class URLSerializer(AbstractedLocationSerializer):

    """Serializer for the URL model with primary keys for related objects."""

    class Meta:

        """Meta class for URLSerializer."""

        model = URL
        exclude = ("location", "hash")
