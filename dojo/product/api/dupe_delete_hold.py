from django.db.models import Value
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from dojo.authorization import api_permissions as permissions
from dojo.models import Product


class ClearDupeDeleteHoldMixin:

    """
    POST <asset or product>/{id}/clear_dupe_delete_hold/: let Delete Duplicates remove the asset's duplicates again.

    Shared by the product and asset viewsets, so every mount of either one carries it.
    """

    @extend_schema(request=None, responses={status.HTTP_204_NO_CONTENT: None})
    @action(
        detail=True, methods=["post"],
        # A hold stops Delete Duplicates from removing this asset's duplicates, set when deleting
        # them looked unsafe. Lifting it lets deletion resume, so only a superuser may.
        permission_classes=[IsAuthenticated, permissions.IsSuperUser],
    )
    def clear_dupe_delete_hold(self, request, pk=None):
        product = self.get_object()
        # update() rather than save(): only the hold changes, and no save signal recomputes
        # anything for a field nothing else reads. The product history trigger still records it.
        Product.objects.filter(pk=product.pk).update(dupe_delete_held_at=Value(None))
        return Response(status=status.HTTP_204_NO_CONTENT)
