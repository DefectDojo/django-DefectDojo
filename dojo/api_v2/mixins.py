from rest_framework.response import Response
from django.db import DEFAULT_DB_ALIAS
from django.contrib.admin.utils import NestedObjects
from drf_spectacular.utils import extend_schema
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import action
from rest_framework import status
import itertools


class DeletePreviewModelMixin:
    @extend_schema(
        methods=['GET'],
    )
    @swagger_auto_schema(
        method='get',
    )
    @action(detail=True, methods=["get"])
    def delete_preview(self, request, pk=None):
        object = self.get_object()

        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([object])
        rels = collector.nested()

        def flatten(elem):
            if isinstance(elem, list):
                return itertools.chain.from_iterable(map(flatten, elem))
            else:
                return [elem]

        rels = [{"model": type(x).__name__, "id": x.id, "name": str(x)} for x in flatten(rels)]

        return Response(rels,
                        status=status.HTTP_200_OK)
