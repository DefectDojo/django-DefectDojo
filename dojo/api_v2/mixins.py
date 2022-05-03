from django.db import DEFAULT_DB_ALIAS
from django.contrib.admin.utils import NestedObjects
from drf_spectacular.utils import extend_schema
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import action
from rest_framework import status
from rest_framework.authtoken.models import Token
from dojo.api_v2 import serializers
import itertools


class DeletePreviewModelMixin:
    @extend_schema(
        methods=['GET'],
        responses={status.HTTP_200_OK: serializers.DeletePreviewSerializer(many=True)}
    )
    @swagger_auto_schema(
        method='get',
        responses={'default': serializers.DeletePreviewSerializer(many=True)}
    )
    @action(detail=True, methods=["get"], filter_backends=[], suffix='List')
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

        rels = [
            {
                "model": type(x).__name__,
                "id": x.id if hasattr(x, 'id') else None,
                "name": str(x) if not isinstance(x, Token) else "<APITokenIsHidden>"
            }
            for x in flatten(rels)
        ]

        page = self.paginate_queryset(rels)

        serializer = serializers.DeletePreviewSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)
