import logging
import os
import mimetypes
import json
from rest_framework.decorators import action
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.db import transaction, IntegrityError
from dojo.api_v2.scope.filter import InputFilter, InputFlowFilter
from dojo.api_v2.scope.models import InputSecret, InputFile, Input , InputFlow,InputScenario,InputURL
from dojo.api_v2.scope.serializers import *
from dojo.api_v2.views import DojoModelViewSet
from dojo.api_v2.utils import http_response
from dojo.authorization.roles_permissions import Permissions
from rest_framework.pagination import LimitOffsetPagination
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from django.http import FileResponse
from dojo.api_v2.api_error import ApiError
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    OpenApiTypes,
)
from dojo.api_v2 import (
    permissions,
    prefetch,
)
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from dojo.api_v2.scope.queries import get_authorized_scope
from dojo.finding import serializer
from dojo.models import Engagement
from dojo.engagement.queries import get_authorized_engagements

logger = logging.getLogger(__name__)


class ScopeViewSet(prefetch.PrefetchListMixin,
                             prefetch.PrefetchRetrieveMixin,
                             DojoModelViewSet):
    queryset = Input.objects.all() 
    permission_classes = (IsAuthenticated,
                          permissions.UserHasInputPermission,)
    serializer_class = InputSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = InputFilter
    pagination_class = LimitOffsetPagination

    def get_queryset(self, pid):
        product = get_object_or_404(Product, id=pid)
        inputs = get_authorized_scope(Permissions.Input_View, product)
        return inputs
        
    def destroy(self, request, *args, **kwargs):
        input_id = kwargs.get("pk")
        input_instance = get_object_or_404(Input, id=input_id)
        
        self.check_object_permissions(request, input_instance)
        
        input_instance.delete()
        return http_response.ok(message="Input deleted successfully.", data=None)

    def update(self, request, *args, **kwargs):
        input_id = kwargs.get("pk")
        try:
            input_instance = get_object_or_404(Input, id=input_id)
            serializer = InputSerializer(input_instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            instance  = serializer.save()
            return http_response.ok(message="Input updated successfully.", data=InputSerializer(instance).data)
        except Exception as e:
            logger.error(f"Validation error on PATCH Input: {e}")
            return http_response.error(
                message="Validation error occurred.", data=serializer.errors)

    def list(self, request, *args, **kwargs):
        inputs_qr = self.filter_queryset(
            self.get_queryset(request.query_params.get("product")))
        page = self.paginate_queryset(inputs_qr)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(inputs_qr, many=True)
        return http_response.ok(data=serializer.data)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="engagement",
                type=OpenApiTypes.INT,
                description="Engagement ID",
                required=True,
            ),
            OpenApiParameter(
                name="product",
                type=OpenApiTypes.INT,
                description="Product ID",
                required=True,
            ),
            OpenApiParameter(
                name="description",
                type=OpenApiTypes.STR,
                description="Description",
                required=True,
            ),
            OpenApiParameter(
                name="type",
                type=OpenApiTypes.STR,
                description="Type input (secret/file)",
                required=True,
                enum=["secret", "file"],
            ),
            OpenApiParameter(
                name="file",
                type=OpenApiTypes.BINARY,
                description="File to upload",
                required=True,
            ),
            OpenApiParameter(
                name="file_name",
                type=OpenApiTypes.STR,
                description="File name",
                required=True,
            ),
        ],
        responses={status.HTTP_201_CREATED: ScopeFileSerializers},
    )
    @action(detail=False, methods=["post"])
    def create_scope_file(self, request, *args, **kwargs):
        try:
            serializer = ScopeFileSerializers(data=request.query_params)
            serializer.is_valid(raise_exception=True)
            instance = serializer.save(request=request)
            return http_response.ok(message="Input Engagement created successfully.", data=InputEngagementSerializer(instance).data)
        except IntegrityError as e:
            logger.error(f"IntegrityError while creating Input Engagement: {e}")
            return http_response.error(
                message="Integrity error occurred while creating Input Engagement.", data=serializer.errors)
    
    @action(detail=False, methods=["post"])
    def create_scope_secret(self, request, *args, **kwargs):
        try:
            serializer = ScopeSecretSerializers(data=request.data)
            serializer.is_valid(raise_exception=True)
            instance = serializer.save(owner=request.user)
            return http_response.ok(message="Input Engagement created successfully.", data=InputEngagementSerializer(instance).data)
        except IntegrityError as e:
            logger.error(f"IntegrityError while creating Input Engagement: {e}")
            return http_response.error(
                message="Integrity error occurred while creating Input Engagement.", data=serializer.errors)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="input",
                type=OpenApiTypes.INT,
                description="Input ID",
                required=True,
            ),
        ],
    )
    @action(detail=False, methods=["get"], url_path="download_file")
    def download_file(self, request, *args, **kwargs):
        """
        GET /.../download_file/?input=<input_id>
        Returns the file attached to the given Input as a downloadable response.
        """
        input_id = request.query_params.get("input") or request.query_params.get("input_id")
        if not input_id:
            return http_response.error(message="Missing 'input' query parameter.", data=None)

        input_file = get_object_or_404(InputFile, input__id=input_id)
        self.check_object_permissions(request, input_file)

        file_field = input_file.file
        if not file_field:
            raise ApiError.not_found(detail="File not fonud")

        try:
            file_handle = file_field.open("rb")
        except Exception as e:
            raise ApiError.internal_server_error(detail="Unable to open file: " + str(e))

        filename = os.path.basename(file_field.name)
        content_type, _ = mimetypes.guess_type(filename)
        response = FileResponse(
            file_handle,
            as_attachment=True,
            filename=filename,
            content_type=content_type or "application/octet-stream"
            )
        return response

@extend_schema(tags=["scope"])
class InputSecretViewSet(prefetch.PrefetchListMixin,
                             prefetch.PrefetchRetrieveMixin,
                             DojoModelViewSet):
    queryset = InputSecret.objects.all() 
    permission_classes = (IsAuthenticated,
                          permissions.UserHasEngagementPermission,)
    serializer_class = InputSecretSerializer 
    filter_backends = (DjangoFilterBackend,)

@extend_schema(tags=["scope"])
class InputFileViewSet(prefetch.PrefetchListMixin,
                             prefetch.PrefetchRetrieveMixin,
                             DojoModelViewSet):
    queryset = InputFile.objects.all() 
    permission_classes = (IsAuthenticated,
                          permissions.UserHasEngagementPermission,)
    serializer_class = InputFileSerializer 
    filter_backends = (DjangoFilterBackend,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def patch(self, request, *args, **kwargs):
        input_id = request.query_params.get("id")
        input_file_instance = get_object_or_404(InputFile, input__id=input_id)
        self.check_object_permissions(request, input_file_instance)
        try:
            patch_data = request.query_params.copy()
            patch_data.pop("id", None)
            patch_data.update(request.data)
            serializer = InputFileSerializer(input_file_instance, data=patch_data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return http_response.ok(message="InputFile updated successfully.", data=serializer.data)
        except Exception as e:
            logger.error(f"Validation error on PATCH InputFile: {e}")
            return http_response.bad_request(
                message="Validation error occurred.", data=serializer.errors)
@extend_schema(tags=["scope"])
class InputFlowViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet
):
    queryset = InputFlow.objects.select_related(
        "engagement__product__prod_type"
    ).prefetch_related(
        "urls__scenarios"
    ).order_by("id")

    serializer_class = InputFlowSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = InputFlowFilter
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasInputFlowPermission,
    )

    def get_queryset(self):
        return self.queryset.filter(
            engagement__in=get_authorized_engagements(Permissions.Input_Flow_View))

    def create(self, request, *args, **kwargs):
        engagement_id = request.data.get("engagement")
        if not engagement_id:
            return http_response.error(
                message="El campo engagement es obligatorio.",
                data={"engagement": ["This field is required."]},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        engagement = get_object_or_404(Engagement, pk=engagement_id)
        self.check_object_permissions(request, engagement)
        engagement_name = engagement.name

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        return http_response.ok(
            message=f"Se creó el flujo {instance.flowName} correctamente en el engagement {engagement_name}.",
            data=self.get_serializer(instance).data
        )
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        return http_response.ok(
            message=f"Se actualizó el flujo {instance.flowName} correctamente.",
            data=self.get_serializer(instance).data
        )

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="add_url")
    def add_url(self, request, pk=None):
        flow = self.get_queryset().filter(pk=pk).first()

        if not flow:
            return http_response.error(
                message="No es posible agregar la URL porque el flujo indicado no existe.",
                data={"flow": ["The specified flow does not exist."]}
            )

        if flow.engagement is None:
            return http_response.error(
                message="El flujo no tiene un engagement asociado.",
                data={"engagement": ["Flow has no engagement associated."]}
            )

        self.check_object_permissions(request, flow)

        serializer = InputURLSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        instance = serializer.save(flow=flow)

        return http_response.ok(
            message=f"Se creó la URL {instance.url} correctamente.",
            data=InputURLSerializer(instance).data
        )



@extend_schema(tags=["scope"])
class InputURLViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet
):
    queryset = InputURL.objects.select_related(
        "flow",
        "flow__engagement",
    ).prefetch_related(
        "scenarios"
    ).order_by("id")

    serializer_class = InputURLSerializer
    filter_backends = (DjangoFilterBackend,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasInputFlowPermission,
    )

    def get_queryset(self):
        return self.queryset.filter(
            flow__engagement__in=get_authorized_engagements(Permissions.Input_Flow_View))

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return http_response.ok(
            message="Consulta de URL realizada correctamente.",
            data=serializer.data
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        return http_response.ok(
            message=f"Se actualizó la URL {instance.url} correctamente.",
            data=self.get_serializer(instance).data
        )

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="add_scenario")
    def add_scenario(self, request, pk=None):
        url_instance = self.get_object()

        serializer = InputScenarioSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        instance = serializer.save(url=url_instance)

        return http_response.ok(
            message=f"Se agregó un escenario a la URL {url_instance.url} correctamente.",
            data=InputScenarioSerializer(instance).data
        )

@extend_schema(tags=["scope"])
class InputScenarioViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet
):
    queryset = InputScenario.objects.select_related(
        "url",
        "url__flow",
        "url__flow__engagement",
    ).order_by("id")

    serializer_class = InputScenarioSerializer

    filter_backends = (DjangoFilterBackend,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasInputFlowPermission,
    )

    def get_queryset(self):
        return self.queryset.filter(
            url__flow__engagement__in=get_authorized_engagements(Permissions.Input_Flow_View))

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        return http_response.ok(
            message=f"Se actualizó el escenario {instance.id} correctamente.",
            data=self.get_serializer(instance).data
        )
