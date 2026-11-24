import logging
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import mixins, status, viewsets
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated 
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth.models import Permission
from dojo.api_v2 import (
    permissions,
    prefetch,
    serializers,
)
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    OpenApiTypes,
)
from dojo.risk_acceptance.risk_pending import (
    accept_or_reject_risk_bulk,
    get_user_with_permission_key)
from dojo.risk_acceptance.notification import Notification as NotificationRiskAcceptance
from dojo.risk_acceptance.serializers import RiskAcceptanceEmailSerializer
from dojo.api_v2.risk_acceptance.serializers import RiskAcceptanceToNotesSerializer
from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.models import Risk_Acceptance, Notes
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.risk_acceptance.helper import remove_finding_from_risk_acceptance
from dojo.filters import ApiRiskAcceptanceFilter 
from dojo.authorization.roles_permissions import Permissions
from dojo.api_v2.api_error import ApiError
from dojo.api_v2.utils import http_response
from dojo.api_v2 import serializers
from dojo.api_v2.risk_acceptance.user_case import UseCaseRiskAcceptance

logger = logging.getLogger(__name__)


class RiskAcceptanceViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = serializers.RiskAcceptanceSerializer
    queryset = Risk_Acceptance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiRiskAcceptanceFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasRiskAcceptancePermission,
    )

    def create(self, request, *args, **kwargs):
        serializers  = self.serializer_class(data=request.data, context={"request": request})
        serializers.is_valid(raise_exception=True)
        use_case = UseCaseRiskAcceptance(
            validate_data=serializers.validated_data,
            request=request
        )
        risk_acceptance_obj = use_case.execute()
        serializer_response = self.serializer_class(risk_acceptance_obj)
        return http_response.created(serializer_response.data)

    def put(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return response


    def destroy(self, request, pk=None):
        instance = self.get_object()
        # Remove any findings on the risk acceptance
        for finding in instance.accepted_findings.all():
            remove_finding_from_risk_acceptance(request.user, instance, finding)
        # return the response of the object being deleted
        return super().destroy(request, pk=pk)

    def get_queryset(self):
        return (
            get_authorized_risk_acceptances(Permissions.Risk_Acceptance)
            .prefetch_related(
                "notes", "engagement_set", "owner", "accepted_findings",
            )
            .distinct().order_by("-id")
        )
    
    @action(
            methods=["POST"],
            detail=True,
            parser_classes=[MultiPartParser, FormParser]
    )
    def upload_file(self, request, pk=None):
        risk_acceptance = get_object_or_404(Risk_Acceptance, id=pk)
        if "file" not in request.FILES:
            return http_response.bad_request(message="File not found")
        uploaded_file = request.FILES["file"]
        risk_acceptance.path = uploaded_file
        risk_acceptance.save()
        return http_response.ok(message="File uploaded succesfully")

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: serializers.RiskAcceptanceProofSerializer,
        },
    )
    @action(detail=True, methods=["get"])
    def download_proof(self, request, pk=None):
        risk_acceptance = self.get_object()
        # Get the file object
        file_object = risk_acceptance.path
        if file_object is None or risk_acceptance.filename() is None:
            return Response(
                {"error": "Proof has not provided to this risk acceptance..."},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Get the path of the file in media root
        file_path = Path(settings.MEDIA_ROOT) / file_object.name
        file_handle = file_path.open("rb")
        # send file
        response = FileResponse(
            file_handle,
            content_type=f"{mimetypes.guess_type(str(file_path))}",
            status=status.HTTP_200_OK,
        )
        response["Content-Length"] = file_object.size
        response[
            "Content-Disposition"
        ] = f'attachment; filename="{risk_acceptance.filename()}"'

        return response
    
    @extend_schema(
        methods=["POST"],
        responses=None,
        request=RiskAcceptanceEmailSerializer,
    )
    @action(detail=True, methods=["post"])
    def accept_bulk(self, request, pk=None):
        risk_acceptance = get_object_or_404(Risk_Acceptance.objects, id=pk)
        eng = Risk_Acceptance.objects.get(id=pk).accepted_findings.all().first().test.engagement
        product = eng.product
        product_type = product.prod_type
        permission_key = request.data.get("permission_key", None)
        action = request.data.get("actions", None)
        try:
            accept_or_reject_risk_bulk(
                eng=eng,
                risk_acceptance=risk_acceptance,
                product=product,
                product_type=product_type,
                action=action,
                permission_key=permission_key)

            logger.info("send message of confirmation for leader(s)")
            NotificationRiskAcceptance.proccess_confirmation(
                risk_pending=risk_acceptance,
                error=action,
                user_leader=get_user_with_permission_key(permission_key)
            )
            return http_response.ok(message="Acceptance process successfully completed")
        except Exception as e:
            logger.error(f"Failed accept bulk: {e}")
            NotificationRiskAcceptance.proccess_confirmation(
                    risk_pending=risk_acceptance,
                    user_leader=get_user_with_permission_key(permission_key, raise_exception=False),
                    error=str(e),
                    product=product.name,
                    product_type=product_type.name
                )
            raise ApiError.internal_server_error(detail=str(e))

    @extend_schema(
        methods=["POST"],
        request=serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"])
    def notes(self, request, pk=None):
        risk_acceptance = self.get_object()
        if request.method == "POST":
            new_note = serializers.AddNewNoteOptionSerializer(
                data=request.data,
            )
            if new_note.is_valid():
                entry = new_note.validated_data["entry"]
                private = new_note.validated_data.get("private", False)
                note_type = new_note.validated_data.get("note_type", None)
            else:
                return Response(
                    new_note.errors, status=status.HTTP_400_BAD_REQUEST,
                )

            notes = risk_acceptance.notes.filter(note_type=note_type).first()
            if notes and note_type and note_type.is_single:
                return Response("Only one instance of this note_type allowed on an engagement.", status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            notes = Notes(
                entry=entry,
                author=author,
                private=private,
                note_type=note_type,
            )
            notes.save()
            risk_acceptance.notes.add(notes)

            serialized_note = serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(
                serialized_note.data, status=status.HTTP_201_CREATED,
            )
        notes = risk_acceptance.notes.all()

        serialized_notes = RiskAcceptanceToNotesSerializer(
            {"risk_acceptance": risk_acceptance, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)