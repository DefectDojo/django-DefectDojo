import mimetypes
from pathlib import Path

from django.conf import settings
from django.http import FileResponse
from django.urls import reverse
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2 import serializers as api_v2_serializers
from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.models import NoteHistory, Notes, Risk_Acceptance
from dojo.risk_acceptance.api.filters import ApiRiskAcceptanceFilter
from dojo.risk_acceptance.api.serializer import (
    RiskAcceptanceProofSerializer,
    RiskAcceptanceSerializer,
    RiskAcceptanceToNotesSerializer,
)
from dojo.risk_acceptance.helper import remove_finding_from_risk_acceptance
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.utils import process_tag_notifications


class RiskAcceptanceViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = RiskAcceptanceSerializer
    queryset = Risk_Acceptance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiRiskAcceptanceFilter

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasRiskAcceptancePermission,
    )

    def destroy(self, request, pk=None):
        instance = self.get_object()
        # Remove any findings on the risk acceptance
        for finding in instance.accepted_findings.all():
            remove_finding_from_risk_acceptance(request.user, instance, finding)
        # return the response of the object being deleted
        return super().destroy(request, pk=pk)

    def get_queryset(self):
        return (
            get_authorized_risk_acceptances("edit")
            .prefetch_related(
                "notes", "engagement_set", "owner", "accepted_findings",
            )
            .distinct()
        )

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: RiskAcceptanceToNotesSerializer,
        },
    )
    @extend_schema(
        methods=["POST"],
        request=api_v2_serializers.AddNewNoteOptionSerializer,
        responses={status.HTTP_201_CREATED: api_v2_serializers.NoteSerializer},
    )
    @action(detail=True, methods=["get", "post"], permission_classes=(IsAuthenticated, permissions.UserHasRiskAcceptanceRelatedObjectPermission))
    def notes(self, request, pk=None):
        risk_acceptance = self.get_object()
        if request.method == "POST":
            new_note = api_v2_serializers.AddNewNoteOptionSerializer(data=request.data)
            if new_note.is_valid():
                entry = new_note.validated_data["entry"]
                private = new_note.validated_data.get("private", False)
                note_type = new_note.validated_data.get("note_type", None)
            else:
                return Response(new_note.errors, status=status.HTTP_400_BAD_REQUEST)

            notes = risk_acceptance.notes.filter(note_type=note_type).first()
            if notes and note_type and note_type.is_single:
                return Response("Only one instance of this note_type allowed on a risk acceptance.", status=status.HTTP_400_BAD_REQUEST)

            author = request.user
            note = Notes(entry=entry, author=author, private=private, note_type=note_type)
            note.save()
            history = NoteHistory.objects.create(data=note.entry, time=note.date, current_editor=note.author)
            note.history.add(history)
            risk_acceptance.notes.add(note)
            engagement = risk_acceptance.engagement
            if engagement:
                process_tag_notifications(
                    request=request,
                    note=note,
                    parent_url=request.build_absolute_uri(
                        reverse("view_risk_acceptance", args=(engagement.id, risk_acceptance.id)),
                    ),
                    parent_title=f"Risk Acceptance: {risk_acceptance.name}",
                )

            serialized_note = api_v2_serializers.NoteSerializer(
                {"author": author, "entry": entry, "private": private},
            )
            return Response(serialized_note.data, status=status.HTTP_201_CREATED)

        notes = risk_acceptance.notes.all()
        serialized_notes = RiskAcceptanceToNotesSerializer(
            {"risk_acceptance_id": risk_acceptance, "notes": notes},
        )
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

    @extend_schema(
        methods=["GET"],
        responses={
            status.HTTP_200_OK: RiskAcceptanceProofSerializer,
        },
    )
    @action(detail=True, methods=["get"], permission_classes=(IsAuthenticated, permissions.UserHasRiskAcceptanceRelatedObjectPermission))
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
        # NOTE: FileResponse takes ownership of closing the file handle when the response is closed.
        # Explicitly register the closer to avoid potential resource leaks and satisfy static analyzers.
        file_handle = file_path.open("rb")
        # send file
        response = FileResponse(
            file_handle,
            content_type=mimetypes.guess_type(str(file_path))[0] or "application/octet-stream",
            status=status.HTTP_200_OK,
        )
        if hasattr(response, "_resource_closers"):
            response._resource_closers.append(file_handle.close)
        response["Content-Length"] = file_object.size
        response[
            "Content-Disposition"
        ] = f'attachment; filename="{risk_acceptance.filename()}"'

        return response
