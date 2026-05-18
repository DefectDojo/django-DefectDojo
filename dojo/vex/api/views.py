"""CycloneDX VEX export — serializes Dojo triage decisions as a VEX document."""
import datetime
import json
import uuid

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.models import Engagement, Finding, Product
from dojo.authorization.roles_permissions import Permissions


CYCLONEDX_SPEC_VERSION = "1.4"
DOJO_TOOL_NAME = "DefectDojo"


def _finding_to_vex_state(finding: Finding) -> tuple[str, list[str]]:
    """Return (analysisState, responses[]) for a finding.

    Priority: false_p > risk_accepted > mitigated > active+verified > in_triage
    """
    if finding.false_p:
        return "false_positive", []
    if finding.risk_accepted:
        return "exploitable", ["will_not_fix"]
    if finding.is_mitigated and not finding.active:
        return "resolved", []
    if finding.active and finding.verified:
        return "exploitable", []
    return "in_triage", []


def _finding_to_vex_entry(finding: Finding) -> dict | None:
    """Serialize one finding as a CycloneDX vulnerability entry."""
    vuln_id = finding.vuln_id_from_tool
    if not vuln_id:
        ids = list(finding.vulnerability_id_set.values_list("vulnerability_id", flat=True))
        if not ids:
            return None
        vuln_id = ids[0]

    purl = finding.component_purl
    if not purl:
        name = (finding.component_name or "").lower()
        version = finding.component_version or ""
        purl = f"pkg:generic/{name}@{version}" if name else None
    if not purl:
        return None

    state, responses = _finding_to_vex_state(finding)
    analysis: dict = {"state": state}
    if responses:
        analysis["response"] = responses

    latest_note = finding.notes.order_by("-date").first()
    if latest_note:
        analysis["detail"] = latest_note.entry

    entry: dict = {
        "id": vuln_id,
        "affects": [{"ref": purl}],
        "analysis": analysis,
    }
    return entry


def _build_vex_document(findings, product_name: str) -> dict:
    entries = []
    for f in findings:
        entry = _finding_to_vex_entry(f)
        if entry is not None:
            entries.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"name": product_name, "type": "application"},
            "tools": [{"name": DOJO_TOOL_NAME}],
        },
        "vulnerabilities": entries,
    }


class VexCycloneDxProductView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[OpenApiParameter("pk", int, OpenApiParameter.PATH, description="Product ID")],
        responses={(200, "application/json"): {}},
        summary="Export CycloneDX VEX for a product",
        description=(
            "Returns a CycloneDX VEX document containing triage decisions for all "
            "non-duplicate findings in the product. Excludes findings with no vuln ID or PURL."
        ),
    )
    def get(self, request: Request, pk: int) -> Response:
        product = Product.objects.get(pk=pk)
        user_is_authorized(request.user, Permissions.Product_View, product)

        findings = (
            Finding.objects.filter(
                test__engagement__product=product,
                duplicate=False,
            )
            .prefetch_related("notes", "vulnerability_id_set")
            .order_by("id")
        )
        vex = _build_vex_document(findings, product.name)
        return Response(vex, content_type="application/json")


class VexCycloneDxEngagementView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[OpenApiParameter("pk", int, OpenApiParameter.PATH, description="Engagement ID")],
        responses={(200, "application/json"): {}},
        summary="Export CycloneDX VEX for an engagement",
        description=(
            "Returns a CycloneDX VEX document scoped to a single engagement."
        ),
    )
    def get(self, request: Request, pk: int) -> Response:
        engagement = Engagement.objects.get(pk=pk)
        user_is_authorized(request.user, Permissions.Engagement_View, engagement)

        findings = (
            Finding.objects.filter(
                test__engagement=engagement,
                duplicate=False,
            )
            .prefetch_related("notes", "vulnerability_id_set")
            .order_by("id")
        )
        vex = _build_vex_document(findings, engagement.name)
        return Response(vex, content_type="application/json")
