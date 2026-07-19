"""
Finding write service for API v3 (D7 -- the flagship service extraction).

This module is the single home for finding create/update/delete orchestration and side-effects
(JIRA push + keep-in-sync, risk-acceptance processing, vulnerability-id / CWE persistence, found_by
handling, mitigated-field edit rules, status invariants, deletion dedup/grading hooks). It is
written to serve *all three* consumers (v2 serializer, UI views, v3 routes), but in the alpha PR only
v3 calls it -- so the additive property (D1) is preserved. The v2 ``FindingSerializer`` /
``FindingCreateSerializer`` and the UI ``EditFinding`` view remain the live implementations and are
**not modified** here.

Extraction rule (D7): the functions below reconcile *both* reference implementations --
``dojo/finding/api/serializer.py`` (``FindingSerializer.update``/``validate`` and
``FindingCreateSerializer.create``/``validate``) and the UI flow in ``dojo/finding/ui/views.py``
(``EditFinding.process_finding_form`` / ``process_jira_form`` / ``process_forms``). Where they
diverge, the canonical behavior chosen here is recorded in API_V3_PLAN.md §12 (see the OS3b
divergence entry). The serializer path is the primary reference (the plan names it), so where the UI
adds API-absent side-effects (last_reviewed stamping, mitigated-status propagation to location edges,
false-positive history, burp req/resp, finding-group handling, github, jira link/unlink) those are
consciously **deferred** to the convergence track rather than baked into the API here.

Invariant I6: keyword-only args, an explicit ``user``, no HTTP context. Validation failures raise
``rest_framework.exceptions.ValidationError`` -- exactly the exception the reference serializer
raises -- which the v3 kernel error boundary maps to a 400 ``application/problem+json`` (§12 OS1).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from crum import get_current_request
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.finding.helper import (
    can_edit_mitigated_data,
    save_cwes,
    save_vulnerability_ids,
)
from dojo.jira import services as jira_services
from dojo.models import SEVERITIES, Dojo_User, Finding, Test_Type
from dojo.notifications.helper import async_create_notification, process_tag_notifications
from dojo.utils import get_object_or_none

if TYPE_CHECKING:
    from dojo.models import Test
    from dojo.notes.models import Notes

logger = logging.getLogger(__name__)

# Distinguishes "key absent" from "key present with value None" in a PATCH change set.
_UNSET = object()

# Scalar Finding fields consumed via **kwargs on create; relations/side-effect keys are handled
# explicitly (popped) before this set is applied.
_SPECIAL_KEYS = frozenset({"reporter", "mitigated_by", "found_by", "tags", "vulnerability_ids", "push_to_jira", "test"})


# --- shared validation (ported from FindingSerializer.validate / FindingCreateSerializer.validate) --

def _validate_severity(severity: str) -> None:
    if severity is not None and severity not in SEVERITIES:
        msg = f"Severity must be one of the following: {SEVERITIES}"
        raise ValidationError({"severity": [msg]})


def _validate_mitigated_editable(data: dict, user) -> None:
    """Mirror the serializer's mitigated-field editability gate (settings.EDITABLE_MITIGATED_DATA)."""
    attempting = any(
        (field in data) and (data.get(field) is not None)
        for field in ("mitigated", "mitigated_by")
    )
    if attempting and not can_edit_mitigated_data(user):
        errors = {}
        if ("mitigated" in data) and (data.get("mitigated") is not None):
            errors["mitigated"] = ["Editing mitigated timestamp is disabled (EDITABLE_MITIGATED_DATA=false)"]
        if ("mitigated_by" in data) and (data.get("mitigated_by") is not None):
            errors["mitigated_by"] = ["Editing mitigated_by is disabled (EDITABLE_MITIGATED_DATA=false)"]
        if errors:
            raise ValidationError(errors)


def _validate_status_invariants(*, is_active, is_verified, is_duplicate, is_false_p,
                                is_risk_accepted, product, was_risk_accepted) -> None:
    """Port the active/verified/duplicate/false_p/risk_accepted invariants (both serializers)."""
    if (is_active or is_verified) and is_duplicate:
        msg = "Duplicate findings cannot be verified or active"
        raise ValidationError(msg)
    if is_false_p and is_verified:
        msg = "False positive findings cannot be verified."
        raise ValidationError(msg)
    if is_risk_accepted and not was_risk_accepted and not product.enable_simple_risk_acceptance:
        msg = "Simple risk acceptance is disabled for this product, use the UI to accept this finding."
        raise ValidationError(msg)
    if is_active and is_risk_accepted:
        msg = "Active findings cannot be risk accepted."
        raise ValidationError(msg)


def _process_risk_acceptance(finding: Finding, changes: dict, user) -> None:
    """
    Port ``FindingSerializer.process_risk_acceptance`` (runs in validate(), i.e. before field
    updates). No-op unless ``risk_accepted`` is an explicit bool in the change set.
    """
    import dojo.risk_acceptance.helper as ra_helper  # noqa: PLC0415 -- lazy import, avoids circular dependency

    is_risk_accepted = changes.get("risk_accepted")
    if not isinstance(is_risk_accepted, bool):
        return
    if (is_risk_accepted and not finding.risk_accepted
            and finding.test.engagement.product.enable_simple_risk_acceptance
            and not changes.get("active")):
        ra_helper.simple_risk_accept(user, finding)
    elif not is_risk_accepted and finding.risk_accepted:
        ra_helper.risk_unaccept(user, finding)


def _resolve_user(pk: int) -> Dojo_User:
    user = get_object_or_none(Dojo_User, pk=pk)
    if user is None:
        raise ValidationError({"reporter": [f"user {pk} does not exist"]})
    return user


def _resolve_test_types(ids: list[int]) -> list[Test_Type]:
    resolved = []
    for pk in ids:
        tt = get_object_or_none(Test_Type, pk=pk)
        if tt is None:
            raise ValidationError({"found_by": [f"Test_Type {pk} does not exist"]})
        resolved.append(tt)
    return resolved


# --- public service API (I6) ------------------------------------------------------------------

def create_finding(*, test: Test, data: dict, user, push_to_jira: bool = False,
                   vulnerability_ids: list[str] | None = None) -> Finding:
    """
    Create a finding under ``test``. Ports ``FindingCreateSerializer.create``/``validate``:
    reporter defaulting, status invariants, vulnerability-id + CWE persistence, found_by, JIRA push,
    and the ``finding_added`` notification.
    """
    data = {k: v for k, v in data.items() if k not in _SPECIAL_KEYS or k in {"reporter", "mitigated_by", "found_by", "tags"}}

    _validate_severity(data.get("severity"))
    _validate_mitigated_editable(data, user)
    _validate_status_invariants(
        is_active=data.get("active"),
        is_verified=data.get("verified"),
        is_duplicate=data.get("duplicate"),
        is_false_p=data.get("false_p"),
        is_risk_accepted=data.get("risk_accepted"),
        product=test.engagement.product,
        was_risk_accepted=False,
    )

    reporter_id = data.pop("reporter", None)
    reporter = _resolve_user(reporter_id) if reporter_id is not None else user
    mitigated_by_id = data.pop("mitigated_by", None)
    mitigated_by = _resolve_user(mitigated_by_id) if mitigated_by_id is not None else None
    found_by_ids = data.pop("found_by", None)
    tags = data.pop("tags", None)

    scalars = {k: v for k, v in data.items() if v is not None}
    # Mirror the serializer: the first vuln id is written into `cve` *before* the initial save so it
    # is persisted (save_vulnerability_ids below only sets it in memory).
    if vulnerability_ids:
        scalars["cve"] = vulnerability_ids[0]
    new_finding = Finding(test=test, reporter=reporter, **scalars)
    if mitigated_by is not None:
        new_finding.mitigated_by = mitigated_by
    # Persist vuln ids so model save computes the hash including them (mirror the serializer).
    new_finding.unsaved_vulnerability_ids = vulnerability_ids or []
    new_finding.save()

    if found_by_ids:
        new_finding.found_by.set(_resolve_test_types(found_by_ids))
    if vulnerability_ids:
        save_vulnerability_ids(new_finding, vulnerability_ids)
    # Create always persists the primary Finding.cwe as a Finding_CWE row (mirror serializer).
    save_cwes(new_finding)
    if tags is not None:
        new_finding.tags = tags
        new_finding.save()

    if push_to_jira:
        jira_services.push(new_finding)

    dojo_dispatch_task(
        async_create_notification,
        event="finding_added",
        title=_("Addition of %s") % new_finding.title,
        finding_id=new_finding.id,
        description=_('Finding "%s" was added by %s') % (new_finding.title, new_finding.reporter),
        url=reverse("view_finding", args=(new_finding.id,)),
        icon="exclamation-triangle",
    )
    return new_finding


def update_finding(finding: Finding, *, changes: dict, user, push_to_jira: bool = False,
                   vulnerability_ids: list[str] | None = None) -> Finding:
    """
    Update ``finding`` from a partial ``changes`` dict. Ports ``FindingSerializer.update``/
    ``validate``: mitigated-edit rules, status invariants (PATCH defaults from the instance),
    risk-acceptance processing, vulnerability-id + CWE persistence, found_by set/clear, reporter,
    and the synchronous JIRA push (force_sync, raising on failure) + keep-in-sync.
    """
    changes = dict(changes)

    if "severity" in changes:
        _validate_severity(changes["severity"])
    _validate_mitigated_editable(changes, user)
    _validate_status_invariants(
        is_active=changes.get("active", finding.active),
        is_verified=changes.get("verified", finding.verified),
        is_duplicate=changes.get("duplicate", finding.duplicate),
        is_false_p=changes.get("false_p", finding.false_p),
        is_risk_accepted=changes.get("risk_accepted", finding.risk_accepted),
        product=finding.test.engagement.product,
        was_risk_accepted=finding.risk_accepted,
    )
    # Runs before the field updates (mirrors validate() -> process_risk_acceptance ordering).
    _process_risk_acceptance(finding, changes, user)

    reporter_id = changes.pop("reporter", None)
    if reporter_id is not None:
        finding.reporter = _resolve_user(reporter_id)
    mitigated_by = changes.pop("mitigated_by", _UNSET)
    if mitigated_by is not _UNSET:
        finding.mitigated_by = _resolve_user(mitigated_by) if mitigated_by is not None else None
    found_by_ids = changes.pop("found_by", _UNSET)
    tags = changes.pop("tags", _UNSET)
    cwe_provided = "cwe" in changes

    # Persist vuln ids first so model save computes the hash including them (mirror serializer).
    if vulnerability_ids:
        save_vulnerability_ids(finding, vulnerability_ids)

    if found_by_ids is not _UNSET:
        if found_by_ids:
            finding.found_by.set(_resolve_test_types(found_by_ids))
        else:
            finding.found_by.clear()

    for key, value in changes.items():
        setattr(finding, key, value)
    finding.save()

    # v3 exposes a scalar `cwe` (not the v2 nested `cwes` list), so resync the Finding_CWE rows
    # whenever `cwe` is updated -- keeps Finding.cwe and its Finding_CWE rows consistent (§12).
    if cwe_provided:
        save_cwes(finding)

    if tags is not _UNSET:
        finding.tags = tags if tags is not None else []
        finding.save()

    if push_to_jira or jira_services.is_keep_in_sync(finding):
        success, message = jira_services.push(finding, force_sync=True)
        if not success:
            raise ValidationError(message)
    return finding


def delete_finding(finding: Finding, *, user, push_to_jira: bool | None = None) -> None:
    """
    Delete ``finding``. Mirrors the v2 ``FindingViewSet.destroy`` calculation/dedup hooks: the
    model's ``Finding.delete()`` runs ``finding_helper.finding_delete`` (dedup reassignment) and
    ``perform_product_grading`` (§12). ``user`` is part of the service contract (I6); the model
    resolves the acting user via crum.

    ``push_to_jira`` is the v2 tri-state: ``None`` (default) lets the JIRA delete-sync run with its
    default semantics — exactly what v2's ``destroy`` passes when the query param is absent. Passing
    no value at all would hit ``Finding.delete()``'s suppress-sentinel and silently skip the JIRA
    close/reassign (divergence D17, a confirmed v3 regression — see API_V3_DIVERGENCE_ANALYSIS.md).
    """
    logger.debug("api_v3 delete_finding id=%s by user=%s", finding.pk, getattr(user, "username", user))
    finding.delete(push_to_jira=push_to_jira)


def process_note_added(finding: Finding, note: Notes, *, user) -> None:
    """
    Fire the same side-effects as the v2 finding notes ``@action`` create branch
    (``dojo/finding/api/views.py`` -- ``finding.last_reviewed`` stamping, ``process_tag_notifications``,
    and ``jira_services.add_comment``) after a note has been persisted and linked to ``finding``:

    1. ``last_reviewed`` / ``last_reviewed_by`` stamping (finding notes only -- engagement/test don't);
    2. @mention notifications -- the **exact** v2 parsing/notification helper is reused, not reimplemented;
    3. JIRA comment sync on the finding's linked issue, else its finding-group issue -- same conditions as v2.

    I6: keyword-only ``user``, no HTTP object in the signature. The v2 @mention helper
    (``process_tag_notifications``) needs the request to build the absolute mention URL, so it is read
    from crum -- set for the whole request by ``CurrentRequestUserMiddleware``, the same context bridge
    ``delete_finding`` relies on. With no request available (a pure non-HTTP call) mentions are skipped
    while the other side-effects still fire (§12).
    """
    # (1) last_reviewed / last_reviewed_by stamping -- mirrors the v2 finding notes @action exactly.
    finding.last_reviewed = note.date
    finding.last_reviewed_by = user
    finding.save(update_fields=["last_reviewed", "last_reviewed_by", "updated"])

    # (2) @mention notifications -- reuse the exact v2 parsing/notification code path.
    request = get_current_request()
    if request is not None:
        process_tag_notifications(
            request=request,
            note=note,
            parent_url=request.build_absolute_uri(reverse("view_finding", args=(finding.id,))),
            parent_title=f"Finding: {finding.title}",
        )

    # (3) JIRA comment sync -- same conditions as v2 (linked issue, else finding-group issue).
    if finding.has_jira_issue:
        jira_services.add_comment(finding, note)
    elif finding.has_jira_group_issue:
        jira_services.add_comment(finding.finding_group, note)
