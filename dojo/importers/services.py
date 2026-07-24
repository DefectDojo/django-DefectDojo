"""
Importer service facade (D7 / §6 OS1).

The current importer returns a 7-tuple and **no service wrapper exists today** -- the v2
``ImportScanSerializer`` calls ``DefaultImporter`` directly. This facade is framework-neutral (no
HTTP/DRF context): it constructs the importer options exactly as the v2 serializers do today
(``dojo/api_v2/serializers.py:526-903`` are the reference implementations; they are not modified)
and unpacks the 7-tuple into a structured ``ImportResult``.

The importer 7-tuple is ``(test, updated_count, new, closed, reactivated, untouched,
test_import)`` for both the importer and the reimporter (the importer always reports
reactivated/untouched as 0). See ``default_importer.py:165`` / ``default_reimporter.py:165``.

I6: keyword-only args, explicit ``user``, returns a result dataclass, callable without any HTTP
context. In the alpha PR only v3 calls this; v2 migrates onto it in the CONV1 convergence track.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.utils import timezone

from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Dojo_User

if TYPE_CHECKING:
    from datetime import date

    from django.core.files.uploadedfile import UploadedFile

    from dojo.models import Engagement, Test, Test_Import


@dataclass(frozen=True)
class ImportResult:

    """Structured import/reimport outcome (§4.13)."""

    test: Test
    mode_resolved: str                    # "import" | "reimport"
    new: int
    closed: int
    reactivated: int
    untouched: int
    test_import: Test_Import | None
    close_old_findings: bool              # effective value
    do_not_reactivate: bool               # effective value


def _resolve_environment(name: str | None, *, auto_create: bool) -> Development_Environment:
    """Mirror ``setup_common_context`` environment resolution (§ v2 serializer)."""
    name = name or "Development"
    if auto_create:
        return Development_Environment.objects.get_or_create(name=name)[0]
    try:
        return Development_Environment.objects.get(name=name)
    except Development_Environment.DoesNotExist:
        msg = f"Environment named {name} does not exist."
        raise ValueError(msg)


def _aware_scan_date(scan_date: date | datetime | None) -> datetime | None:
    """Make the scan date timezone-aware exactly as the v2 serializer does."""
    if scan_date is None:
        return None
    if isinstance(scan_date, datetime):
        return timezone.make_aware(scan_date) if timezone.is_naive(scan_date) else scan_date
    return timezone.make_aware(datetime.combine(scan_date, datetime.min.time()))


def _build_options(
    *,
    user: Dojo_User,
    scan_type: str,
    environment: Development_Environment,
    scan_date: datetime | None,
    minimum_severity: str,
    active: bool | None,
    verified: bool | None,
    tags: list[str] | None,
    service: str | None,
    version: str | None,
    group_by: str | None,
    test_title: str | None,
    deduplication_execution_mode: str | None,
    push_to_jira: bool,
    close_old_findings: bool,
    close_old_findings_product_scope: bool,
    do_not_reactivate: bool,
    extra: dict[str, Any],
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "user": user,
        "scan_type": scan_type,
        "environment": environment,
        "scan_date": scan_date,
        "minimum_severity": minimum_severity,
        "active": active,
        "verified": verified,
        "tags": tags,
        "service": service,
        "version": version,
        "group_by": group_by,
        "test_title": test_title,
        "deduplication_execution_mode": Dojo_User.resolve_deduplication_execution_mode(
            user, deduplication_execution_mode,
        ),
        "push_to_jira": push_to_jira,
        "close_old_findings": close_old_findings,
        "close_old_findings_product_scope": close_old_findings_product_scope,
        "do_not_reactivate": do_not_reactivate,
    }
    # Drop None values so the importer's own defaults apply (matches serializer behaviour where a
    # field absent from initial_data is not forced).
    options = {k: v for k, v in options.items() if v is not None}
    options.update(extra)
    return options


def _unpack(result_tuple: tuple, *, mode: str, close_old_findings: bool, do_not_reactivate: bool) -> ImportResult:
    test, _updated_count, new, closed, reactivated, untouched, test_import = result_tuple
    return ImportResult(
        test=test,
        mode_resolved=mode,
        new=new,
        closed=closed,
        reactivated=reactivated,
        untouched=untouched,
        test_import=test_import,
        close_old_findings=close_old_findings,
        do_not_reactivate=do_not_reactivate,
    )


def import_scan(
    *,
    user: Dojo_User,
    scan_file: UploadedFile | None,
    scan_type: str,
    engagement: Engagement,
    environment: str | None = "Development",
    auto_create_context: bool = False,
    minimum_severity: str = "Info",
    active: bool | None = None,
    verified: bool | None = None,
    close_old_findings: bool = False,
    close_old_findings_product_scope: bool = False,
    do_not_reactivate: bool = False,
    tags: list[str] | None = None,
    scan_date: date | datetime | None = None,
    service: str | None = None,
    version: str | None = None,
    test_title: str | None = None,
    group_by: str | None = None,
    deduplication_execution_mode: str | None = None,
    push_to_jira: bool = False,
    **extra: Any,
) -> ImportResult:
    """Import a scan into a new test on ``engagement`` (mirrors ``ImportScanSerializer.save()``)."""
    options = _build_options(
        user=user,
        scan_type=scan_type,
        environment=_resolve_environment(environment, auto_create=auto_create_context),
        scan_date=_aware_scan_date(scan_date),
        minimum_severity=minimum_severity,
        active=active,
        verified=verified,
        tags=tags,
        service=service,
        version=version,
        group_by=group_by,
        test_title=test_title,
        deduplication_execution_mode=deduplication_execution_mode,
        push_to_jira=push_to_jira,
        close_old_findings=close_old_findings,
        close_old_findings_product_scope=close_old_findings_product_scope,
        do_not_reactivate=do_not_reactivate,
        extra=extra,
    )
    options["engagement"] = engagement
    importer = DefaultImporter(**options)
    result_tuple = importer.process_scan(scan_file)
    return _unpack(result_tuple, mode="import", close_old_findings=close_old_findings, do_not_reactivate=do_not_reactivate)


def reimport_scan(
    *,
    user: Dojo_User,
    scan_file: UploadedFile | None,
    test: Test,
    scan_type: str | None = None,
    environment: str | None = "Development",
    auto_create_context: bool = False,
    minimum_severity: str = "Info",
    active: bool | None = None,
    verified: bool | None = None,
    close_old_findings: bool = True,
    close_old_findings_product_scope: bool = False,
    do_not_reactivate: bool = False,
    tags: list[str] | None = None,
    scan_date: date | datetime | None = None,
    service: str | None = None,
    version: str | None = None,
    test_title: str | None = None,
    group_by: str | None = None,
    deduplication_execution_mode: str | None = None,
    push_to_jira: bool = False,
    **extra: Any,
) -> ImportResult:
    """Reimport a scan into an existing ``test`` (mirrors ``ReImportScanSerializer.save()``)."""
    options = _build_options(
        user=user,
        scan_type=scan_type or test.test_type.name,
        environment=_resolve_environment(environment, auto_create=auto_create_context),
        scan_date=_aware_scan_date(scan_date),
        minimum_severity=minimum_severity,
        active=active,
        verified=verified,
        tags=tags,
        service=service,
        version=version,
        group_by=group_by,
        test_title=test_title,
        deduplication_execution_mode=deduplication_execution_mode,
        push_to_jira=push_to_jira,
        close_old_findings=close_old_findings,
        close_old_findings_product_scope=close_old_findings_product_scope,
        do_not_reactivate=do_not_reactivate,
        extra=extra,
    )
    options["test"] = test
    options["engagement"] = test.engagement
    reimporter = DefaultReImporter(**options)
    result_tuple = reimporter.process_scan(scan_file)
    return _unpack(result_tuple, mode="reimport", close_old_findings=close_old_findings, do_not_reactivate=do_not_reactivate)


def auto_import_scan(
    *,
    user: Dojo_User,
    scan_file: UploadedFile | None,
    scan_type: str,
    engagement: Engagement | None = None,
    test: Test | None = None,
    product_name: str | None = None,
    engagement_name: str | None = None,
    product_type_name: str | None = None,
    test_title: str | None = None,
    auto_create_context: bool = False,
    close_old_findings: bool | None = None,
    do_not_reactivate: bool = False,
    **kwargs: Any,
) -> ImportResult:
    """
    Resolve the target test via ``AutoCreateContextManager`` and dispatch to reimport (existing
    test) or import (new). Mirrors ``ReImportScanSerializer`` auto-create semantics: when a brand
    new test is created, ``close_old_findings`` is forced False (nothing to compare against).
    """
    auto = AutoCreateContextManager()
    context: dict[str, Any] = {
        "scan_type": scan_type,
        "engagement": engagement,
        "test": test,
        "product_name": product_name,
        "engagement_name": engagement_name,
        "product_type_name": product_type_name,
        "test_title": test_title,
        "auto_create_context": auto_create_context,
    }
    try:
        auto.process_import_meta_data_from_dict(context)
        context["product"] = auto.get_target_product_if_exists(**context)
        context["engagement"] = auto.get_target_engagement_if_exists(**context)
        target_test = auto.get_target_test_if_exists(**context)
    except (ValueError, TypeError) as exc:
        raise ValueError(str(exc))

    if target_test is not None:
        return reimport_scan(
            user=user,
            scan_file=scan_file,
            test=target_test,
            scan_type=scan_type,
            close_old_findings=True if close_old_findings is None else close_old_findings,
            do_not_reactivate=do_not_reactivate,
            auto_create_context=auto_create_context,
            test_title=test_title,
            **kwargs,
        )

    if auto_create_context:
        resolved_engagement = auto.get_or_create_engagement(**context)
        return import_scan(
            user=user,
            scan_file=scan_file,
            scan_type=scan_type,
            engagement=resolved_engagement,
            # Do not close old findings when creating a brand new test.
            close_old_findings=False,
            do_not_reactivate=do_not_reactivate,
            auto_create_context=auto_create_context,
            test_title=test_title,
            **kwargs,
        )

    msg = "A test could not be found, and auto_create_context was not enabled to create one."
    raise ValueError(msg)
