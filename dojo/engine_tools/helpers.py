# Utils
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from datetime import timedelta
from celery.utils.log import get_task_logger
from enum import Enum
from io import BytesIO
import boto3
import pandas as pd

# Dojo
from dojo.models import Finding, Dojo_Group, Notes, Vulnerability_Id
from dojo.group.queries import get_group_members_for_group
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.queries import tag_filter, priority_tag_filter
from dojo.celery import app
from dojo.user.queries import get_user
from dojo.notifications.helper import create_notification, EmailNotificationManger
from dojo.utils import get_full_url


logger = get_task_logger(__name__)


class Constants(Enum):
    VULNERABILITY_ID_HELP_TEXT = (
        "Vulnerability technical id from the source tool. "
        "Allows to track unique vulnerabilities."
    )
    ON_WHITELIST = "On Whitelist"
    ON_BLACKLIST = "On Blacklist"
    REVIEWERS_MAINTAINER_GROUP = settings.REVIEWER_GROUP_NAME
    APPROVERS_CYBERSECURITY_GROUP = settings.APPROVER_GROUP_NAME
    ENGINE_CONTAINER_TAG = settings.DD_CUSTOM_TAG_PARSER.get("twistlock")
    TAG_PRISMA = settings.FINDING_EXCLUSION_FILTER_TAGS.split(",")[0]
    TAG_TENABLE = settings.FINDING_EXCLUSION_FILTER_TAGS.split(",")[1]


def get_reviewers_members():
    reviewer_group = Dojo_Group.objects.filter(
        name=Constants.REVIEWERS_MAINTAINER_GROUP.value
    ).first()
    reviewer_members = get_group_members_for_group(reviewer_group)

    return [member.user.username for member in reviewer_members if member]


def get_approvers_members():
    approvers_group = Dojo_Group.objects.filter(
        name=Constants.APPROVERS_CYBERSECURITY_GROUP.value
    ).first()
    approvers_members = get_group_members_for_group(approvers_group)

    return [member.user.username for member in approvers_members if member]


def get_note(author, message):
    note, _ = Notes.objects.get_or_create(author=author, entry=message)
    return note


def has_valid_comments(finding_exclusion, user) -> bool:
    if user.is_superuser:
        return True
    for comment in finding_exclusion.discussions.all():
        if comment.author == user:
            return True

    return False


@app.task
def add_findings_to_whitelist(unique_id_from_tool, relative_url):
    findings_to_update = (
        Finding.objects.filter(
            Q(cve=unique_id_from_tool) | Q(vuln_id_from_tool=unique_id_from_tool),
            active=True,
        )
        .exclude(risk_status=Constants.ON_WHITELIST.value)
        .filter(tag_filter)
    )

    if findings_to_update.exists():
        finding_exclusion_url = get_full_url(relative_url)
        system_user = get_user(settings.SYSTEM_USER)
        message = f"Finding added to white list, for more details check the finding exclusion request: {finding_exclusion_url}"
        note = get_note(system_user, message)

    for finding in findings_to_update:
        if "white_list" not in finding.tags:
            finding.tags.add("white_list")
        finding.active = False
        finding.notes.add(note)
        finding.risk_status = Constants.ON_WHITELIST.value

    Finding.objects.bulk_update(findings_to_update, ["active", "risk_status"], 1000)
    logger.info(f"{findings_to_update.count()} findings added to whitelist.")


def accept_finding_exclusion_inmediately(finding_exclusion: FindingExclusion) -> None:
    finding_exclusion.status = "Accepted"
    finding_exclusion.final_status = "Accepted"
    finding_exclusion.accepted_at = timezone.now()
    finding_exclusion.accepted_by = finding_exclusion.reviewed_by
    finding_exclusion.status_updated_at = timezone.now()
    finding_exclusion.status_updated_by = finding_exclusion.reviewed_by
    finding_exclusion.expiration_date = timezone.now() + timedelta(
        days=int(settings.FINDING_EXCLUSION_EXPIRATION_DAYS)
    )
    finding_exclusion.save()

    relative_url = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
    add_findings_to_whitelist.apply_async(
        args=(
            finding_exclusion.unique_id_from_tool,
            str(relative_url),
        )
    )

    # Send notification to the developer owner
    create_notification(
        event="finding_exclusion_approved",
        subject=f"✅Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
        title=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
        description=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipients=[finding_exclusion.created_by.username],
        icon="check-circle",
        color_icon="#28a745",
    )


def check_prisma_and_tenable_cve(cve: str) -> tuple[bool, bool]:
    has_prisma_findings = (
        Finding.objects.filter(cve=cve, active=True)
        .filter(
            Q(tags__name__icontains=Constants.TAG_PRISMA.value)
            | Q(tags__name__icontains=Constants.ENGINE_CONTAINER_TAG.value)
        )
        .exists()
    )

    has_tenable_findings = Finding.objects.filter(
        cve=cve, active=True, tags__name__icontains=Constants.TAG_TENABLE.value
    ).exists()

    return has_prisma_findings, has_tenable_findings


def send_mail_to_cybersecurity(
    finding_exclusion: FindingExclusion, message: str
) -> None:
    email_notification_manager = EmailNotificationManger()
    recipient = None
    practice = finding_exclusion.practice

    cyber_providers = settings.PROVIDERS_CYBERSECURITY_EMAIL

    for key, value in cyber_providers.items():
        if key in practice:
            recipient = value

    if not recipient:
        has_prisma_findings, has_tenable_findings = check_prisma_and_tenable_cve(
            finding_exclusion.unique_id_from_tool
        )

        if has_prisma_findings:
            recipient = cyber_providers.get("prisma", "")

        if has_tenable_findings:
            recipient = cyber_providers.get("tenable", "")

    # The practice is not in the list of providers
    if not recipient:
        # Set approve status inmediately
        if finding_exclusion.type == "white_list":
            accept_finding_exclusion_inmediately(finding_exclusion)

        return

    devsecops_email = cyber_providers.get("devsecops", "")

    title = message
    description = message
    approvers = get_approvers_members()

    email_notification_manager.send_mail_notification(
        event="finding_exclusion_request",
        subject=f"✅{message}",
        user=None,
        title=title,
        description=description,
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipient=[recipient, devsecops_email],
    )

    create_notification(
        event="finding_exclusion_request",
        subject=f"🙋‍♂️{message}",
        title=message,
        description=message,
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipients=approvers,
        color_icon="#52A3FA",
    )


def remove_finding_from_list(finding: Finding, note: Notes, list_type: str) -> Finding:
    finding.risk_status = None
    finding.notes.add(note)

    if list_type == "white_list":
        if not finding.is_mitigated:
            finding.active = True
        finding.tags.remove("white_list") if "white_list" in finding.tags else None
    elif list_type == "black_list":
        finding.tags.remove("black_list") if "black_list" in finding.tags else None

    return finding


@app.task
def expire_finding_exclusion(expired_fex_id: str) -> None:
    expired_fex = FindingExclusion.objects.get(uuid=expired_fex_id)
    try:
        with transaction.atomic():
            expired_fex.status = "Expired"
            expired_fex.save()
            system_user = get_user(settings.SYSTEM_USER)
            logger.info(f"Expired finding exclusion: {expired_fex}")
            note = get_note(
                system_user,
                f"Finding has been removed from the {expired_fex.type} as it has expired.",
            )

            risk_status = (
                Constants.ON_BLACKLIST.value
                if expired_fex.type == "black_list"
                else Constants.ON_WHITELIST.value
            )

            findings = Finding.objects.filter(
                Q(cve=expired_fex.unique_id_from_tool)
                | Q(vuln_id_from_tool=expired_fex.unique_id_from_tool),
                risk_status=risk_status,
            ).prefetch_related("tags", "notes")

            findings_to_update = []

            for finding in findings:
                finding = remove_finding_from_list(finding, note, expired_fex.type)
                findings_to_update.append(finding)
                logger.info(f"Removed finding {finding.id} from {expired_fex.type}.")

            Finding.objects.bulk_update(
                findings_to_update, ["active", "risk_status"], 1000
            )

            maintainers = get_reviewers_members()
            approvers = get_approvers_members()

            create_notification(
                event="finding_exclusion_expired",
                subject=f"⚠️Finding Exclusion Expired - {expired_fex.unique_id_from_tool}",
                title=f"The finding exclusion for {expired_fex.unique_id_from_tool} has expired.",
                description=f"All findings added via this finding exclusion {expired_fex.unique_id_from_tool} will be removed from the {expired_fex.type}.",
                url=reverse("finding_exclusion", args=[str(expired_fex.pk)]),
                recipients=maintainers + approvers + [expired_fex.created_by.username],
                icon="exclamation-triangle",
                color_icon="#FABC5C",
            )
    except Exception as e:
        logger.error(f"Error processing expired exclusion {expired_fex.uuid}: {str(e)}")


@app.task
def expire_finding_exclusion_immediately(finding_exclusion_id: str) -> None:
    expire_finding_exclusion.apply_async(args=(str(finding_exclusion_id),))


@app.task
def check_expiring_findingexclusions():
    expired_finding_exclusions = FindingExclusion.objects.filter(
        status="Accepted", expiration_date__lt=timezone.now()
    )

    for expired_fex in expired_finding_exclusions:
        expire_finding_exclusion.apply_async(args=(str(expired_fex.uuid),))


@app.task
def check_new_findings_to_exclusion_list():
    finding_exclusions = FindingExclusion.objects.filter(status="Accepted")

    for finding_exclusion in finding_exclusions:
        relative_url = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
        if finding_exclusion.type == "white_list":
            add_findings_to_whitelist.apply_async(
                args=(
                    finding_exclusion.unique_id_from_tool,
                    relative_url,
                )
            )
        else:
            add_findings_to_blacklist.apply_async(
                args=(
                    finding_exclusion.unique_id_from_tool,
                    relative_url,
                )
            )


@app.task
def add_findings_to_blacklist(unique_id_from_tool, relative_url):
    findings_to_update = (
        Finding.objects.filter(
            Q(cve=unique_id_from_tool) | Q(vuln_id_from_tool=unique_id_from_tool),
            active=True,
        )
        .exclude(risk_status=Constants.ON_BLACKLIST.value)
        .filter(priority_tag_filter)
    )

    if findings_to_update.exists():
        finding_exclusion_url = get_full_url(relative_url)
        system_user = get_user(settings.SYSTEM_USER)
        message = f"Finding added to blacklist, for more details check the finding exclusion request: {finding_exclusion_url}"
        note = get_note(system_user, message)

    for finding in findings_to_update:
        if "black_list" not in finding.tags:
            finding.tags.add("black_list")
        finding.notes.add(note)
        finding.risk_status = Constants.ON_BLACKLIST.value

    Finding.objects.bulk_update(findings_to_update, ["risk_status"], 1000)
    findings_to_update_count = findings_to_update.count()
    logger.info(f"{findings_to_update_count} findings added to blacklist.")

    if findings_to_update_count > 0:
        blacklist_message = f"{findings_to_update_count} findings added to the blacklist. CVE: {unique_id_from_tool}."
        create_notification(
            event="finding_exclusion_request",
            subject=f"✅Findings added to blacklist with the CVE: {unique_id_from_tool}",
            title=blacklist_message,
            description=blacklist_message,
            url=relative_url,
            recipients=get_reviewers_members() + get_approvers_members(),
            color_icon="#52A3FA",
        )
        finding_exclusion = FindingExclusion.objects.filter(
            unique_id_from_tool=unique_id_from_tool,
            type="black_list",
            status="Accepted",
        ).first()
        send_mail_to_cybersecurity(finding_exclusion, blacklist_message)


def add_discussion_to_finding_exclusion(finding_exclusion) -> None:
    system_user = get_user(settings.SYSTEM_USER)
    content = "Created by the vulnerability prioritization check."

    discussion = FindingExclusionDiscussion(
        finding_exclusion=finding_exclusion, author=system_user, content=content
    )
    discussion.save()


@app.task
def update_finding_prioritization_per_cve(
    vulnerability_id, cve_greater, severity, scan_type, priorization
) -> None:
    priority_cve_severity_filter = Q()
    if vulnerability_id:
        if scan_type == "Tenable Scan":
            ids = (
                Vulnerability_Id.objects.filter(
                    vulnerability_id=cve_greater
                ).values_list("finding_id", flat=True)
                if cve_greater != vulnerability_id
                else []
            )
            priority_cve_severity_filter = (
                (Q(id__in=ids) & Q(severity=severity) & Q(cve=vulnerability_id) & ~Q(cve=None))
                if ids
                else (Q(severity=severity) & Q(cve=vulnerability_id) & ~Q(cve=None))
            )
        else:
            priority_cve_severity_filter = (Q(cve=vulnerability_id) & ~Q(cve=None)) | (
                Q(vuln_id_from_tool=vulnerability_id) & ~Q(vuln_id_from_tool=None)
            )
    else:
        priority_cve_severity_filter = Q(severity=severity) & Q(cve=None)

    findings = Finding.objects.filter(
        priority_cve_severity_filter, test__scan_type=scan_type
    ).filter(priority_tag_filter)
    for finding_update in findings:
        finding_update.priority = priorization
        finding_update.set_sla_expiration_date()

    Finding.objects.bulk_update(findings, ["priority", "sla_expiration_date"], 1000)
    return f"{vulnerability_id} with severity {severity} of {scan_type} with {findings.count()} findings updated with prioritization {priorization}"


def identify_priority_vulnerabilities(findings) -> int:
    """
    Identifies priority vulnerabilities based on risk score and adds them to the blacklist.

    Args:
        findings (QuerySet): Set of vulnerabilities from the Finding model
    """
    system_user = get_user(settings.SYSTEM_USER)

    severity_risk_map = {
        "Low": float(settings.PRIORIZATION_FIELD_WEIGHTS.get("P_Low")),
        "Medium": float(settings.PRIORIZATION_FIELD_WEIGHTS.get("P_Medium")),
        "High": float(settings.PRIORIZATION_FIELD_WEIGHTS.get("P_High")),
        "Critical": float(settings.PRIORIZATION_FIELD_WEIGHTS.get("P_Critical")),
    }

    try:

        # Read the risk score file from the S3 bucket with boto3
        s3 = boto3.client("s3")
        response = s3.get_object(
            Bucket=settings.BUCKET_NAME_RISK_SCORE, Key=settings.PATH_FILE_RISK_SCORE
        )

        # Get the parquet content
        parquet_content = response["Body"].read()
        df_risk_score = pd.read_parquet(BytesIO(parquet_content))

    except Exception as e:
        logger.error(f"Error reading risk score file: {e}")
        df_risk_score = pd.DataFrame(columns=["cve", "prediction"])

    for finding in findings:
        cve_greater = None
        if not df_risk_score.empty and finding.cve:
            cve_greater = finding.cve
            if Constants.TAG_TENABLE.value in finding.tags:
                vulnerabilities_id = finding.vulnerability_ids
                priority = 0
                for vuln_id in vulnerabilities_id:
                    loc_res = df_risk_score.loc[
                        df_risk_score["cve"] == vuln_id, "prediction"
                    ].values
                    if loc_res.size > 0:
                        if float(loc_res[0]) > priority:
                            cve_greater = vuln_id
                            priority = float(loc_res[0])
                    else:
                        priority = severity_risk_map.get(finding.severity, 0)
            else:
                loc_res = df_risk_score.loc[
                    df_risk_score["cve"] == finding.cve, "prediction"
                ].values
                if loc_res.size > 0:
                    priority = float(loc_res[0])
                else:
                    priority = severity_risk_map.get(finding.severity, 0)
        else:
            priority = severity_risk_map.get(finding.severity, 0)

        update_finding_prioritization_per_cve.apply_async(
            args=(finding.cve, cve_greater, finding.severity, finding.test.scan_type, priority)
        )

        if priority >= float(
            settings.PRIORIZATION_FIELD_WEIGHTS.get("minimum_prioritization")
        ):
            finding_exclusion = FindingExclusion.objects.filter(
                unique_id_from_tool=finding.cve, type="black_list", status="Accepted"
            )

            if not finding_exclusion.exists():
                new_finding_exclusion = FindingExclusion(
                    type="black_list",
                    unique_id_from_tool=finding.cve,
                    expiration_date=None,
                    status_updated_at=timezone.now(),
                    status_updated_by=system_user,
                    reviewed_at=None,
                    reason="Highly exploitable vulnerability.",
                    status="Accepted",
                    final_status="Accepted",
                    created_by=system_user,
                    accepted_by=system_user,
                )
                new_finding_exclusion.save()
                relative_url = reverse(
                    "finding_exclusion", args=[str(new_finding_exclusion.pk)]
                )
                add_discussion_to_finding_exclusion(finding_exclusion)
                add_findings_to_blacklist.apply_async(
                    args=(new_finding_exclusion.unique_id_from_tool, relative_url)
                )
            else:
                fx = finding_exclusion.first()
                relative_url = reverse("finding_exclusion", args=[str(fx.pk)])
                add_findings_to_blacklist.apply_async(
                    args=(fx.unique_id_from_tool, relative_url)
                )


@app.task
def check_priorization():
    # Get all vulnerabilities with priority tag filter
    all_vulnerabilities = (
        Finding.objects.filter(priority_tag_filter)
        .order_by("cve", "test__scan_type", "severity")
        .distinct("cve", "test__scan_type", "severity")
    )

    logger.info(f"Identified {len(all_vulnerabilities)} vulnerabilities for prioritization.")

    # Identify priority vulnerabilities
    identify_priority_vulnerabilities(all_vulnerabilities)


@app.task
def remove_findings_from_deleted_finding_exclusions(
    unique_id_from_tool: str, fx_type: str
) -> None:
    try:
        with transaction.atomic():
            system_user = get_user(settings.SYSTEM_USER)
            note = get_note(
                system_user,
                f"Finding has been removed from the {fx_type} as it has deleted.",
            )

            is_active = True if fx_type == "black_list" else False
            risk_status = (
                Constants.ON_BLACKLIST.value
                if fx_type == "black_list"
                else Constants.ON_WHITELIST.value
            )

            findings = Finding.objects.filter(
                Q(cve=unique_id_from_tool) | Q(vuln_id_from_tool=unique_id_from_tool),
                active=is_active,
                risk_status=risk_status,
            ).prefetch_related("tags", "notes")

            findings_to_update = []

            for finding in findings:
                finding = remove_finding_from_list(finding, note, fx_type)
                findings_to_update.append(finding)
                logger.info(f"Removed finding {finding.id} from {fx_type}.")

            Finding.objects.bulk_update(
                findings_to_update, ["active", "risk_status"], 1000
            )

    except Exception as e:
        logger.error(
            f"Error processing deleted exclusion {unique_id_from_tool}: {str(e)}"
        )

