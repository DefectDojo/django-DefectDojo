# Utils
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from django.core.cache import cache
from datetime import timedelta
from celery.utils.log import get_task_logger
from enum import Enum
from io import BytesIO
import boto3
import pandas as pd
import csv
import datetime
import gzip
import io
import requests

# Dojo
from dojo.models import Finding, Dojo_Group, Notes, Vulnerability_Id
from dojo.group.queries import get_group_members_for_group
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.queries import tag_filter, priority_tag_filter
from dojo.celery import app
from dojo.user.queries import get_user
from dojo.notifications.helper import create_notification, EmailNotificationManger
from dojo.utils import get_full_url
from django.db.models import Count

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
    TAG_HACKING = settings.PROVIDERS.split("//")[0]


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
    finding: Finding,
    cve_greater,
    priorization,
    epss_score,
    epss_percentile,
    known_exploited,
    ransomware_used,
    kev_date_added,
) -> None:

    priority_cve_severity_filter = Q()
    vulnerability_id = finding.cve
    severity = finding.severity
    scan_type = finding.test.scan_type
    logger.info(
        f"Init update_finding_prioritization_per_cve with CVE {vulnerability_id}, severity {severity}, cve_greater {cve_greater}, scan_type {scan_type}"
    )
    if vulnerability_id:
        if (
            Constants.TAG_TENABLE.value in finding.tags
            or Constants.TAG_HACKING.value in finding.tags
        ):
            ids = (
                Vulnerability_Id.objects.filter(
                    vulnerability_id=cve_greater
                ).values_list("finding_id", flat=True)
                if cve_greater != vulnerability_id
                else []
            )
            priority_cve_severity_filter = (
                (
                    Q(id__in=ids)
                    & Q(severity=severity)
                    & Q(cve=vulnerability_id)
                    & ~Q(cve=None)
                )
                if ids
                else (Q(severity=severity) & Q(cve=vulnerability_id) & ~Q(cve=None))
            )
        else:
            priority_cve_severity_filter = (Q(cve=vulnerability_id) & ~Q(cve=None)) | (
                Q(vuln_id_from_tool=vulnerability_id) & ~Q(vuln_id_from_tool=None)
            )
    else:
        priority_cve_severity_filter = Q(severity=severity)

    findings = (
        Finding.objects.filter(priority_cve_severity_filter, test__scan_type=scan_type)
        .filter(priority_tag_filter)
        .filter(active=settings.CELERY_CRON_STATUS_FINDINGS_PRIORIZATION)
    )

    # If we need to filter by vulnerability_id count, apply it after the initial query
    if vulnerability_id and Constants.TAG_HACKING.value in finding.tags and not ids:
        findings = findings.annotate(
            vulnerability_id_count=Count("vulnerability_id")
        ).filter(vulnerability_id_count=1)

    # Process in chunks to avoid memory issues
    MAX_BATCH_SIZE = 5000
    findings_iterator = findings.iterator(chunk_size=1000)
    findings_to_update = []
    total_processed = 0

    for finding_update in findings_iterator:
        finding_update.priority = priorization
        finding_update.set_sla_expiration_date()
        finding_update.epss_score = epss_score
        finding_update.epss_percentile = epss_percentile
        finding_update.known_exploited = known_exploited
        finding_update.ransomware_used = ransomware_used
        finding_update.kev_date = kev_date_added
        findings_to_update.append(finding_update)

        # Update in batches to avoid memory overflow
        if len(findings_to_update) >= MAX_BATCH_SIZE:
            Finding.objects.bulk_update(
                findings_to_update,
                [
                    "priority",
                    "sla_expiration_date",
                    "epss_score",
                    "epss_percentile",
                    "known_exploited",
                    "ransomware_used",
                    "kev_date",
                ],
                1000,
            )
            total_processed += len(findings_to_update)
            logger.info(
                f"Updated batch of {len(findings_to_update)} findings (total: {total_processed}) for CVE {vulnerability_id}"
            )
            findings_to_update = []

    # Update remaining findings
    if findings_to_update:
        Finding.objects.bulk_update(
            findings_to_update,
            [
                "priority",
                "sla_expiration_date",
                "epss_score",
                "epss_percentile",
                "known_exploited",
                "ransomware_used",
                "kev_date",
            ],
            1000,
        )
        total_processed += len(findings_to_update)

    message = f"{vulnerability_id} with severity {severity} and cve_greater {cve_greater} of {scan_type} with {total_processed} findings updated with prioritization {priorization} and EPSS score {epss_score} and percentile {epss_percentile}"
    if known_exploited:
        message += f" (Known Exploited Vulnerability) - Ransomware_used {ransomware_used} - KEV Date Added {kev_date_added}"
    logger.info("Finished update_finding_prioritization_per_cve: " + message)
    return message


def identify_priority_vulnerabilities(findings) -> int:
    """
    Identifies priority vulnerabilities based on risk score and adds them to the blacklist.

    Args:
        findings (QuerySet): Set of vulnerabilities from the Finding model
    """
    system_user = get_user(settings.SYSTEM_USER)

    severity_risk_map = get_severity_risk_map()
    df_risk_score, epss_dict, kev_dict = get_risk_priority_epss_kev_data()

    for finding in findings:
        (
            priority,
            epss_score,
            epss_percentile,
            known_exploited,
            ransomware_used,
            kev_date_added,
            cve_greater,
        ) = calculate_priority_epss_kev_finding(
            finding, severity_risk_map, df_risk_score, epss_dict, kev_dict
        )

        update_finding_prioritization_per_cve.apply_async(
            args=(
                finding,
                cve_greater,
                priority,
                epss_score,
                epss_percentile,
                known_exploited,
                ransomware_used,
                kev_date_added,
            ),
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


def get_severity_risk_map():
    priorization_weights = settings.PRIORIZATION_FIELD_WEIGHTS
    return {
        "Strict": {
            "Low": float(priorization_weights.get("P_Critical")),
            "Medium": float(priorization_weights.get("P_Critical")),
            "High": float(priorization_weights.get("P_Critical")),
            "Critical": float(priorization_weights.get("P_Critical")),
        },
        "Standard": {
            "Low": float(priorization_weights.get("P_Low")),
            "Medium": float(priorization_weights.get("P_Medium")),
            "High": float(priorization_weights.get("P_High")),
            "Critical": float(priorization_weights.get("P_Critical")),
        },
        "Discreet": {
            "Low": float(priorization_weights.get("P_Low")),
            "Medium": float(priorization_weights.get("P_Low")),
            "High": float(priorization_weights.get("P_Medium")),
            "Critical": float(priorization_weights.get("P_High")),
        },
        "Stable": {
            "Low": float(priorization_weights.get("P_Low")),
            "Medium": float(priorization_weights.get("P_Low")),
            "High": float(priorization_weights.get("P_High")),
            "Critical": float(priorization_weights.get("P_Critical")),
        }
    }


def get_risk_priority_epss_kev_data():
    """
    Get risk score, EPSS and KEV data with caching for performance
    Cache TTL: 24 hours (86400 seconds)
    """
    cache_key = "risk_priority_epss_kev_data"
    cached_data = cache.get(cache_key)

    if cached_data:
        logger.info("Using cached risk score, EPSS and KEV data")
        return cached_data

    logger.info("Fetching fresh risk score, EPSS and KEV data")

    try:
        risk_score_dataframes = list_and_read_parquet_files_from_s3(
            bucket_name=settings.BUCKET_NAME_RISK_SCORE,
            prefix_path=settings.PATH_FOLDER_RISK_SCORE,
        )

        if risk_score_dataframes:
            df_risk_score = combine_parquet_dataframes(risk_score_dataframes)
            logger.info(
                f"Loaded combined risk score data with {len(df_risk_score)} records"
            )
        else:
            df_risk_score = pd.DataFrame(columns=["cve", "prediction"])

    except Exception as e:
        logger.error(f"Error reading risk score files: {e}")
        df_risk_score = pd.DataFrame(columns=["cve", "prediction"])

    # Get epss data and kev data
    epss_dict = download_epss_data(backward_day=0, cve_cutoff=settings.CVE_CUTOFF)
    kev_dict = generate_cve_kev_dict()

    result = (df_risk_score, epss_dict, kev_dict)

    # Cache for 24 hours
    cache.set(cache_key, result, 86400)
    logger.info("Cached risk score, EPSS and KEV data for 24 hours")

    return result


def calculate_priority_epss_kev_finding(
    finding, severity_risk_map, df_risk_score, epss_dict, kev_dict
):
    priority = 0
    epss_score = None
    epss_percentile = None
    known_exploited = False
    ransomware_used = False
    kev_date_added = None
    cve_greater = None
    # Convert tags to string and extract severity type from tag
    tags_str = (
        str(finding.tags.names())
        if hasattr(finding.tags, "names")
        else str(finding.tags)
    )

    severity_risk_map = severity_risk_map.get(
        settings.PRIORIZATION_FIELD_WEIGHTS.get(tags_str.replace(",", ":").replace(" ", ""), "Standard"),
        severity_risk_map["Standard"],
    )
    if df_risk_score is not None and not df_risk_score.empty and finding.cve:
        cve_greater = finding.cve
        if (
            Constants.TAG_TENABLE.value in finding.tags
            or Constants.TAG_HACKING.value in finding.tags
        ):
            vulnerabilities_id = finding.vulnerability_ids
            priority = 0
            for vuln_id in vulnerabilities_id:
                loc_res = df_risk_score.loc[
                    df_risk_score["cve"] == vuln_id, "prediction"
                ].values
                if loc_res.size > 0:
                    current_priority = float(loc_res[0])
                    if current_priority > priority:
                        cve_greater = vuln_id
                        priority = current_priority

            if priority == 0:
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

    if cve_greater:
        epss_score = epss_dict.get(cve_greater, {}).get("epss", None)
        epss_percentile = epss_dict.get(cve_greater, {}).get("percentil", None)
        known_exploited = True if kev_dict.get(cve_greater, {}) else False
        ransomware_used = kev_dict.get(cve_greater, {}).get(
            "knownRansomwareCampaignUse", False
        )
        kev_date_added = kev_dict.get(cve_greater, {}).get("dateAdded", None)

    return (
        priority,
        epss_score,
        epss_percentile,
        known_exploited,
        ransomware_used,
        kev_date_added,
        cve_greater,
    )


def list_and_read_parquet_files_from_s3(bucket_name: str, prefix_path: str) -> list:
    try:
        s3 = boto3.client("s3")

        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix_path)

        if "Contents" not in response:
            logger.warning(f"No files found in s3://{bucket_name}/{prefix_path}")
            return []

        dataframes = []
        parquet_files = [
            obj for obj in response["Contents"] if obj["Key"].endswith(".parquet")
        ]

        logger.info(
            f"Found {len(parquet_files)} parquet files in s3://{bucket_name}/{prefix_path}"
        )

        for obj in parquet_files:
            file_key = obj["Key"]
            try:
                file_response = s3.get_object(Bucket=bucket_name, Key=file_key)
                parquet_content = file_response["Body"].read()
                df = pd.read_parquet(BytesIO(parquet_content))

                df.attrs["source_file"] = file_key
                df.attrs["last_modified"] = obj["LastModified"]
                df.attrs["size"] = obj["Size"]

                dataframes.append(df)
                logger.info(f"Successfully read {file_key} - {len(df)} rows")

            except Exception as e:
                logger.error(f"Error reading {file_key}: {str(e)}")
                continue

        return dataframes

    except Exception as e:
        logger.error(f"Error listing/reading parquet files from S3: {str(e)}")
        return []


def combine_parquet_dataframes(dataframes: list) -> pd.DataFrame:
    if not dataframes:
        return pd.DataFrame()

    try:
        combined_df = pd.concat(dataframes, ignore_index=True)
        logger.info(
            f"Combined {len(dataframes)} DataFrames into one with {len(combined_df)} total rows"
        )
        return combined_df

    except Exception as e:
        logger.error(f"Error combining DataFrames: {str(e)}")
        return pd.DataFrame()


def download_epss_data(backward_day, cve_cutoff):
    base_url = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"
    date = datetime.datetime.now() - datetime.timedelta(days=backward_day)
    attempts = 0
    while attempts < 2:
        formatted_date = date.strftime("%Y-%m-%d")
        url = base_url.format(formatted_date)
        response = requests.get(url)
        if response.status_code == 200:
            with gzip.open(io.BytesIO(response.content), "rt") as f:
                data = f.read()
            logger.info(f"{formatted_date} EPSS data downloaded.")
            return format_data(data, cve_cutoff)
        else:
            logger.warning(f"Could not find {formatted_date} EPSS data.")
            date -= datetime.timedelta(days=1)
            attempts += 1
    return None


def format_data(epss_data, cve_cutoff):
    if not epss_data:
        return None
    csv_reader = csv.reader(io.StringIO(epss_data))
    next(csv_reader), next(csv_reader)
    return {
        row[0]: {"epss": row[1], "percentil": row[2]}
        for row in csv_reader
        if len(row) >= 3 and row[0] >= cve_cutoff
    }


def generate_cve_kev_dict():
    """
    Generates a dictionary mapping CVEs to their KEV data.
    Returns:
        dict: {cve: {"dateAdded": "YYYY-MM-DD", "knownRansomwareCampaignUse": "True/False"}}
    """
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url)

        if response.status_code != 200:
            logger.error("Could not download KEV data for dictionary generation.")
            return {}

        data = response.json()
        logger.info(
            "KEV data downloaded for dictionary generation - catalog version %s.",
            data.get("catalogVersion", "unknown"),
        )

        cve_kev_dict = {}
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cveID")
            if cve_id:
                cve_kev_dict[cve_id] = {
                    "dateAdded": item.get("dateAdded", ""),
                    "knownRansomwareCampaignUse": (
                        True
                        if item.get("knownRansomwareCampaignUse") == "Known"
                        else False
                    ),
                }

        return cve_kev_dict

    except Exception as e:
        logger.error(f"Error generating CVE-KEV dictionary: {str(e)}")
        return {}


@app.task
def check_priorization():
    # Get all vulnerabilities with priority tag filter
    all_vulnerabilities = (
        Finding.objects.filter(active=settings.CELERY_CRON_STATUS_FINDINGS_PRIORIZATION)
        .filter(priority_tag_filter)
        .order_by("cve", "test__scan_type", "severity")
        .distinct("cve", "test__scan_type", "severity")
    )

    logger.info(
        f"Identified {len(all_vulnerabilities)} vulnerabilities for prioritization."
    )

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
