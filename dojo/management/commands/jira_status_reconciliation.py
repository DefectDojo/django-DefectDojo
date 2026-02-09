import argparse
import logging

import pghistory
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.utils.dateparse import parse_datetime

import dojo.jira_link.helper as jira_helper
from dojo.models import Engagement, Finding, Finding_Group, Product

logger = logging.getLogger(__name__)


def jira_status_reconciliation(*args, **kwargs):
    mode = kwargs["mode"]
    product = kwargs["product"]
    engagement = kwargs["engagement"]
    daysback = kwargs["daysback"]
    dryrun = kwargs["dryrun"]
    include_findings = kwargs.get("include_findings", True)
    include_finding_groups = kwargs.get("include_finding_groups", True)

    logger.debug("mode: %s product:%s engagement: %s dryrun: %s", mode, product, engagement, dryrun)

    if mode and mode not in {"push_status_to_jira", "import_status_from_jira", "reconcile"}:
        logger.info("mode must be one of reconcile, push_status_to_jira or import_status_from_jira")
        return False

    if not mode:
        mode = "reconcile"

    # Resolve product and engagement objects once for reuse in both loops
    product_obj = None
    if product:
        product_obj = Product.objects.filter(name=product).first()

    engagement_obj = None
    if engagement:
        engagement_obj = Engagement.objects.filter(name=engagement).first()

    timestamp = None
    if daysback:
        timestamp = timezone.now() - relativedelta(days=int(daysback))

    messages = ["jira_key;url;resolution_or_status;jira_issue.jira_change;issue_from_jira.fields.updated;last_status_update;issue_from_jira.fields.updated;last_reviewed;issue_from_jira.fields.updated;flag1;flag2;flag3;action;change_made"]

    # --- Process individual findings with direct JIRA issues ---
    if include_findings:
        _reconcile_findings(mode, product_obj, engagement_obj, timestamp, dryrun, messages)

    # --- Process finding groups with JIRA issues ---
    if include_finding_groups:
        _reconcile_finding_groups(mode, product_obj, engagement_obj, timestamp, dryrun, messages)

    logger.info("results (semicolon seperated)")
    for message in messages:
        logger.info(message)
    return None


def _reconcile_findings(mode, product_obj, engagement_obj, timestamp, dryrun, messages):
    """Reconcile individual findings that have their own direct JIRA issues."""
    findings = Finding.objects.all()
    if product_obj:
        findings = findings.filter(test__engagement__product=product_obj)

    if engagement_obj:
        findings = findings.filter(test__engagement=engagement_obj)

    if timestamp:
        findings = findings.filter(created__gte=timestamp)

    findings = findings.exclude(jira_issue__isnull=True)

    # order by product, engagement to increase the chance of being able to reuse jira_instance + jira connection
    findings = findings.order_by("test__engagement__product__id", "test__engagement__id")

    findings = findings.prefetch_related("jira_issue__jira_project__jira_instance")
    findings = findings.prefetch_related("test__engagement__jira_project__jira_instance")
    findings = findings.prefetch_related("test__engagement__product__jira_project_set__jira_instance")

    logger.debug(findings.query)

    for find in findings:
        logger.debug("jira status reconciliation for: %i:%s", find.id, find)

        issue_from_jira = jira_helper.get_jira_issue_from_jira(find)

        if not issue_from_jira:
            message = "{};{}/finding/{};{};{};{};{};{};{};{};{};{};{};{};unable to retrieve JIRA Issue;{}".format(
                find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), None, None, None, None,
                            find.jira_issue.jira_change, None, find.last_status_update, None, find.last_reviewed, None, "error")
            messages.append(message)
            logger.info(message)
            continue

        assignee = issue_from_jira.fields.assignee if hasattr(issue_from_jira.fields, "assignee") else None
        assignee_name = assignee.displayName if assignee else None
        resolution = issue_from_jira.fields.resolution if issue_from_jira.fields.resolution and issue_from_jira.fields.resolution != "None" else None
        resolution_id = resolution.id if resolution else None
        resolution_name = resolution.name if resolution else None

        # convert from str to datetime
        issue_from_jira.fields.updated = parse_datetime(issue_from_jira.fields.updated)

        flag1, flag2, flag3 = None, None, None

        if mode == "reconcile" and not find.last_status_update:
            message = "{}; {}/finding/{};{};{};{};{};{};{};{};{};{};{};{};skipping finding with no last_status_update;{}".format(
                find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), None, None, None, None,
                find.jira_issue.jira_change, issue_from_jira.fields.updated, find.last_status_update, issue_from_jira.fields.updated, find.last_reviewed, issue_from_jira.fields.updated, "skipped")
            messages.append(message)
            logger.info(message)
            continue
        if find.risk_accepted:
            message = "{}; {}/finding/{};{};{};{};{};{};{};{};{};{};{};{}skipping risk accepted findings;{}".format(
                find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, None, None, None,
                find.jira_issue.jira_change, issue_from_jira.fields.updated, find.last_status_update, issue_from_jira.fields.updated, find.last_reviewed, issue_from_jira.fields.updated, "skipped")
            messages.append(message)
            logger.info(message)
        elif jira_helper.issue_from_jira_is_active(issue_from_jira) and find.active:
            message = "{}; {}/finding/{};{};{};{};{};{};{};{};{};{};{};{};no action both sides are active/open;{}".format(
                find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, None, None, None,
                    find.jira_issue.jira_change, issue_from_jira.fields.updated, find.last_status_update, issue_from_jira.fields.updated, find.last_reviewed, issue_from_jira.fields.updated, "equal")
            messages.append(message)
            logger.info(message)
        elif not jira_helper.issue_from_jira_is_active(issue_from_jira) and not find.active:
            message = "{}; {}/finding/{};{};{};{};{};{};{};{};{};{};{};{};no action both sides are inactive/closed;{}".format(
                find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, None, None, None,
                find.jira_issue.jira_change, issue_from_jira.fields.updated, find.last_status_update, issue_from_jira.fields.updated, find.last_reviewed, issue_from_jira.fields.updated, "equal")
            messages.append(message)
            logger.info(message)

        else:
            # statuses are different
            if mode in {"push_status_to_jira", "import_status_from_jira"}:
                action = mode
            else:
                # reconcile
                # Status is JIRA is newer if:
                # dojo.jira_change < jira.updated, and
                # dojo.last_status_update < jira.updated, and
                # dojo.last_reviewed < jira.update,

                flag1 = (not find.jira_issue.jira_change or (find.jira_issue.jira_change < issue_from_jira.fields.updated))
                flag2 = not find.last_status_update or (find.last_status_update < issue_from_jira.fields.updated)
                flag3 = (not find.last_reviewed or (find.last_reviewed < issue_from_jira.fields.updated))

                logger.debug("%s,%s,%s,%s", resolution_name, flag1, flag2, flag3)

                if flag1 and flag2 and flag3:
                    action = "import_status_from_jira"

                else:
                    # Status is DOJO is newer if:
                    # dojo.jira_change > jira.updated or # can't happen
                    # dojo.last_status_update > jira.updated or
                    # dojo.last_reviewed > jira.updated
                    # dojo.mitigated > dojo.jira_change

                    flag1 = not find.jira_issue.jira_change or (find.jira_issue.jira_change > issue_from_jira.fields.updated)
                    flag2 = find.last_status_update > issue_from_jira.fields.updated
                    flag3 = find.is_mitigated and find.mitigated and find.jira_issue.jira_change and find.mitigated > find.jira_issue.jira_change

                    logger.debug("%s,%s,%s,%s", resolution_name, flag1, flag2, flag3)

                    if flag1 or flag2 or flag3:
                        action = "push_status_to_jira"

            prev_jira_instance, jira = None, None

            if action == "import_status_from_jira":
                message_action = "deactivating" if find.active else "reactivating"

                status_changed = jira_helper.process_resolution_from_jira(find, resolution_id, resolution_name, assignee_name, issue_from_jira.fields.updated, find.jira_issue) if not dryrun else "dryrun"
                if status_changed:
                    message = f"{find.jira_issue.jira_key}; {settings.SITE_URL}/finding/{find.id};{find.status()};{resolution_name};{flag1};{flag2};{flag3};{find.jira_issue.jira_change};{issue_from_jira.fields.updated};{find.last_status_update};{issue_from_jira.fields.updated};{find.last_reviewed};{issue_from_jira.fields.updated};{message_action} finding in defectdojo;{status_changed}"
                    messages.append(message)
                    logger.info(message)
                else:
                    message = f"{find.jira_issue.jira_key}; {settings.SITE_URL}/finding/{find.id};{find.status()};{resolution_name};{flag1};{flag2};{flag3};{find.jira_issue.jira_change};{issue_from_jira.fields.updated};{find.last_status_update};{issue_from_jira.fields.updated};{find.last_reviewed};{issue_from_jira.fields.updated};no changes made from jira resolution;{status_changed}"
                    messages.append(message)
                    logger.info(message)

            elif action == "push_status_to_jira":
                jira_instance = jira_helper.get_jira_instance(find)
                if not prev_jira_instance or (jira_instance.id != prev_jira_instance.id):
                    # only reconnect to jira if the instance if different from the previous finding
                    jira = jira_helper.get_jira_connection(jira_instance)

                message_action = "reopening" if find.active else "closing"

                status_changed = jira_helper.push_status_to_jira(find, jira_instance, jira, issue_from_jira, save=True) if not dryrun else "dryrun"

                if status_changed:
                    message = f"{find.jira_issue.jira_key}; {settings.SITE_URL}/finding/{find.id};{find.status()};{resolution_name};{flag1};{flag2};{flag3};{message_action};{find.jira_issue.jira_change};{issue_from_jira.fields.updated};{find.last_status_update};{issue_from_jira.fields.updated};{find.last_reviewed};{issue_from_jira.fields.updated} jira issue;{status_changed};"
                    messages.append(message)
                    logger.info(message)
                else:
                    if status_changed is None:
                        status_changed = "Error"
                    message = f"{find.jira_issue.jira_key}; {settings.SITE_URL}/finding/{find.id};{find.status()};{resolution_name};{flag1};{flag2};{flag3};{find.jira_issue.jira_change};{issue_from_jira.fields.updated};{find.last_status_update};{issue_from_jira.fields.updated};{find.last_reviewed};{issue_from_jira.fields.updated};no changes made while pushing status to jira;{status_changed}"
                    messages.append(message)

                    logger.info(message)
            else:
                message = f"{find.jira_issue.jira_key}; {settings.SITE_URL}/finding/{find.id};{find.status()};{resolution_name};{flag1};{flag2};{flag3};{find.jira_issue.jira_change};{issue_from_jira.fields.updated};{find.last_status_update};{issue_from_jira.fields.updated};{find.last_reviewed};{issue_from_jira.fields.updated};unable to determine source of truth;{status_changed}"
                messages.append(message)

                logger.info(message)


def _reconcile_finding_groups(mode, product_obj, engagement_obj, timestamp, dryrun, messages):
    """
    Reconcile finding groups that have their own JIRA issues.

    This handles JIRA issues attached to Finding_Group objects separately from
    individual finding JIRA issues to avoid pushing the same JIRA issue twice.
    We use push_status_to_jira directly on the group (not push_finding_group_to_jira
    which would also push individual finding JIRA issues already handled by
    _reconcile_findings).
    """
    finding_groups = Finding_Group.objects.all()
    if product_obj:
        finding_groups = finding_groups.filter(test__engagement__product=product_obj)

    if engagement_obj:
        finding_groups = finding_groups.filter(test__engagement=engagement_obj)

    if timestamp:
        finding_groups = finding_groups.filter(created__gte=timestamp)

    finding_groups = finding_groups.exclude(jira_issue__isnull=True)

    # order by product, engagement to increase the chance of being able to reuse jira_instance + jira connection
    finding_groups = finding_groups.order_by("test__engagement__product__id", "test__engagement__id")

    finding_groups = finding_groups.prefetch_related("jira_issue__jira_project__jira_instance")
    finding_groups = finding_groups.prefetch_related("test__engagement__jira_project__jira_instance")
    finding_groups = finding_groups.prefetch_related("test__engagement__product__jira_project_set__jira_instance")
    finding_groups = finding_groups.prefetch_related("findings")

    logger.debug(finding_groups.query)

    for finding_group in finding_groups:
        logger.debug("jira status reconciliation for finding group: %i:%s", finding_group.id, finding_group)

        group_findings = finding_group.findings.all()
        group_url = f"{settings.SITE_URL}/test/{finding_group.test.id}"

        issue_from_jira = jira_helper.get_jira_issue_from_jira(finding_group)

        if not issue_from_jira:
            message = f"{finding_group.jira_issue.jira_key};{group_url};{finding_group.status()};unable to retrieve JIRA Issue;error"
            messages.append(message)
            logger.info(message)
            continue

        assignee = issue_from_jira.fields.assignee if hasattr(issue_from_jira.fields, "assignee") else None
        assignee_name = assignee.displayName if assignee else None
        resolution = issue_from_jira.fields.resolution if issue_from_jira.fields.resolution and issue_from_jira.fields.resolution != "None" else None
        resolution_id = resolution.id if resolution else None
        resolution_name = resolution.name if resolution else None

        # convert from str to datetime
        issue_from_jira.fields.updated = parse_datetime(issue_from_jira.fields.updated)

        # Derive timestamps from the findings in the group
        group_last_status_update = _max_or_none(f.last_status_update for f in group_findings)
        group_last_reviewed = _max_or_none(f.last_reviewed for f in group_findings)
        group_is_active = any(f.active for f in group_findings)
        group_all_mitigated = all(f.is_mitigated for f in group_findings) if group_findings else False

        flag1, flag2, flag3 = None, None, None

        if mode == "reconcile" and not group_last_status_update:
            message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};skipping finding group with no last_status_update;skipped"
            messages.append(message)
            logger.info(message)
            continue

        jira_is_active = jira_helper.issue_from_jira_is_active(issue_from_jira)

        if jira_is_active and group_is_active:
            message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};{resolution_name};no action both sides are active/open;equal"
            messages.append(message)
            logger.info(message)
        elif not jira_is_active and not group_is_active:
            message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};{resolution_name};no action both sides are inactive/closed;equal"
            messages.append(message)
            logger.info(message)

        else:
            # statuses are different
            action = None
            if mode in {"push_status_to_jira", "import_status_from_jira"}:
                action = mode
            else:
                # reconcile - determine which side is newer using derived timestamps
                # Status in JIRA is newer if all DefectDojo timestamps are older than JIRA updated
                flag1 = (not finding_group.jira_issue.jira_change or (finding_group.jira_issue.jira_change < issue_from_jira.fields.updated))
                flag2 = not group_last_status_update or (group_last_status_update < issue_from_jira.fields.updated)
                flag3 = (not group_last_reviewed or (group_last_reviewed < issue_from_jira.fields.updated))

                logger.debug("finding_group reconcile: %s,%s,%s,%s", resolution_name, flag1, flag2, flag3)

                if flag1 and flag2 and flag3:
                    action = "import_status_from_jira"
                else:
                    # Status in DefectDojo is newer
                    flag1 = not finding_group.jira_issue.jira_change or (finding_group.jira_issue.jira_change > issue_from_jira.fields.updated)
                    flag2 = group_last_status_update and (group_last_status_update > issue_from_jira.fields.updated)
                    flag3 = group_all_mitigated and finding_group.jira_issue.jira_change and any(
                        f.is_mitigated and f.mitigated and f.mitigated > finding_group.jira_issue.jira_change
                        for f in group_findings
                    )

                    logger.debug("finding_group reconcile dojo newer: %s,%s,%s,%s", resolution_name, flag1, flag2, flag3)

                    if flag1 or flag2 or flag3:
                        action = "push_status_to_jira"

            prev_jira_instance, jira = None, None

            if action == "import_status_from_jira":
                # Import status from JIRA to all findings in the group
                # Same pattern as the JIRA webhook handler in dojo/jira_link/views.py
                any_status_changed = False
                for find in group_findings:
                    if not dryrun:
                        status_changed = jira_helper.process_resolution_from_jira(
                            find, resolution_id, resolution_name, assignee_name,
                            issue_from_jira.fields.updated, finding_group.jira_issue,
                            finding_group=finding_group,
                        )
                    else:
                        status_changed = "dryrun"
                    if status_changed:
                        any_status_changed = True

                message_action = "deactivating" if group_is_active else "reactivating"
                message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};{resolution_name};{flag1};{flag2};{flag3};{message_action} findings in finding group;{any_status_changed}"
                messages.append(message)
                logger.info(message)

            elif action == "push_status_to_jira":
                # Push the finding group's aggregate status to its JIRA issue directly.
                # We do NOT use push_finding_group_to_jira here because that would also push
                # individual finding JIRA issues which are already handled by _reconcile_findings.
                jira_instance = jira_helper.get_jira_instance(finding_group)
                if not prev_jira_instance or (jira_instance.id != prev_jira_instance.id):
                    jira = jira_helper.get_jira_connection(jira_instance)

                message_action = "reopening" if group_is_active else "closing"

                status_changed = jira_helper.push_status_to_jira(finding_group, jira_instance, jira, issue_from_jira, save=True) if not dryrun else "dryrun"

                if status_changed:
                    message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};{resolution_name};{flag1};{flag2};{flag3};{message_action} jira issue for finding group;{status_changed}"
                else:
                    if status_changed is None:
                        status_changed = "Error"
                    message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};{resolution_name};{flag1};{flag2};{flag3};no changes made while pushing status to jira;{status_changed}"

                messages.append(message)
                logger.info(message)
            else:
                message = f"{finding_group.jira_issue.jira_key}; {group_url};finding_group:{finding_group.id};{finding_group.status()};{resolution_name};{flag1};{flag2};{flag3};unable to determine source of truth;unknown"
                messages.append(message)
                logger.info(message)


def _max_or_none(iterable):
    """Return the max of non-None values in iterable, or None if all are None."""
    values = [v for v in iterable if v is not None]
    return max(values) if values else None


class Command(BaseCommand):

    """
    Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
    Risk Accepted findings are skipped.'

    modes:
    - reconcile: reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status update in Defect Dojo and the 'updated' field in the JIRA Issue.
    - push_to_jira: overwrite status in JIRA with status in Defect Dojo
    - sync_from_jira: overwrite status in Defect Dojo with status from JIRA
    """

    help = "Reconcile finding/finding group status with JIRA issue status, stdout will contain semicolon seperated CSV results. \
        Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped."

    mode_help = (
        "- reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change timestamp in both systems to determine which one is the correct status"
        "- push_status_to_jira: update JIRA status for all JIRA issues connected to a Defect Dojo finding or finding group (will not push summary/description, only status)"
        "- import_status_from_jira: update Defect Dojo finding/finding group status from JIRA"
    )

    def add_arguments(self, parser):
        parser.add_argument("--mode", help=self.mode_help)
        parser.add_argument("--product", help="Only process findings in this product (name)")
        parser.add_argument("--engagement", help="Only process findings in this engagement (name)")
        parser.add_argument("--daysback", type=int, help="Only process findings created in the last 'daysback' days")
        parser.add_argument("--dryrun", action="store_true", help="Only print actions to be performed, but make no modifications.")
        parser.add_argument(
            "--include-findings", action=argparse.BooleanOptionalAction, default=True,
            help="Process individual findings with direct JIRA issues (default: True)",
        )
        parser.add_argument(
            "--include-finding-groups", action=argparse.BooleanOptionalAction, default=True,
            help="Process finding groups with JIRA issues (default: True)",
        )

    def handle(self, *args, **options):
        # Wrap with pghistory context for audit trail
        with pghistory.context(
            source="jira_reconciliation",
            mode=options.get("mode", "reconcile"),
        ):
            return jira_status_reconciliation(*args, **options)
