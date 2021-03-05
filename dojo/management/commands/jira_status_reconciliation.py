from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.dateparse import parse_datetime

from dojo.models import Engagement, Finding, Product
import dojo.jira_link.helper as jira_helper
import logging
logger = logging.getLogger(__name__)


"""
Author: Valentijn scholten
modes:
- reconcile: reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status update in Defect Dojo and the 'updated' field in the JIRA Issue.
- push_to_jira: overwrite status in JIRA with status in Defect Dojo
- sync_from_jira: overwrite status in Defect Dojo with status from JIRA
"""


class Command(BaseCommand):
    help = 'Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results. Risk Accepted findings are skipped.'

    mode_help = \
        '- reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change timestamp in both systems to determine which one is the correct status' \
        '- push_status_to_jira: update JIRA status for all JIRA issues connected to a Defect Dojo finding (will not push summary/description, only status)' \
        '- import_status_from_jira: update Defect Dojo finding status from JIRA'

    def add_arguments(self, parser):
        parser.add_argument('--mode', help=self.mode_help)
        parser.add_argument('--product', help='Only process findings in this product (name)')
        parser.add_argument('--engagement', help='Only process findings in this product (name)')
        parser.add_argument('--dryrun', action='store_true', help='Only print actions to be performed, but make no modifications.')

    def handle(self, *args, **options):
        mode = options['mode']
        product = options['product']
        engagement = options['engagement']
        dryrun = options['dryrun']

        logger.debug('mode: %s product:%s engagement: %s dryrun: %s', mode, product, engagement, dryrun)

        if mode and mode not in ('push_status_to_jira', 'import_status_from_jira', 'reconcile'):
            print('mode must be one of reconcile, push_status_to_jira or import_status_from_jira')
            return False

        findings = Finding.objects.all()
        if product:
            product = Product.objects.filter(name=product).first()
            findings = findings.filter(test__engagement__product=product)

        if engagement:
            engagement = Engagement.objects.filter(name=engagement).first()
            findings = findings.filter(test__engagement=engagement)

        findings = findings.exclude(jira_issue__isnull=True)

        # order by product, engagement to increase the cance of being able to reuse jira_instance + jira connection
        findings = findings.order_by('test__engagement__product__id', 'test__engagement__id')

        findings = findings.prefetch_related('jira_issue__jira_project__jira_instance')
        findings = findings.prefetch_related('test__engagement__jira_project__jira_instance')
        findings = findings.prefetch_related('test__engagement__product__jira_project_set__jira_instance')

        logger.debug(findings.query)

        messages = ['jira_key;finding_url;resolution_or_status;action;change_made']
        for find in findings:
            logger.debug('jira status reconciliation for: %i:%s', find.id, find)

            issue_from_jira = jira_helper.get_jira_issue_from_jira(find)

            if not issue_from_jira:
                message = '%s; %s/finding/%d;%s;%s;unable to retrieve JIRA Issue;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), None, 'error')
                messages.append(message)
                logger.info(message)
                continue

            assignee = issue_from_jira.fields.assignee if hasattr(issue_from_jira.fields, 'assignee') else None
            assignee_name = assignee.displayName if assignee else None
            resolution = issue_from_jira.fields.resolution if issue_from_jira.fields.resolution and issue_from_jira.fields.resolution != "None" else None
            resolution_id = resolution.id if resolution else None
            resolution_name = resolution.name if resolution else None

            # convert from str to datetime
            issue_from_jira.fields.updated = parse_datetime(issue_from_jira.fields.updated)

            logger.debug('find.jira_issue.jira_change: %s', find.jira_issue.jira_change)
            logger.debug('issue_from_jira.fields.updated: %s', issue_from_jira.fields.updated)
            logger.debug('find.last_status_update: %s', find.last_status_update)
            logger.debug('issue_from_jira.fields.updated: %s', issue_from_jira.fields.updated)
            logger.debug('find.last_reviewed: %s', find.last_reviewed)
            logger.debug('issue_from_jira.fields.updated: %s', issue_from_jira.fields.updated)

            no_action = 'False' if not dryrun else 'dryrun'

            if find.risk_accepted:
                message = '%s; %s/finding/%d;%s;%s;skipping risk accepted findings;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, no_action)
                messages.append(message)
                logger.info(message)
            elif jira_helper.issue_from_jira_is_active(issue_from_jira) and find.active:
                message = '%s; %s/finding/%d;%s;%s;no action both sides are active/open;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, no_action)
                messages.append(message)
                logger.info(message)
            elif not jira_helper.issue_from_jira_is_active(issue_from_jira) and not find.active:
                message = '%s; %s/finding/%d;%s;%s;no action both sides are inactive/closed;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, no_action)
                messages.append(message)
                logger.info(message)
            else:
                # statuses are different
                if mode in ('push_status_to_jira', 'import_status_from_jira'):
                    action = mode
                else:
                    # reconcile
                    # Status is JIRA is newer if:
                    # dojo.jira_change < jira.updated, and
                    # dojo.last_status_update < jira.updated, and
                    # dojo.last_reviewed < jira.update,
                    logger.debug('%s,%s,%s,%s',
                                    resolution_name,
                                    (not find.jira_issue.jira_change or (find.jira_issue.jira_change < issue_from_jira.fields.updated)),
                                    not find.last_status_update or (find.last_status_update < issue_from_jira.fields.updated),
                                    (not find.last_reviewed or (find.last_reviewed < issue_from_jira.fields.updated)))

                    if (not find.jira_issue.jira_change or (find.jira_issue.jira_change < issue_from_jira.fields.updated)):
                        if not find.last_status_update or (find.last_status_update < issue_from_jira.fields.updated):
                            if not find.last_reviewed or (find.last_reviewed < issue_from_jira.fields.updated):
                                action = 'import_status_from_jira'

                    # Status is DOJO is newer if:
                    # dojo.jira_change > jira.updated or # can't happen
                    # dojo.last_status_update > jira.updated or
                    # dojo.last_reviewed > jira.updated
                    # dojo.mitigated > dojo.jira_change
                    logger.debug('%s,%s,%s,%s',
                                    resolution_name,
                                    (not find.jira_issue.jira_change or (find.jira_issue.jira_change > issue_from_jira.fields.updated)),
                                    (find.last_status_update > issue_from_jira.fields.updated),
                                    (find.is_Mitigated and find.mitigated and find.jira_issue.jira_change and find.mitigated > find.jira_issue.jira_change))

                    if (not find.jira_issue.jira_change or (find.jira_issue.jira_change > issue_from_jira.fields.updated)) or \
                        (find.last_status_update > issue_from_jira.fields.updated) or \
                            (find.is_Mitigated and find.mitigated and find.jira_issue.jira_change and find.mitigated > find.jira_issue.jira_change):

                        action = 'push_status_to_jira'

                prev_jira_instance, jira = None, None

                if action == 'import_status_from_jira':
                    message_action = 'deactivating' if find.active else 'reactivating'

                    status_changed = jira_helper.process_resolution_from_jira(find, resolution_id, resolution_name, assignee_name, issue_from_jira.fields.updated) if not dryrun else 'dryrun'
                    if status_changed:
                        message = '%s; %s/finding/%d;%s;%s;%s finding in defectdojo;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, message_action, status_changed)
                        messages.append(message)
                        logger.info(message)
                    else:
                        message = '%s; %s/finding/%d;%s;%s;no changes made from jira resolution;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, status_changed)
                        messages.append(message)
                        logger.info(message)

                elif action == 'push_status_to_jira':
                    jira_instance = jira_helper.get_jira_instance(find)
                    if not prev_jira_instance or (jira_instance.id != prev_jira_instance.id):
                        # only reconnect to jira if the instance if different from the previous finding
                        jira = jira_helper.get_jira_connection(jira_instance)

                    message_action = 'reopening' if find.active else 'closing'

                    status_changed = jira_helper.push_status_to_jira(find, jira_instance, jira, issue_from_jira) if not dryrun else 'dryrun'

                    if status_changed:
                        message = '%s; %s/finding/%d;%s;%s;%s jira issue;%s;' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, message_action, status_changed)
                        messages.append(message)
                        logger.info(message)
                    else:
                        if status_changed is None:
                            status_changed = 'Error'
                        message = '%s; %s/finding/%d;%s;%s;no changes made while pushing status to jira;%s' % (find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), resolution_name, status_changed)
                        messages.append(message)

                        logger.info(message)

        logger.info('results (tab seperated)')
        for message in messages:
            print(message)
