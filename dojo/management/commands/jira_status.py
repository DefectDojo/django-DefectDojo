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
- reconcile: reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change timestamp in both systems to determine which one is the correct status
- push_to_jira: update JIRA issues connected to a Defect Dojo finding (will overwrite any existing summar/description present in JIRA)
- sync_from_jira: update Defect Dojo finding status from JIRA
- create_jira_for_push_all: not implemented yet. Create JIRA issues for all Defect Dojo findings that have push_all_issues on their engagement or product, but no JIRA issue yet.

jira -> dojo:
dojo.jira_change < jira.updated and
dojo.last_status_update < jira.updated and
dojo.last_reviewed < jira.update
(dojo.mitigated < dojo.jira_change or dojo.is_Mitigated == False)

dojo -> jira:
dojo.jira_change > jira.updated or # can't happen
dojo.last_status_update > jira.updated or
dojo.last_reviewed > jira.updated
dojo.mitigated > dojo.jira_change


"""


class Command(BaseCommand):
    help = 'Manage JIRA issues'

    mode_help = \
        '- reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change timestamp in both systems to determine which one is the correct status' \
        '- status_to_jira: update JIRA status for all JIRA issues connected to a Defect Dojo finding (will not push summary/description, only status)' \
        '- status_from_jira: update Defect Dojo finding status from JIRA'

    def add_arguments(self, parser):
        parser.add_argument('--mode', help=self.mode_help)
        parser.add_argument('--product', help='Only process findings in this product (name)')
        parser.add_argument('--engagement', help='Only process findings in this product (name)')
        parser.add_argument('--dryrun', help='Only pring actions to be performed, but make no modifications.')

    def handle(self, *args, **options):
        mode = options['mode']
        product = options['product']
        engagement = options['engagement']
        dryrun = options['dryrun']

        logger.debug('mode: %s product:%s engagement: %s dryrun: %s', mode, product, engagement, dryrun)

        if not mode or mode == 'reconcile':
            self.reconcile(product, engagement, dryrun)
        elif mode == 'push_to_jira':
            self.status_to_jira(product, engagement, dryrun)
        elif mode == 'sync_from_jira':
            self.status_from_jira(product, engagement, dryrun)

    def reconcile(self, product, engagement, *arg, **kwargs):
        findings = Finding.objects.all()
        if product:
            product = Product.objects.filter(name=product).first()
            findings.filter(test__engagement__product=product)

        if engagement:
            engagement = Engagement.objects.filter(name=engagement).first()
            findings.filter(test__engagement=engagement)

        findings = findings.exclude(jira_issue__isnull=True)

        # order by product, engagement to increase the cance of being able to reuse jira_instance + jira connection
        findings.order_by('product', 'engagement')

        logger.debug(findings.query)

        # TODO remove
        findings = Finding.objects.filter(id=77220)

        for find in findings:
            logger.debug('jira status reconciliation for: %i:%s', find.id, find)

            issue_from_jira = jira_helper.get_jira_issue_from_jira(find)

            # jira -> dojo:
            # dojo.jira_change < jira.updated and
            # dojo.last_status_update < jira.updated and
            # dojo.last_reviewed < jira.update
            # (dojo.mitigated < dojo.jira_change or dojo.is_Mitigated == False)

            # convert from str to datetime
            issue_from_jira.updated = parse_datetime(issue_from_jira.fields.updated)
            logger.debug('%s,%s,%s,%s', (find.jira_issue.jira_change < issue_from_jira.updated), (find.last_status_update < issue_from_jira.updated), (find.last_reviewed < issue_from_jira.updated), (not find.is_Mitigated or find.mititaged < find.jira_issue.jira_change))

            if find.jira_issue.jira_change < issue_from_jira.updated:
                if find.last_status_update < issue_from_jira.updated:
                    if find.last_reviewed < issue_from_jira.updated:
                        if not find.is_Mitigated or find.mititaged < find.jira_issue.jira_change:
                            assignee = issue_from_jira.fields.assignee if hasattr(issue_from_jira.fields, 'assignee') else None
                            assignee_name = assignee.displayName if assignee else None
                            resolution = issue_from_jira.fields.resolution if issue_from_jira.fields.resolution and issue_from_jira.fields.resolution != "None" else None
                            resolution_id = resolution.id if resolution else None
                            resolution_name = resolution.name if resolution else None

                            status_changed = jira_helper.process_resolution_from_jira(find, resolution_id, resolution_name, assignee_name)
                            if status_changed:
                                logger.info('%s; %s/finding/%d;processed resolution from jira;%s;%s', find.jira_issue.jira_key, settings.SITE_URL, find.id, resolution_name, status_changed)
                            else:
                                logger.info('%s; %s/finding/%d;no changes made from jira resolution;%s;%s', find.jira_issue.jira_key, settings.SITE_URL, find.id, resolution_name, status_changed)

                            # done with this finding, continue with next finding
                            continue

            # dojo -> jira:
            # dojo.jira_change > jira.updated or # can't happen
            # dojo.last_status_update > jira.updated or
            # dojo.last_reviewed > jira.updated
            # dojo.mitigated > dojo.jira_change
            logger.debug('%s,%s,%s,%s', (find.jira_issue.jira_change > issue_from_jira.updated), (find.last_status_update > issue_from_jira.updated), (find.last_reviewed > issue_from_jira.updated), (not find.is_Mitigated or find.mititaged < find.jira_issue.jira_change))
            prev_jira_instance, jira = None, None
            if (find.jira_issue.jira_change > issue_from_jira.updated) or \
                (find.last_status_update > issue_from_jira.updated) or \
                    (find.last_reviewed > issue_from_jira.updated) or \
                        (find.is_Mitigated and find.mititaged < find.jira_issue.jira_change):

                jira_instance = jira_helper.get_jira_instance(find)
                if not prev_jira_instance or (jira_instance.id != prev_jira_instance.id):
                    # only reconnect to jira if the instance if different from the previous finding
                    jira = jira_helper.get_jira_connection(jira_instance)

                status_changed = jira_helper.push_status_to_jira(find, jira_instance, jira, issue_from_jira)

                if status_changed:
                    logger.info('%s; %s/finding/%d;pushed status to jira;%s;%s', find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), status_changed)
                else:
                    if status_changed is None:
                        status_changed = 'Error'
                    logger.info('%s; %s/finding/%d;no changes made while pushing status to jira;%s;%s', find.jira_issue.jira_key, settings.SITE_URL, find.id, find.status(), status_changed)

    def status_to_jira(self, product, engagement, *arg, **kwargs):
        pass

    def status_from_jira(self, product, engagement, *arg, **kwargs):
        pass
