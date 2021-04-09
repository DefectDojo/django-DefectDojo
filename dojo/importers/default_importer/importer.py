from dojo.models import Test, Finding, \
    Test_Type, \
    Endpoint, BurpRawRequestResponse, \
    Endpoint_Status, \
    Test_Import, \
    Test_Import_Finding_Action, IMPORT_CREATED_FINDING, IMPORT_CLOSED_FINDING

from dojo.tools.factory import handles_active_verified_statuses, import_parser_factory
from dojo.utils import get_current_user, max_safe
from dojo.notifications.helper import create_notification
from django.urls import reverse

from django.core.exceptions import MultipleObjectsReturned
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
import base64
import logging

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DojoDefaultImporter(object):

    def create_test(self, scan_type, engagement, lead, environment, tags=None,
                    scan_date=None, version=None, branch_tag=None, build_id=None, commit_hash=None, now=timezone.now()):

        test_type, created = Test_Type.objects.get_or_create(
            name=scan_type)

        if created:
            logger.info('Created new Test_Type with name %s because a report is being imported', test_type.name)

        test = Test(
            engagement=engagement,
            lead=lead,
            test_type=test_type,
            target_start=scan_date if scan_date else now.date(),
            target_end=scan_date if scan_date else now.date(),
            environment=environment,
            percent_complete=100,
            version=version,
            branch_tag=branch_tag,
            build_id=build_id,
            commit_hash=commit_hash,
            tags=tags)
        try:
            # TODO What is going on here?
            test.full_clean()
        except ValidationError:
            pass

        test.save()
        return test

    def parse_findings(self, scan, test, active, verified, scan_type):
        try:
            parser = import_parser_factory(scan,
                                           test,
                                           active,
                                           verified,
                                           scan_type)
            parsed_findings = parser.get_findings(scan, test)
            return parsed_findings
        except SyntaxError as se:
            logger.exception(se)
            logger.warn("Error in parser: {}".format(str(se)))
            raise
        except ValueError as ve:
            logger.exception(ve)
            logger.warn("Error in parser: {}".format(str(ve)))
            raise
        except Exception as e:
            logger.exception(e)
            logger.warn("Error in parser: {}".format(str(e)))
            raise

    def process_parsed_findings(self, test, parsed_findings, scan_type, user, active, verified, minimum_severity=None,
                                endpoints_to_add=None, push_to_jira=None, now=timezone.now()):
        logger.debug('endpoints_to_add: %s', endpoints_to_add)
        new_findings = []
        items = parsed_findings
        logger.debug('starting import of %i items.', len(items) if items else 0)
        i = 0
        for item in items:
            sev = item.severity
            if sev == 'Information' or sev == 'Informational':
                sev = 'Info'

            item.severity = sev

            if minimum_severity and (Finding.SEVERITIES[sev] >
                    Finding.SEVERITIES[minimum_severity]):
                continue

            item.test = test
            item.reporter = user if user else get_current_user
            item.last_reviewed = now
            item.last_reviewed_by = user if user else get_current_user

            # TODO this is not really used, and there's PR https://github.com/DefectDojo/django-DefectDojo/pull/4014 with a better/generic solution
            if not handles_active_verified_statuses(scan_type):
                item.active = active
                item.verified = verified

            item.created = now
            item.updated = now
            item.save(dedupe_option=False)

            if (hasattr(item, 'unsaved_req_resp') and
                    len(item.unsaved_req_resp) > 0):
                for req_resp in item.unsaved_req_resp:
                    burp_rr = BurpRawRequestResponse(
                        finding=item,
                        burpRequestBase64=base64.b64encode(req_resp["req"].encode("utf-8")),
                        burpResponseBase64=base64.b64encode(req_resp["resp"].encode("utf-8")))
                    burp_rr.clean()
                    burp_rr.save()

            if (item.unsaved_request is not None and
                    item.unsaved_response is not None):
                burp_rr = BurpRawRequestResponse(
                    finding=item,
                    burpRequestBase64=base64.b64encode(item.unsaved_request.encode()),
                    burpResponseBase64=base64.b64encode(item.unsaved_response.encode()))
                burp_rr.clean()
                burp_rr.save()

            for endpoint in item.unsaved_endpoints:
                try:
                    ep, created = Endpoint.objects.get_or_create(
                        protocol=endpoint.protocol,
                        host=endpoint.host,
                        path=endpoint.path,
                        query=endpoint.query,
                        fragment=endpoint.fragment,
                        product=test.engagement.product)
                except (MultipleObjectsReturned):
                    pass

                try:
                    eps, created = Endpoint_Status.objects.get_or_create(
                        finding=item,
                        endpoint=ep)
                except (MultipleObjectsReturned):
                    pass

                ep.endpoint_status.add(eps)
                item.endpoint_status.add(eps)
                item.endpoints.add(ep)

                if endpoints_to_add:
                    for endpoint in endpoints_to_add:
                        try:
                            ep, created = Endpoint.objects.get_or_create(
                                protocol=endpoint.protocol,
                                host=endpoint.host,
                                path=endpoint.path,
                                query=endpoint.query,
                                fragment=endpoint.fragment,
                                product=test.engagement.product)
                        except (MultipleObjectsReturned):
                            pass
                        try:
                            eps, created = Endpoint_Status.objects.get_or_create(
                                finding=item,
                                endpoint=ep)
                        except (MultipleObjectsReturned):
                            pass

                        ep.endpoint_status.add(eps)
                        item.endpoints.add(ep)
                        item.endpoint_status.add(eps)

            if item.unsaved_tags:
                item.tags = item.unsaved_tags

            new_findings.append(item)
            item.save(push_to_jira=push_to_jira)

        return new_findings

    def close_old_findings(self, test, user=None):
        old_findings = []
        logger.debug('IMPORT_SCAN: Closing findings no longer present in scan report')
        # Close old active findings that are not reported by this scan.
        new_hash_codes = test.finding_set.values('hash_code')

        # TODO I don't think these criteria are 100% correct, why are findings with the same hash_code excluded?
        # Would it make more sense to exclude duplicates? But the deduplication process can be unfinished because it's
        # run in a celery async task...
        if test.engagement.deduplication_on_engagement:
            old_findings = Finding.objects.exclude(test=test) \
                                            .exclude(hash_code__in=new_hash_codes) \
                                            .filter(test__engagement=test.engagement,
                                                test__test_type=test.test_type,
                                                active=True)
        else:
            # TODO BUG? this will violate the deduplication_on_engagement setting for other engagements
            old_findings = Finding.objects.exclude(test=test) \
                                            .exclude(hash_code__in=new_hash_codes) \
                                            .filter(test__engagement__product=test.engagement.product,
                                                test__test_type=test.test_type,
                                                active=True)

        for old_finding in old_findings:
            old_finding.active = False
            old_finding.is_Mitigated = True
            old_finding.notes.create(author=user,
                                        entry="This finding has been automatically closed"
                                        " as it is not present anymore in recent scans.")
            endpoint_status = old_finding.endpoint_status.all()
            for status in endpoint_status:
                status.mitigated_by = user if user else get_current_user()
                status.mitigated_time = timezone.now()
                status.mitigated = True
                status.last_modified = timezone.now()
                status.save()

            old_finding.tags.add('stale')
            old_finding.save(dedupe_option=False)

        return old_findings

    def import_scan(self, scan, scan_type, engagement, lead, environment, active=True, verified=True, tags=None, minimum_severity=None,
                    user=None, endpoints_to_add=None, scan_date=None, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False):
        now = timezone.now()
        user = user or get_current_user()

        logger.debug('IMPORT_SCAN: Create Test')

        test = self.create_test(scan_type, engagement, lead, environment, scan_date=scan_date, tags=tags,
                            version=version, branch_tag=branch_tag, build_id=build_id, commit_hash=commit_hash, now=now)

        logger.debug('IMPORT_SCAN: Parse findings')

        parsed_findings = self.parse_findings(scan, test, active, verified, scan_type)

        logger.debug('IMPORT_SCAN: Processing findings')

        new_findings = self.process_parsed_findings(test, parsed_findings, scan_type, user, active, verified, minimum_severity=minimum_severity, endpoints_to_add=endpoints_to_add, push_to_jira=push_to_jira, now=now)

        closed_findings = []
        if close_old_findings:
            closed_findings = self.close_old_findings(test, user=user)

        logger.debug('IMPORT_SCAN: Updating timestampes')

        test.engagement.updated = now
        if test.engagement.engagement_type == 'CI/CD':
            test.engagement.target_end = max_safe([scan_date, test.engagement.target_end])
        test.engagement.save()

        if settings.TRACK_IMPORT_HISTORY:
            logger.debug('IMPORT_SCAN: Updating Import History')
            import_settings = {}  # json field
            import_settings['active'] = active
            import_settings['verified'] = verified
            import_settings['minimum_severity'] = minimum_severity
            import_settings['close_old_findings'] = close_old_findings
            import_settings['push_to_jira'] = push_to_jira
            import_settings['tags'] = tags
            if endpoints_to_add:
                import_settings['endpoints'] = endpoints_to_add

            test_import = Test_Import(test=test, import_settings=import_settings, version=version, branch_tag=branch_tag, build_id=build_id, commit_hash=commit_hash, type=Test_Import.IMPORT_TYPE)
            test_import.save()

            test_import_finding_action_list = []
            for finding in closed_findings:
                test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_CLOSED_FINDING))
            for finding in new_findings:
                test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_CREATED_FINDING))

            Test_Import_Finding_Action.objects.bulk_create(test_import_finding_action_list)

        logger.debug('IMPORT_SCAN: Generating notifications')

        title = 'Test created for ' + str(test.engagement.product) + ': ' + str(test.engagement.name) + ': ' + str(test)
        create_notification(event='test_added', title=title, test=test, engagement=test.engagement, product=test.engagement.product,
                            url=reverse('view_test', args=(test.id,)))

        updated_count = len(new_findings) + len(closed_findings)
        if updated_count > 0:
            title = 'Created ' + str(updated_count) + " findings for " + str(test.engagement.product) + ': ' + str(test.engagement.name) + ': ' + str(test)
            create_notification(event='scan_added', title=title, findings_new=new_findings, findings_mitigated=closed_findings,
                                finding_count=updated_count, test=test, engagement=test.engagement, product=test.engagement.product,
                                url=reverse('view_test', args=(test.id,)))
        logger.debug('IMPORT_SCAN: Done')

        return test, len(new_findings), len(closed_findings)
