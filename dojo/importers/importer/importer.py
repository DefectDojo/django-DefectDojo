import base64

from django.db.models.query_utils import Q
from dojo.importers import utils as importer_utils
from dojo.decorators import dojo_async_task
from dojo.utils import get_current_user, is_finding_groups_enabled
from dojo.celery import app
from django.core.exceptions import ValidationError
from django.core import serializers
import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
import dojo.notifications.helper as notifications_helper
from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone
from dojo.models import (BurpRawRequestResponse, FileUpload,
                         Finding, Test, Test_Import, Test_Type)
from dojo.tools.factory import get_parser
import logging


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DojoDefaultImporter(object):

    def create_test(self, scan_type, test_type_name, engagement, lead, environment, tags=None,
                    scan_date=None, version=None, branch_tag=None, build_id=None, commit_hash=None, now=timezone.now(),
                    api_scan_configuration=None, title=None):

        test_type, created = Test_Type.objects.get_or_create(
            name=test_type_name)

        if created:
            logger.info('Created new Test_Type with name %s because a report is being imported', test_type.name)

        test = Test(
            title=title,
            engagement=engagement,
            lead=lead,
            test_type=test_type,
            scan_type=scan_type,
            target_start=scan_date if scan_date else now.date(),
            target_end=scan_date if scan_date else now.date(),
            environment=environment,
            percent_complete=100,
            version=version,
            branch_tag=branch_tag,
            build_id=build_id,
            commit_hash=commit_hash,
            api_scan_configuration=api_scan_configuration,
            tags=tags,
        )

        test.full_clean()
        test.save()
        return test

    @dojo_async_task
    @app.task(ignore_result=False)
    def process_parsed_findings(self, test, parsed_findings, scan_type, user, active=None, verified=None, minimum_severity=None,
                                endpoints_to_add=None, push_to_jira=None, group_by=None, now=timezone.now(), service=None, scan_date=None,
                                create_finding_groups_for_all_findings=True, **kwargs):
        logger.debug('endpoints_to_add: %s', endpoints_to_add)
        new_findings = []
        items = parsed_findings
        logger.debug('starting import of %i items.', len(items) if items else 0)
        i = 0
        group_names_to_findings_dict = {}

        for item in items:
            # FIXME hack to remove when all parsers have unit tests for this attribute
            if item.severity.lower().startswith('info') and item.severity != 'Info':
                item.severity = 'Info'

            item.numerical_severity = Finding.get_numerical_severity(item.severity)

            if minimum_severity and (Finding.SEVERITIES[item.severity] >
                    Finding.SEVERITIES[minimum_severity]):
                # finding's severity is below the configured threshold : ignoring the finding
                continue

            item.test = test
            item.reporter = user if user else get_current_user
            item.last_reviewed = now
            item.last_reviewed_by = user if user else get_current_user

            logger.debug('process_parsed_findings: active from report: %s, verified from report: %s', item.active, item.verified)
            if active is not None:
                # indicates an override. Otherwise, do not change the value of item.active
                item.active = active

            if verified is not None:
                # indicates an override. Otherwise, do not change the value of verified
                item.verified = verified

            # if scan_date was provided, override value from parser
            if scan_date:
                item.date = scan_date.date()

            if service:
                item.service = service

            item.save(dedupe_option=False)

            if is_finding_groups_enabled() and group_by:
                # If finding groups are enabled, group all findings by group name
                name = finding_helper.get_group_by_group_name(item, group_by)
                if name is not None:
                    if name in group_names_to_findings_dict:
                        group_names_to_findings_dict[name].append(item)
                    else:
                        group_names_to_findings_dict[name] = [item]

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

            importer_utils.chunk_endpoints_and_disperse(item, test, item.unsaved_endpoints)
            if endpoints_to_add:
                importer_utils.chunk_endpoints_and_disperse(item, test, endpoints_to_add)

            if item.unsaved_tags:
                item.tags = item.unsaved_tags

            if item.unsaved_files:
                for unsaved_file in item.unsaved_files:
                    data = base64.b64decode(unsaved_file.get('data'))
                    title = unsaved_file.get('title', '<No title>')
                    file_upload, file_upload_created = FileUpload.objects.get_or_create(
                        title=title,
                    )
                    file_upload.file.save(title, ContentFile(data))
                    file_upload.save()
                    item.files.add(file_upload)

            importer_utils.handle_vulnerability_ids(item)

            new_findings.append(item)
            # to avoid pushing a finding group multiple times, we push those outside of the loop
            if is_finding_groups_enabled() and group_by:
                item.save()
            else:
                item.save(push_to_jira=push_to_jira)

        for (group_name, findings) in group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(group_name, findings, group_by, create_finding_groups_for_all_findings, **kwargs)
            if push_to_jira:
                if findings[0].finding_group is not None:
                    jira_helper.push_to_jira(findings[0].finding_group)
                else:
                    jira_helper.push_to_jira(findings[0])

        sync = kwargs.get('sync', False)
        if not sync:
            return [serializers.serialize('json', [finding, ]) for finding in new_findings]
        return new_findings

    def close_old_findings(self, test, scan_date_time, user, push_to_jira=None, service=None, close_old_findings_product_scope=False):
        # Close old active findings that are not reported by this scan.
        new_hash_codes = test.finding_set.values('hash_code')

        if close_old_findings_product_scope:
            # Close old findings of the same test type in the same product
            old_findings = Finding.objects.exclude(test=test) \
                .exclude(hash_code__in=new_hash_codes) \
                .filter(test__engagement__product=test.engagement.product,
                        test__test_type=test.test_type,
                        active=True)
        else:
            # Close old findings of the same test type in the same engagement
            old_findings = Finding.objects.exclude(test=test) \
                                        .exclude(hash_code__in=new_hash_codes) \
                                        .filter(test__engagement=test.engagement,
                                                test__test_type=test.test_type,
                                                active=True)

        if service:
            old_findings = old_findings.filter(service=service)
        else:
            old_findings = old_findings.filter(Q(service__isnull=True) | Q(service__exact=''))

        for old_finding in old_findings:
            old_finding.active = False
            old_finding.is_mitigated = True
            old_finding.mitigated = scan_date_time
            old_finding.notes.create(author=user,
                                        entry="This finding has been automatically closed"
                                        " as it is not present anymore in recent scans.")
            endpoint_status = old_finding.status_finding.all()
            for status in endpoint_status:
                status.mitigated_by = user
                status.mitigated_time = timezone.now()
                status.mitigated = True
                status.last_modified = timezone.now()
                status.save()

            old_finding.tags.add('stale')

            # to avoid pushing a finding group multiple times, we push those outside of the loop
            if is_finding_groups_enabled() and old_finding.finding_group:
                # don't try to dedupe findings that we are closing
                old_finding.save(dedupe_option=False)
            else:
                old_finding.save(dedupe_option=False, push_to_jira=push_to_jira)

        if is_finding_groups_enabled() and push_to_jira:
            for finding_group in set([finding.finding_group for finding in old_findings if finding.finding_group is not None]):
                jira_helper.push_to_jira(finding_group)

        return old_findings

    def import_scan(self, scan, scan_type, engagement, lead, environment, active=None, verified=None, tags=None, minimum_severity=None,
                    user=None, endpoints_to_add=None, scan_date=None, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, close_old_findings_product_scope=False,
                    group_by=None, api_scan_configuration=None, service=None, title=None, create_finding_groups_for_all_findings=True):

        logger.debug(f'IMPORT_SCAN: parameters: {locals()}')

        user = user or get_current_user()

        now = timezone.now()

        if api_scan_configuration and api_scan_configuration.product != engagement.product:
            raise ValidationError('API Scan Configuration has to be from same product as  the Engagement')

        # check if the parser that handle the scan_type manage tests
        # if yes, we parse the data first
        # after that we customize the Test_Type to reflect the data
        # This allow us to support some meta-formats like SARIF or the generic format
        parser = get_parser(scan_type)
        if hasattr(parser, 'get_tests'):
            logger.debug('IMPORT_SCAN parser v2: Create Test and parse findings')
            try:
                tests = parser.get_tests(scan_type, scan)
            except ValueError as e:
                logger.warning(e)
                raise ValidationError(e)
            # for now we only consider the first test in the list and artificially aggregate all findings of all tests
            # this is the same as the old behavior as current import/reimporter implementation doesn't handle the case
            # when there is more than 1 test
            #
            # we also aggregate the label of the Test_type to show the user the original scan_type
            # only if they are different. This is to support meta format like SARIF
            # so a report that have the label 'CodeScanner' will be changed to 'CodeScanner Scan (SARIF)'
            test_type_name = scan_type
            if len(tests) > 0:
                if tests[0].type:
                    test_type_name = tests[0].type + " Scan"
                    if test_type_name != scan_type:
                        test_type_name = f"{test_type_name} ({scan_type})"

                test = self.create_test(scan_type, test_type_name, engagement, lead, environment, scan_date=scan_date, tags=tags,
                                    version=version, branch_tag=branch_tag, build_id=build_id, commit_hash=commit_hash, now=now,
                                    api_scan_configuration=api_scan_configuration, title=title)
                # This part change the name of the Test
                # we get it from the data of the parser
                test_raw = tests[0]
                if test_raw.name:
                    test.name = test_raw.name
                if test_raw.description:
                    test.description = test_raw.description
                test.save()

                logger.debug('IMPORT_SCAN parser v2: Parse findings (aggregate)')
                # currently we only support import one Test
                # so for parser that support multiple tests (like SARIF)
                # we aggregate all the findings into one uniq test
                parsed_findings = []
                for test_raw in tests:
                    parsed_findings.extend(test_raw.findings)
            else:
                logger.info(f'No tests found in import for {scan_type}')
        else:
            logger.debug('IMPORT_SCAN: Create Test')
            # by default test_type == scan_type
            test = self.create_test(scan_type, scan_type, engagement, lead, environment, scan_date=scan_date, tags=tags,
                                version=version, branch_tag=branch_tag, build_id=build_id, commit_hash=commit_hash, now=now,
                                api_scan_configuration=api_scan_configuration, title=title)

            logger.debug('IMPORT_SCAN: Parse findings')
            parser = get_parser(scan_type)
            try:
                parsed_findings = parser.get_findings(scan, test)
            except ValueError as e:
                logger.warning(e)
                raise ValidationError(e)

        logger.debug('IMPORT_SCAN: Processing findings')
        new_findings = []
        if settings.ASYNC_FINDING_IMPORT:
            chunk_list = importer_utils.chunk_list(parsed_findings)
            results_list = []
            # First kick off all the workers
            for findings_list in chunk_list:
                result = self.process_parsed_findings(test, findings_list, scan_type, user, active=active,
                                                            verified=verified, minimum_severity=minimum_severity,
                                                            endpoints_to_add=endpoints_to_add, push_to_jira=push_to_jira,
                                                            group_by=group_by, now=now, service=service, scan_date=scan_date, sync=False,
                                                            create_finding_groups_for_all_findings=create_finding_groups_for_all_findings)
                # Since I dont want to wait until the task is done right now, save the id
                # So I can check on the task later
                results_list += [result]
            # After all tasks have been started, time to pull the results
            logger.info('IMPORT_SCAN: Collecting Findings')
            for results in results_list:
                serial_new_findings = results.get()
                new_findings += [next(serializers.deserialize("json", finding)).object for finding in serial_new_findings]
            logger.info('IMPORT_SCAN: All Findings Collected')
            # Indicate that the test is not complete yet as endpoints will still be rolling in.
            test.percent_complete = 50
            test.save()
        else:
            new_findings = self.process_parsed_findings(test, parsed_findings, scan_type, user, active=active,
                                                            verified=verified, minimum_severity=minimum_severity,
                                                            endpoints_to_add=endpoints_to_add, push_to_jira=push_to_jira,
                                                            group_by=group_by, now=now, service=service, scan_date=scan_date, sync=True,
                                                            create_finding_groups_for_all_findings=create_finding_groups_for_all_findings)

        closed_findings = []
        if close_old_findings:
            logger.debug('IMPORT_SCAN: Closing findings no longer present in scan report')
            closed_findings = self.close_old_findings(test, scan_date, user=user, push_to_jira=push_to_jira, service=service,
                                                      close_old_findings_product_scope=close_old_findings_product_scope)

        logger.debug('IMPORT_SCAN: Updating test/engagement timestamps')
        importer_utils.update_timestamps(test, version, branch_tag, build_id, commit_hash, now, scan_date)

        test_import = None
        if settings.TRACK_IMPORT_HISTORY:
            logger.debug('IMPORT_SCAN: Updating Import History')
            test_import = importer_utils.update_import_history(Test_Import.IMPORT_TYPE, active, verified, tags, minimum_severity,
                                                                endpoints_to_add, version, branch_tag, build_id, commit_hash,
                                                                push_to_jira, close_old_findings, test, new_findings, closed_findings)

        logger.debug('IMPORT_SCAN: Generating notifications')
        notifications_helper.notify_test_created(test)
        updated_count = len(new_findings) + len(closed_findings)
        if updated_count > 0:
            notifications_helper.notify_scan_added(test, updated_count, new_findings=new_findings, findings_mitigated=closed_findings)

        logger.debug('IMPORT_SCAN: Updating Test progress')
        importer_utils.update_test_progress(test)

        logger.debug('IMPORT_SCAN: Done')

        return test, len(new_findings), len(closed_findings), test_import
