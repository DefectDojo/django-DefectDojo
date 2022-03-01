import base64
import logging

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
import dojo.notifications.helper as notifications_helper
from dojo.decorators import dojo_async_task
from dojo.celery import app
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core import serializers
from django.core.files.base import ContentFile
from django.utils import timezone
from dojo.importers import utils as importer_utils
from dojo.models import (BurpRawRequestResponse, FileUpload, Finding,
                         Notes, Test_Import)
from dojo.tools.factory import get_parser
from dojo.utils import get_current_user

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DojoDefaultReImporter(object):

    @dojo_async_task
    @app.task(ignore_result=False)
    def process_parsed_findings(self, test, parsed_findings, scan_type, user, active, verified, minimum_severity=None,
                                endpoints_to_add=None, push_to_jira=None, group_by=None, now=timezone.now(), service=None, scan_date=None, **kwargs):

        items = parsed_findings
        original_items = list(test.finding_set.all())
        new_items = []
        mitigated_count = 0
        finding_count = 0
        finding_added_count = 0
        reactivated_count = 0
        reactivated_items = []
        unchanged_count = 0
        unchanged_items = []

        logger.debug('starting reimport of %i items.', len(items) if items else 0)
        from dojo.importers.reimporter.utils import (
            match_new_finding_to_existing_finding,
            update_endpoint_status,
            reactivate_endpoint_status)
        deduplication_algorithm = test.deduplication_algorithm

        i = 0
        logger.debug('STEP 1: looping over findings from the reimported report and trying to match them to existing findings')
        deduplicationLogger.debug('Algorithm used for matching new findings to existing findings: %s', deduplication_algorithm)
        for item in items:
            # FIXME hack to remove when all parsers have unit tests for this attribute
            if item.severity.lower().startswith('info') and item.severity != 'Info':
                item.severity = 'Info'

            item.numerical_severity = Finding.get_numerical_severity(item.severity)

            if minimum_severity and (Finding.SEVERITIES[item.severity] > Finding.SEVERITIES[minimum_severity]):
                # finding's severity is below the configured threshold : ignoring the finding
                continue

            # existing findings may be from before we had component_name/version fields
            component_name = item.component_name if hasattr(item, 'component_name') else None
            component_version = item.component_version if hasattr(item, 'component_version') else None

            if not hasattr(item, 'test'):
                item.test = test

            item.service = service

            item.hash_code = item.compute_hash_code()
            deduplicationLogger.debug("item's hash_code: %s", item.hash_code)

            findings = match_new_finding_to_existing_finding(item, test, deduplication_algorithm)

            deduplicationLogger.debug('found %i findings matching with current new finding', len(findings))

            if findings:
                # existing finding found
                finding = findings[0]
                if finding.false_p or finding.out_of_scope or finding.risk_accepted:
                    logger.debug('%i: skipping existing finding (it is marked as false positive:%s and/or out of scope:%s or is a risk accepted:%s): %i:%s:%s:%s', i, finding.false_p, finding.out_of_scope, finding.risk_accepted, finding.id, finding, finding.component_name, finding.component_version)
                elif finding.mitigated or finding.is_mitigated:
                    logger.debug('%i: reactivating: %i:%s:%s:%s', i, finding.id, finding, finding.component_name, finding.component_version)
                    finding.mitigated = None
                    finding.is_mitigated = False
                    finding.mitigated_by = None
                    finding.active = True
                    finding.verified = verified

                    # existing findings may be from before we had component_name/version fields
                    finding.component_name = finding.component_name if finding.component_name else component_name
                    finding.component_version = finding.component_version if finding.component_version else component_version

                    # don't dedupe before endpoints are added
                    finding.save(dedupe_option=False)
                    note = Notes(
                        entry="Re-activated by %s re-upload." % scan_type,
                        author=user)
                    note.save()

                    endpoint_statuses = finding.endpoint_status.all()

                    # Determine if this can be run async
                    if settings.ASYNC_FINDING_IMPORT:
                        chunk_list = importer_utils.chunk_list(endpoint_statuses)
                        # If there is only one chunk, then do not bother with async
                        if len(chunk_list) < 2:
                            reactivate_endpoint_status(endpoint_statuses, sync=True)
                        logger.debug('IMPORT_SCAN: Split endpoints into ' + str(len(chunk_list)) + ' chunks of ' + str(chunk_list[0]))
                        # First kick off all the workers
                        for endpoint_status_list in chunk_list:
                            reactivate_endpoint_status(endpoint_status_list, sync=False)
                    else:
                        reactivate_endpoint_status(endpoint_statuses, sync=True)

                    finding.notes.add(note)
                    reactivated_items.append(finding)
                    reactivated_count += 1
                else:
                    # existing findings may be from before we had component_name/version fields
                    logger.debug('%i: updating existing finding: %i:%s:%s:%s', i, finding.id, finding, finding.component_name, finding.component_version)
                    if not finding.component_name or not finding.component_version:
                        finding.component_name = finding.component_name if finding.component_name else component_name
                        finding.component_version = finding.component_version if finding.component_version else component_version
                        finding.save(dedupe_option=False)

                    unchanged_items.append(finding)
                    unchanged_count += 1
                if finding.dynamic_finding:
                    logger.debug("Re-import found an existing dynamic finding for this new finding. Checking the status of endpoints")
                    update_endpoint_status(finding, item, user)
            else:
                # no existing finding found
                item.reporter = user
                item.last_reviewed = timezone.now()
                item.last_reviewed_by = user
                item.verified = verified
                item.active = active

                # if scan_date was provided, override value from parser
                if scan_date:
                    item.date = scan_date.date()

                # Save it. Don't dedupe before endpoints are added.
                item.save(dedupe_option=False)
                logger.debug('%i: reimport created new finding as no existing finding match: %i:%s:%s:%s', i, item.id, item, item.component_name, item.component_version)

                # only new items get auto grouped to avoid confusion around already existing items that are already grouped
                if settings.FEATURE_FINDING_GROUPS and group_by:
                    finding_helper.add_finding_to_auto_group(item, group_by, **kwargs)

                finding_added_count += 1
                new_items.append(item)
                finding = item

                if hasattr(item, 'unsaved_req_resp'):
                    for req_resp in item.unsaved_req_resp:
                        burp_rr = BurpRawRequestResponse(
                            finding=finding,
                            burpRequestBase64=base64.b64encode(req_resp["req"].encode("utf-8")),
                            burpResponseBase64=base64.b64encode(req_resp["resp"].encode("utf-8")))
                        burp_rr.clean()
                        burp_rr.save()

                if item.unsaved_request and item.unsaved_response:
                    burp_rr = BurpRawRequestResponse(
                        finding=finding,
                        burpRequestBase64=base64.b64encode(item.unsaved_request.encode()),
                        burpResponseBase64=base64.b64encode(item.unsaved_response.encode()))
                    burp_rr.clean()
                    burp_rr.save()

            # for existing findings: make sure endpoints are present or created
            if finding:
                finding_count += 1
                if settings.ASYNC_FINDING_IMPORT:
                    importer_utils.chunk_endpoints_and_disperse(finding, test, item.unsaved_endpoints)
                else:
                    importer_utils.add_endpoints_to_unsaved_finding(finding, test, item.unsaved_endpoints, sync=True)

                if endpoints_to_add:
                    if settings.ASYNC_FINDING_IMPORT:
                        importer_utils.chunk_endpoints_and_disperse(finding, test, endpoints_to_add)
                    else:
                        importer_utils.add_endpoints_to_unsaved_finding(finding, test, endpoints_to_add, sync=True)

                if item.unsaved_tags:
                    finding.tags = item.unsaved_tags

                if item.unsaved_files:
                    for unsaved_file in item.unsaved_files:
                        data = base64.b64decode(unsaved_file.get('data'))
                        title = unsaved_file.get('title', '<No title>')
                        file_upload, file_upload_created = FileUpload.objects.get_or_create(
                            title=title,
                        )
                        file_upload.file.save(title, ContentFile(data))
                        file_upload.save()
                        finding.files.add(file_upload)

                # existing findings may be from before we had component_name/version fields
                finding.component_name = finding.component_name if finding.component_name else component_name
                finding.component_version = finding.component_version if finding.component_version else component_version

                # finding = new finding or existing finding still in the upload report
                # to avoid pushing a finding group multiple times, we push those outside of the loop
                if settings.FEATURE_FINDING_GROUPS and finding.finding_group:
                    finding.save()
                else:
                    finding.save(push_to_jira=push_to_jira)

        to_mitigate = set(original_items) - set(reactivated_items) - set(unchanged_items)
        # due to #3958 we can have duplicates inside the same report
        # this could mean that a new finding is created and right after
        # that it is detected as the 'matched existing finding' for a
        # following finding in the same report
        # this means untouched can have this finding inside it,
        # while it is in fact a new finding. So we substract new_items
        untouched = set(unchanged_items) - set(to_mitigate) - set(new_items)

        if settings.FEATURE_FINDING_GROUPS and push_to_jira:
            for finding_group in set([finding.finding_group for finding in reactivated_items + unchanged_items + new_items if finding.finding_group is not None]):
                jira_helper.push_to_jira(finding_group)
        sync = kwargs.get('sync', False)
        if not sync:
            serialized_new_items = [serializers.serialize('json', [finding, ]) for finding in new_items]
            serialized_reactivated_items = [serializers.serialize('json', [finding, ]) for finding in reactivated_items]
            serialized_to_mitigate = [serializers.serialize('json', [finding, ]) for finding in to_mitigate]
            serialized_untouched = [serializers.serialize('json', [finding, ]) for finding in untouched]
            return serialized_new_items, serialized_reactivated_items, serialized_to_mitigate, serialized_untouched

        return new_items, reactivated_items, to_mitigate, untouched

    def close_old_findings(self, test, to_mitigate, scan_date_time, user, push_to_jira=None):
        logger.debug('IMPORT_SCAN: Closing findings no longer present in scan report')
        mitigated_findings = []
        for finding in to_mitigate:
            if not finding.mitigated or not finding.is_mitigated:
                logger.debug('mitigating finding: %i:%s', finding.id, finding)
                finding.mitigated = scan_date_time
                finding.is_mitigated = True
                finding.mitigated_by = user
                finding.active = False

                endpoint_status = finding.endpoint_status.all()
                for status in endpoint_status:
                    status.mitigated_by = user
                    status.mitigated_time = timezone.now()
                    status.mitigated = True
                    status.last_modified = timezone.now()
                    status.save()

                # to avoid pushing a finding group multiple times, we push those outside of the loop
                if settings.FEATURE_FINDING_GROUPS and finding.finding_group:
                    # don't try to dedupe findings that we are closing
                    finding.save(dedupe_option=False)
                else:
                    finding.save(push_to_jira=push_to_jira, dedupe_option=False)

                note = Notes(entry="Mitigated by %s re-upload." % test.test_type,
                            author=user)
                note.save()
                finding.notes.add(note)
                mitigated_findings.append(finding)

        if settings.FEATURE_FINDING_GROUPS and push_to_jira:
            for finding_group in set([finding.finding_group for finding in to_mitigate if finding.finding_group is not None]):
                jira_helper.push_to_jira(finding_group)

        return mitigated_findings

    def reimport_scan(self, scan, scan_type, test, active=True, verified=True, tags=None, minimum_severity=None,
                    user=None, endpoints_to_add=None, scan_date=None, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=True, group_by=None, api_scan_configuration=None,
                    service=None):

        logger.debug(f'REIMPORT_SCAN: parameters: {locals()}')

        user = user or get_current_user()

        now = timezone.now()

        if api_scan_configuration:
            if api_scan_configuration.product != test.engagement.product:
                raise ValidationError('API Scan Configuration has to be from same product as the Test')
            if test.api_scan_configuration != api_scan_configuration:
                test.api_scan_configuration = api_scan_configuration
                test.save()

        # check if the parser that handle the scan_type manage tests
        parser = get_parser(scan_type)
        if hasattr(parser, 'get_tests'):
            logger.debug('REIMPORT_SCAN parser v2: Create parse findings')
            tests = parser.get_tests(scan_type, scan)
            # for now we only consider the first test in the list and artificially aggregate all findings of all tests
            # this is the same as the old behavior as current import/reimporter implementation doesn't handle the case
            # when there is more than 1 test
            parsed_findings = []
            for test_raw in tests:
                parsed_findings.extend(test_raw.findings)
        else:
            logger.debug('REIMPORT_SCAN: Parse findings')
            parsed_findings = parser.get_findings(scan, test)

        logger.debug('REIMPORT_SCAN: Processing findings')
        new_findings = []
        reactivated_findings = []
        findings_to_mitigate = []
        untouched_findings = []
        if settings.ASYNC_FINDING_IMPORT:
            chunk_list = importer_utils.chunk_list(parsed_findings)
            results_list = []
            # First kick off all the workers
            for findings_list in chunk_list:
                result = self.process_parsed_findings(test, findings_list, scan_type, user, active, verified,
                                                      minimum_severity=minimum_severity, endpoints_to_add=endpoints_to_add,
                                                      push_to_jira=push_to_jira, group_by=group_by, now=now, service=service, scan_date=scan_date, sync=False)
                # Since I dont want to wait until the task is done right now, save the id
                # So I can check on the task later
                results_list += [result]
            # After all tasks have been started, time to pull the results
            logger.debug('REIMPORT_SCAN: Collecting Findings')
            for results in results_list:
                serial_new_findings, serial_reactivated_findings, serial_findings_to_mitigate, serial_untouched_findings = results.get()
                new_findings += [next(serializers.deserialize("json", finding)).object for finding in serial_new_findings]
                reactivated_findings += [next(serializers.deserialize("json", finding)).object for finding in serial_reactivated_findings]
                findings_to_mitigate += [next(serializers.deserialize("json", finding)).object for finding in serial_findings_to_mitigate]
                untouched_findings += [next(serializers.deserialize("json", finding)).object for finding in serial_untouched_findings]
            logger.debug('REIMPORT_SCAN: All Findings Collected')
            # Indicate that the test is not complete yet as endpoints will still be rolling in.
            test.percent_complete = 50
            test.save()
            importer_utils.update_test_progress(test)
        else:
            new_findings, reactivated_findings, findings_to_mitigate, untouched_findings = \
                self.process_parsed_findings(test, parsed_findings, scan_type, user, active, verified,
                                             minimum_severity=minimum_severity, endpoints_to_add=endpoints_to_add,
                                             push_to_jira=push_to_jira, group_by=group_by, now=now, service=service, scan_date=scan_date, sync=True)

        closed_findings = []
        if close_old_findings:
            logger.debug('REIMPORT_SCAN: Closing findings no longer present in scan report')
            closed_findings = self.close_old_findings(test, findings_to_mitigate, scan_date, user=user, push_to_jira=push_to_jira)

        logger.debug('REIMPORT_SCAN: Updating test/engagement timestamps')
        importer_utils.update_timestamps(test, version, branch_tag, build_id, commit_hash, now, scan_date)

        test_import = None
        if settings.TRACK_IMPORT_HISTORY:
            logger.debug('REIMPORT_SCAN: Updating Import History')
            test_import = importer_utils.update_import_history(Test_Import.REIMPORT_TYPE, active, verified, tags, minimum_severity, endpoints_to_add,
                                                                version, branch_tag, build_id, commit_hash, push_to_jira, close_old_findings,
                                                                test, new_findings, closed_findings, reactivated_findings, untouched_findings)

        logger.debug('REIMPORT_SCAN: Generating notifications')

        updated_count = len(closed_findings) + len(reactivated_findings) + len(new_findings)
        if updated_count > 0:
            notifications_helper.notify_scan_added(test, updated_count, new_findings=new_findings, findings_mitigated=closed_findings,
                                                    findings_reactivated=reactivated_findings, findings_untouched=untouched_findings)

        logger.debug('REIMPORT_SCAN: Done')

        return test, updated_count, len(new_findings), len(closed_findings), len(reactivated_findings), len(untouched_findings), test_import
