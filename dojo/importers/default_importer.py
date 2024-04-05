import logging
import base64
from abc import ABC
from datetime import datetime
from typing import List, Tuple

from django.utils import timezone
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.files.base import ContentFile
from django.core.serializers import serialize, deserialize
from django.conf import settings
from django.db.models.query_utils import Q

from dojo.importers.base_importer import BaseImporter, Parser
import dojo.notifications.helper as notifications_helper
import dojo.finding.helper as finding_helper
from dojo.utils import is_finding_groups_enabled
import dojo.jira_link.helper as jira_helper
from dojo.models import (
    Product_Type,
    Product,
    Engagement,
    Test_Type,
    Test,
    Test_Import,
    Finding,
    Endpoint,
    Development_Environment,
    Dojo_User,
    Tool_Configuration,
    BurpRawRequestResponse,
    FileUpload,
)


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DefaultImporter(BaseImporter):
    def __init__(self, *args, **kwargs):
        """
        Create an instance of the Default Importer
        """
        return ABC.__init__(self, *args, **kwargs)

    def __new__(self, *args, **kwargs):
        """
        Create an instance of the Default Importer
        """
        return ABC.__new__(self, *args, **kwargs)

    def create_test(
        self,
        scan_type: str,
        test_type_name: str,
        **kwargs: dict,
    ):
        """
        Create a fresh test object to be used by the importer. This
        new test will be attached to the supplied engagement with the
        supplied user being marked as the lead of the test
        """
        # Ensure the following fields were supplied in the kwargs
        required_fields = ["engagement", "lead", "environment"]
        if not all(field in kwargs for field in required_fields):
            raise ValueError(
                "(Importer) parse_findings_from_file - "
                f"The following fields must be supplied: {required_fields}"
            )
        # Grab the fields from the kwargs
        engagement = kwargs.get("engagement")
        lead = kwargs.get("lead")
        environment = kwargs.get("environment")
        # Ensure a test type is available for use
        test_type = self.get_or_create_test_type(test_type_name)
        # Make sure timezone is applied to dates
        scan_date, now = self.add_timezone_scan_date_and_now(kwargs.get("scan_date"), now=kwargs.get("now"), **kwargs)
        # Create the test object
        return Test.objects.create(
            engagement=engagement,
            lead=lead,
            environment=environment,
            test_type=test_type,
            scan_type=scan_type,
            target_start=scan_date or now,
            target_end=scan_date or now,
            percent_complete=100,
            **kwargs,
        )

    def process_scan(
        self,
        scan: TemporaryUploadedFile,
        scan_type: str,
        engagement: Engagement = None,
        test: Test = None,
        user: Dojo_User = None,
        parsed_findings: List[Finding] = None,
        **kwargs: dict,
    ) -> Tuple[Test, int, int, int, int, int, Test_Import]:
        logger.debug(f'IMPORT_SCAN: parameters: {locals()}')
        # Get a user in some point
        user = self.get_user_if_supplied(user=user)
        # Validate the Tool_Configuration
        engagement = self.verify_tool_configuration_from_engagement(
            kwargs.get("api_scan_configuration", None),
            engagement
        )
        # Fetch the parser based upon the string version of the scan type
        parser = self.get_parser(scan_type)
        # Get the findings from the parser based on what methods the parser supplies
        # This could either mean traditional file parsing, or API pull parsing
        test, parsed_findings = self.parse_findings(parser, scan_type, scan, test=None)
        # process the findings in the foreground or background
        new_findings = self.determine_process_method(test, parsed_findings, scan_type, user)
        # Close any old findings in the processed list if the the user specified for that
        # to occur in the form that is then passed to the kwargs
        closed_findings = self.close_old_findings(test, test.finding_set.values(), kwargs.ge("scan_date"), user)
        # Update the timestamps of the test object by looking at the findings imported
        self.update_timestamps(test, **kwargs)
        # Create a test import history object to record the flags sent to the importer
        # This operation will return None if the user does not have the import history
        # feature enabled
        test_import_history = self.update_import_history(
            Test_Import.IMPORT_TYPE,
            test,
            new_findings=new_findings,
            closed_findings=closed_findings,
            **kwargs,
        )
        # Send out som notifications to the user
        logger.debug('IMPORT_SCAN: Generating notifications')
        notifications_helper.notify_test_created(test)
        updated_count = len(new_findings) + len(closed_findings)
        notifications_helper.notify_scan_added(test, updated_count, new_findings=new_findings, findings_mitigated=closed_findings)
        # Update the test progress to reflect that the import has completed
        logger.debug('IMPORT_SCAN: Updating Test progress')
        self.update_test_progress(test, **kwargs)

        logger.debug('IMPORT_SCAN: Done')
        return test, 0, len(new_findings), len(closed_findings), 0, 0, test_import_history

    def process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:
        new_findings = []
        items = parsed_findings
        logger.debug('starting import of %i items.', len(items) if items else 0)
        group_names_to_findings_dict = {}

        for item in items:
            # FIXME hack to remove when all parsers have unit tests for this attribute
            # Importing the cvss module via:
            # `from cvss import CVSS3`
            # _and_ given a CVSS vector string such as:
            # cvss_vector_str = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            # the following severity calculation returns the
            # string values of, "None" instead of the expected string values
            # of "Info":
            # ```
            # cvss_obj = CVSS3(cvss_vector_str)
            # severities = cvss_obj.severities()
            # print(severities)
            # ('None', 'None', 'None')
            # print(severities[0])
            # 'None'
            # print(type(severities[0]))
            # <class 'str'>
            # ```
            if (item.severity.lower().startswith('info') or item.severity.lower() == 'none') and item.severity != 'Info':
                item.severity = 'Info'

            item.numerical_severity = Finding.get_numerical_severity(item.severity)
            if (minimum_severity := kwargs.get("minimum_severity")) and (Finding.SEVERITIES[item.severity] > Finding.SEVERITIES[minimum_severity]):
                # finding's severity is below the configured threshold : ignoring the finding
                continue

            now = kwargs.get("now")
            # Some parsers provide "mitigated" field but do not set timezone (because they are probably not available in the report)
            # Finding.mitigated is DateTimeField and it requires timezone
            if item.mitigated and not item.mitigated.tzinfo:
                item.mitigated = item.mitigated.replace(tzinfo=now.tzinfo)

            item.test = test
            item.reporter = user
            item.last_reviewed_by = user
            item.last_reviewed = now

            logger.debug('process_parsed_findings: active from report: %s, verified from report: %s', item.active, item.verified)
            # indicates an override. Otherwise, do not change the value of item.active
            if active := kwargs.get("active") is not None:
                item.active = active
            # indicates an override. Otherwise, do not change the value of verified
            if verified := kwargs.get("verified") is not None:
                item.verified = verified
            # scan_date was provided, override value from parser
            if scan_date := kwargs.get("scan_date"):
                item.date = scan_date.date()
            if service := kwargs.get("service"):
                item.service = service

            item.save(dedupe_option=False)

            group_by = kwargs.get("group_by")
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

            self.chunk_endpoints_and_disperse(item, test, item.unsaved_endpoints)
            if len(endpoints_to_add := kwargs.get("endpoints_to_add")) > 0:
                logger.debug('endpoints_to_add: %s', endpoints_to_add)
                self.chunk_endpoints_and_disperse(item, test, endpoints_to_add)

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

            self.handle_vulnerability_ids(item)

            new_findings.append(item)
            # to avoid pushing a finding group multiple times, we push those outside of the loop
            push_to_jira = kwargs.get("push_to_jira", False)
            if is_finding_groups_enabled() and group_by:
                item.save()
            else:
                item.save(push_to_jira=push_to_jira)

        for (group_name, findings) in group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(
                group_name,
                findings,
                group_by,
                kwargs.get("create_finding_groups_for_all_findings"),
                **kwargs)
            if push_to_jira:
                if findings[0].finding_group is not None:
                    jira_helper.push_to_jira(findings[0].finding_group)
                else:
                    jira_helper.push_to_jira(findings[0])

        sync = kwargs.get('sync', False)
        if not sync:
            return [serialize('json', [finding, ]) for finding in new_findings]
        return new_findings

    def close_old_findings(
        self,
        test: Test,
        findings: List[Finding],
        scan_date: datetime,
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:
        # Close old active findings that are not reported by this scan.
        # Refactoring this to only call test.finding_set.values() once.
        mitigated_hash_codes = []
        new_hash_codes = []
        for finding in findings:
            new_hash_codes.append(finding["hash_code"])
            if finding.is_mitigated or finding.mitigated is not None:
                mitigated_hash_codes.append(finding["hash_code"])
                for hash_code in new_hash_codes:
                    if hash_code == finding["hash_code"]:
                        new_hash_codes.remove(hash_code)

        # Close old findings of the same test type in the same product
        if kwargs.get("close_old_findings_product_scope"):
            old_findings = Finding.objects.exclude(
                test=test
            ).exclude(
                hash_code__in=new_hash_codes
            ).filter(
                test__engagement__product=test.engagement.product,
                test__test_type=test.test_type,
                active=True
            )
        else:
            # Close old findings of the same test type in the same engagement
            old_findings = Finding.objects.exclude(
                test=test
            ).exclude(
                hash_code__in=new_hash_codes
            ).filter(
                test__engagement=test.engagement,
                test__test_type=test.test_type,
                active=True
            )

        if len(service := kwargs.get("service")) > 0:
            old_findings = old_findings.filter(service=service)
        else:
            old_findings = old_findings.filter(Q(service__isnull=True) | Q(service__exact=''))

        for old_finding in old_findings:
            old_finding.active = False
            old_finding.is_mitigated = True
            old_finding.mitigated = scan_date
            old_finding.notes.create(
                author=user,
                entry=(
                    "This finding has been automatically closed "
                    "as it is not present anymore in recent scans."
                )
            )
            endpoint_status = old_finding.status_finding.all()
            for status in endpoint_status:
                status.mitigated_by = user
                status.mitigated_time = timezone.now()
                status.mitigated = True
                status.last_modified = timezone.now()
                status.save()

            old_finding.tags.add('stale')

            # to avoid pushing a finding group multiple times, we push those outside of the loop
            push_to_jira = kwargs.get("push_to_jira", False)
            if is_finding_groups_enabled() and old_finding.finding_group:
                # don't try to dedupe findings that we are closing
                old_finding.save(dedupe_option=False)
            else:
                old_finding.save(dedupe_option=False, push_to_jira=push_to_jira)

        if is_finding_groups_enabled() and push_to_jira:
            for finding_group in set([finding.finding_group for finding in old_findings if finding.finding_group is not None]):
                jira_helper.push_to_jira(finding_group)

        return old_findings

    def parse_findings_from_file(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        test: Test = None,
        **kwargs: dict,
    ) -> Tuple[Test, List[Finding]]:
        """
        Creates a test object as part of the import process as there is not one present
        at the time of import. Once the test is created, proceed with the traditional
        file import as usual from the base class
        """
        # by default test_type == scan_type
        test = self.create_test(
            scan_type,
            scan_type,
            **kwargs,
        )
        logger.debug('IMPORT_SCAN: Parse findings')
        # Use the parent method for the rest of this
        return test, BaseImporter.parse_findings_from_file(
            parser,
            scan_type,
            scan,
            test,
        )

    def parse_findings_from_api_configuration(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        **kwargs: dict,
    ) -> Tuple[Test, List[Finding]]:
        """
        TODO
        """
        logger.debug('IMPORT_SCAN parser v2: Create Test and parse findings')
        parsed_findings = []
        tests = self.api_configuration_get_tests_from_from_parser(
            parser,
            scan_type,
            scan,
            **kwargs,
        )
        # Make sure we have at least one test returned
        if len(tests) == 0:
            logger.info(f'No tests found in import for {scan_type}')
            return parsed_findings
        # for now we only consider the first test in the list and artificially aggregate all findings of all tests
        # this is the same as the old behavior as current import/reimporter implementation doesn't handle the case
        # when there is more than 1 test
        #
        # we also aggregate the label of the Test_type to show the user the original scan_type
        # only if they are different. This is to support meta format like SARIF
        # so a report that have the label 'CodeScanner' will be changed to 'CodeScanner Scan (SARIF)'
        test_type_name = scan_type
        # Determine if we should use a custom test type name
        if tests[0].type:
            test_type_name = f"{tests[0].type} Scan"
            if test_type_name != scan_type:
                test_type_name = f"{test_type_name} ({scan_type})"
        # Create a new test
        test = self.create_test(
            scan_type,
            scan_type,
            **kwargs,
        )
        # This part change the name of the Test
        # we get it from the data of the parser
        test_raw = tests[0]
        if test_raw.name:
            test.name = test_raw.name
        if test_raw.description:
            test.description = test_raw.description
        test.save()
        logger.debug('IMPORT_SCAN parser v2: Parse findings (aggregate)')
        # Aggregate all the findings and return them with the newly created test
        return test, self.api_configuration_get_findings_from_tests(tests)

    def determine_process_method(
        self,
        test: Test,
        parsed_findings: List[Finding],
        scan_type: str,
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:    
        if settings.ASYNC_FINDING_IMPORT:
            return self.async_process_findings(
                test,
                parsed_findings,
                scan_type,
                user,
                **kwargs,
            )
        else:
            return self.sync_process_findings(
                test,
                parsed_findings,
                scan_type,
                user,
                **kwargs,
            )

    def sync_process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        scan_type: str,
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:
        return self.process_findings(
            test,
            parsed_findings,
            scan_type,
            user,
            sync=True,
            **kwargs,
        )

    def async_process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        scan_type: str,
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:
        chunk_list = self.chunk_objects(parsed_findings)
        results_list = []
        # First kick off all the workers
        for findings_list in chunk_list:
            result = self.process_findings(
                test,
                parsed_findings,
                scan_type,
                user,
                sync=False,
                **kwargs,
            )
            # Since I dont want to wait until the task is done right now, save the id
            # So I can check on the task later
            results_list += [result]
        # After all tasks have been started, time to pull the results
        logger.info('IMPORT_SCAN: Collecting Findings')
        for results in results_list:
            serial_new_findings = results.get()
            new_findings += [next(deserialize("json", finding)).object for finding in serial_new_findings]
        logger.info('IMPORT_SCAN: All Findings Collected')
        # Indicate that the test is not complete yet as endpoints will still be rolling in.
        test.percent_complete = 50
        test.save()
        return new_findings