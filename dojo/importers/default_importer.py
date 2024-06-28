import logging
from typing import List, Tuple

from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.serializers import deserialize, serialize
from django.db.models.query_utils import Q

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
import dojo.notifications.helper as notifications_helper
from dojo.importers.base_importer import BaseImporter, Parser
from dojo.importers.options import ImporterOptions
from dojo.models import (
    Engagement,
    Finding,
    Test,
    Test_Import,
)

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DefaultImporterOptions(ImporterOptions):
    def validate_engagement(
        self,
        *args: list,
        **kwargs: dict,
    ):
        return self.validate(
            "engagement",
            expected_types=[Engagement],
            required=True,
            default=None,
            **kwargs,
        )


class DefaultImporter(BaseImporter, DefaultImporterOptions):
    """
    The classic importer process used by DefectDojo

    This Importer is intended to be used when auditing the history
    of findings at a given point in time is required
    """
    def __init__(self, *args, **kwargs):
        super().__init__(
            self,
            *args,
            import_type=Test_Import.IMPORT_TYPE,
            **kwargs,
        )

    def create_test(
        self,
        test_type_name: str,
    ) -> Test:
        """
        Create a fresh test object to be used by the importer. This
        new test will be attached to the supplied engagement with the
        supplied user being marked as the lead of the test
        """
        self.test = Test.objects.create(
            title=self.test_title,
            engagement=self.engagement,
            lead=self.lead,
            environment=self.environment,
            test_type=self.get_or_create_test_type(test_type_name),
            scan_type=self.scan_type,
            target_start=self.scan_date,
            target_end=self.scan_date,
            percent_complete=50,
            version=self.version,
            branch_tag=self.branch_tag,
            build_id=self.build_id,
            commit_hash=self.commit_hash,
            api_scan_configuration=self.api_scan_configuration,
            tags=self.tags,
        )
        return self.test

    def process_scan(
        self,
        scan: TemporaryUploadedFile,
        *args: list,
        **kwargs: dict,
    ) -> Tuple[Test, int, int, int, int, int, Test_Import]:
        """
        The full step process of taking a scan report, and converting it to
        findings in the database. This entails the the following actions:
        - Verify the API scan configuration (if supplied)
        - Parser the findings
        - Process the findings
        - Update the timestamps on the test
        - Update/Create import history objects
        - Send out notifications
        - Update the test progress
        """
        logger.debug(f'IMPORT_SCAN: parameters: {locals()}')
        # Validate the Tool_Configuration
        self.verify_tool_configuration_from_engagement()
        # Fetch the parser based upon the string version of the scan type
        parser = self.get_parser()
        # Get the findings from the parser based on what methods the parser supplies
        # This could either mean traditional file parsing, or API pull parsing
        self.parsed_findings = self.parse_findings(scan, parser)
        # process the findings in the foreground or background
        new_findings = self.determine_process_method(self.parsed_findings, **kwargs)
        # Close any old findings in the processed list if the the user specified for that
        # to occur in the form that is then passed to the kwargs
        closed_findings = self.close_old_findings(self.test.finding_set.all(), **kwargs)
        # Update the timestamps of the test object by looking at the findings imported
        self.update_timestamps()
        # Update the test meta
        self.update_test_meta()
        # Save the test and engagement for changes to take affect
        self.test.save()
        self.test.engagement.save()
        # Create a test import history object to record the flags sent to the importer
        # This operation will return None if the user does not have the import history
        # feature enabled
        test_import_history = self.update_import_history(
            new_findings=new_findings,
            closed_findings=closed_findings,
        )
        # Send out some notifications to the user
        logger.debug('IMPORT_SCAN: Generating notifications')
        notifications_helper.notify_test_created(self.test)
        updated_count = len(new_findings) + len(closed_findings)
        notifications_helper.notify_scan_added(
            self.test,
            updated_count,
            new_findings=new_findings,
            findings_mitigated=closed_findings,
        )
        # Update the test progress to reflect that the import has completed
        logger.debug('IMPORT_SCAN: Updating Test progress')
        self.update_test_progress()
        logger.debug('IMPORT_SCAN: Done')
        return self.test, 0, len(new_findings), len(closed_findings), 0, 0, test_import_history

    def process_findings(
        self,
        parsed_findings: List[Finding],
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Saves findings in memory that were parsed from the scan report into the database.
        This process involves first saving associated objects such as endpoints, files,
        vulnerability IDs, and request response pairs. Once all that has been completed,
        the finding may be appended to a new or existing group based upon user selection
        at import time
        """
        new_findings = []
        logger.debug('starting import of %i parsed findings.', len(parsed_findings) if parsed_findings else 0)
        group_names_to_findings_dict = {}

        for unsaved_finding in parsed_findings:
            # make sure the severity is something is digestible
            unsaved_finding = self.sanitize_severity(unsaved_finding)
            # Filter on minimum severity if applicable
            if (minimum_severity := kwargs.get("minimum_severity")) and (Finding.SEVERITIES[unsaved_finding.severity] > Finding.SEVERITIES[minimum_severity]):
                # finding's severity is below the configured threshold : ignoring the finding
                continue

            # Some parsers provide "mitigated" field but do not set timezone (because they are probably not available in the report)
            # Finding.mitigated is DateTimeField and it requires timezone
            if unsaved_finding.mitigated and not unsaved_finding.mitigated.tzinfo:
                unsaved_finding.mitigated = unsaved_finding.mitigated.replace(tzinfo=self.now.tzinfo)
            # Set some explicit fields on the finding
            unsaved_finding.test = self.test
            unsaved_finding.reporter = self.user
            unsaved_finding.last_reviewed_by = self.user
            unsaved_finding.last_reviewed = self.now
            logger.debug('process_parsed_findings: active from report: %s, verified from report: %s', unsaved_finding.active, unsaved_finding.verified)
            # indicates an override. Otherwise, do not change the value of unsaved_finding.active
            if self.active is not None:
                unsaved_finding.active = self.active
            # indicates an override. Otherwise, do not change the value of verified
            if self.verified is not None:
                unsaved_finding.verified = self.verified
            # scan_date was provided, override value from parser
            if self.scan_date_override:
                unsaved_finding.date = self.scan_date.date()
            if self.service is not None:
                unsaved_finding.service = self.service
            unsaved_finding.save(dedupe_option=False)
            finding = unsaved_finding
            # Determine how the finding should be grouped
            self.process_finding_groups(
                finding,
                group_names_to_findings_dict,
            )
            # Process any request/response pairs
            self.process_request_response_pairs(finding)
            # Process any endpoints on the endpoint, or added on the form
            self.process_endpoints(finding, self.endpoints_to_add)
            # Process any tags
            if finding.unsaved_tags:
                finding.tags = finding.unsaved_tags
            # Process any files
            self.process_files(finding)
            # Process vulnerability IDs
            finding = self.process_vulnerability_ids(finding)
            # Categorize this finding as a new one
            new_findings.append(finding)
            # to avoid pushing a finding group multiple times, we push those outside of the loop
            if self.findings_groups_enabled and self.group_by:
                finding.save()
            else:
                finding.save(push_to_jira=self.push_to_jira)

        for (group_name, findings) in group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(
                group_name,
                findings,
                self.group_by,
                create_finding_groups_for_all_findings=self.create_finding_groups_for_all_findings,
                **kwargs
            )
            if self.push_to_jira:
                if findings[0].finding_group is not None:
                    jira_helper.push_to_jira(findings[0].finding_group)
                else:
                    jira_helper.push_to_jira(findings[0])

        sync = kwargs.get('sync', True)
        if not sync:
            return [serialize('json', [finding, ]) for finding in new_findings]
        return new_findings

    def close_old_findings(
        self,
        findings: List[Finding],
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Closes old findings based on a hash code match at either the product
        or the engagement scope. Closing an old finding entails setting the
        finding to mitigated status, setting all endpoint statuses to mitigated,
        as well as leaving a not on the finding indicating that it was mitigated
        because the vulnerability is no longer present in the submitted scan report.
        """
        # First check if close old findings is desired
        if not self.close_old_findings_toggle:
            return []
        logger.debug("REIMPORT_SCAN: Closing findings no longer present in scan report")
        # Close old active findings that are not reported by this scan.
        # Refactoring this to only call test.finding_set.values() once.
        findings = findings.values()
        mitigated_hash_codes = []
        new_hash_codes = []
        for finding in findings:
            new_hash_codes.append(finding["hash_code"])
            if finding.get("is_mitigated", None):
                mitigated_hash_codes.append(finding["hash_code"])
                for hash_code in new_hash_codes:
                    if hash_code == finding["hash_code"]:
                        new_hash_codes.remove(hash_code)
        # Get the initial filtered list of old findings to be closed without
        # considering the scope of the product or engagement
        old_findings = Finding.objects.exclude(
            test=self.test
        ).exclude(
            hash_code__in=new_hash_codes
        ).filter(
            test__test_type=self.test.test_type,
            active=True
        )
        # Accommodate for product scope or engagement scope
        if self.close_old_findings_product_scope:
            old_findings = old_findings.filter(test__engagement__product=self.test.engagement.product)
        else:
            old_findings = old_findings.filter(test__engagement=self.test.engagement)
        # Use the service to differentiate further
        if self.service is not None:
            old_findings = old_findings.filter(service=self.service)
        else:
            old_findings = old_findings.filter(Q(service__isnull=True) | Q(service__exact=''))
        # Update the status of the findings and any endpoints
        for old_finding in old_findings:
            self.mitigate_finding(
                old_finding,
                (
                    "This finding has been automatically closed "
                    "as it is not present anymore in recent scans."
                ),
                self.findings_groups_enabled,
            )
        # push finding groups to jira since we only only want to push whole groups
        if self.findings_groups_enabled and self.push_to_jira:
            for finding_group in {finding.finding_group for finding in old_findings if finding.finding_group is not None}:
                jira_helper.push_to_jira(finding_group)

        return old_findings

    def parse_findings_static_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> List[Finding]:
        """
        Creates a test object as part of the import process as there is not one present
        at the time of import. Once the test is created, proceed with the traditional
        file import as usual from the base class
        """
        # by default test_type == scan_type
        self.test = self.create_test(self.scan_type)
        logger.debug('IMPORT_SCAN: Parse findings')
        # Use the parent method for the rest of this
        return super().parse_findings_static_test_type(scan, parser)

    def parse_findings_dynamic_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> List[Finding]:
        """
        Uses the parser to fetch any tests that may have been created
        by the API based parser, aggregates all findings from each test
        into a single test, and then renames the test is applicable
        """
        logger.debug('IMPORT_SCAN parser v2: Create Test and parse findings')
        tests = self.parse_dynamic_test_type_tests(scan, parser)
        parsed_findings = []
        # Make sure we have at least one test returned
        if len(tests) == 0:
            logger.info(f'No tests found in import for {self.scan_type}')
            self.test = None
            return parsed_findings
        # for now we only consider the first test in the list and artificially aggregate all findings of all tests
        # this is the same as the old behavior as current import/reimporter implementation doesn't handle the case
        # when there is more than 1 test
        #
        # we also aggregate the label of the Test_type to show the user the original self.scan_type
        # only if they are different. This is to support meta format like SARIF
        # so a report that have the label 'CodeScanner' will be changed to 'CodeScanner Scan (SARIF)'
        test_type_name = self.scan_type
        # Determine if we should use a custom test type name
        if tests[0].type:
            test_type_name = f"{tests[0].type} Scan"
            if test_type_name != self.scan_type:
                test_type_name = f"{test_type_name} ({self.scan_type})"
        # Create a new test
        self.test = self.create_test(test_type_name)
        # This part change the name of the Test
        # we get it from the data of the parser
        test_raw = tests[0]
        if test_raw.name:
            self.test.name = test_raw.name
        if test_raw.description:
            self.test.description = test_raw.description
        self.test.save()
        logger.debug('IMPORT_SCAN parser v2: Parse findings (aggregate)')
        # Aggregate all the findings and return them with the newly created test
        return self.parse_dynamic_test_type_findings_from_tests(tests)

    def async_process_findings(
        self,
        parsed_findings: List[Finding],
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Processes findings in chunks within N number of processes. The
        ASYNC_FINDING_IMPORT_CHUNK_SIZE setting will determine how many
        findings will be processed in a given worker/process/thread
        """
        chunk_list = self.chunk_findings(parsed_findings)
        results_list = []
        new_findings = []
        # First kick off all the workers
        for findings_list in chunk_list:
            result = self.process_findings(
                findings_list,
                sync=False,
                **kwargs,
            )
            # Since I dont want to wait until the task is done right now, save the id
            # So I can check on the task later
            results_list += [result]
        # After all tasks have been started, time to pull the results
        logger.info('IMPORT_SCAN: Collecting Findings')
        for results in results_list:
            serial_new_findings = results
            new_findings += [next(deserialize("json", finding)).object for finding in serial_new_findings]
        logger.info('IMPORT_SCAN: All Findings Collected')
        # Indicate that the test is not complete yet as endpoints will still be rolling in.
        self.test.percent_complete = 50
        self.test.save()
        return new_findings
