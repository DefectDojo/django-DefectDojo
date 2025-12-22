import logging

from django.conf import settings
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.serializers import serialize
from django.db.models.query_utils import Q
from django.urls import reverse

import dojo.jira_link.helper as jira_helper
from dojo.decorators import we_want_async
from dojo.finding import helper as finding_helper
from dojo.importers.base_importer import BaseImporter, Parser
from dojo.importers.options import ImporterOptions
from dojo.models import (
    Engagement,
    Finding,
    Test,
    Test_Import,
)
from dojo.notifications.helper import create_notification
from dojo.utils import perform_product_grading
from dojo.validators import clean_tags

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
    ) -> tuple[Test, int, int, int, int, int, Test_Import]:
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
        logger.debug(f"IMPORT_SCAN: parameters: {locals()}")
        # Validate the Tool_Configuration
        self.verify_tool_configuration_from_engagement()
        # Fetch the parser based upon the string version of the scan type
        parser = self.get_parser()
        # Get the findings from the parser based on what methods the parser supplies
        # This could either mean traditional file parsing, or API pull parsing
        parsed_findings = self.parse_findings(scan, parser) or []
        # process the findings in the foreground or background
        new_findings = self.determine_process_method(parsed_findings, **kwargs)
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
        logger.debug("IMPORT_SCAN: Generating notifications")
        create_notification(
            event="test_added",
            title=f"Test created for {self.test.engagement.product}: {self.test.engagement.name}: {self.test}",
            test=self.test,
            engagement=self.test.engagement,
            product=self.test.engagement.product,
            url=reverse("view_test", args=(self.test.id,)),
            url_api=reverse("test-detail", args=(self.test.id,)),
        )
        updated_count = len(new_findings) + len(closed_findings)
        self.notify_scan_added(
            self.test,
            updated_count,
            new_findings=new_findings,
            findings_mitigated=closed_findings,
        )
        # Update the test progress to reflect that the import has completed
        logger.debug("IMPORT_SCAN: Updating Test progress")
        self.update_test_progress()
        logger.debug("IMPORT_SCAN: Done")
        return self.test, 0, len(new_findings), len(closed_findings), 0, 0, test_import_history

    def process_findings(
        self,
        parsed_findings: list[Finding],
        **kwargs: dict,
    ) -> list[Finding]:
        # Batched post-processing (no chord): dispatch a task per 1000 findings or on final finding
        batch_finding_ids: list[int] = []
        batch_max_size = getattr(settings, "IMPORT_REIMPORT_DEDUPE_BATCH_SIZE", 1000)

        """
        Saves findings in memory that were parsed from the scan report into the database.
        This process involves first saving associated objects such as endpoints, files,
        vulnerability IDs, and request response pairs. Once all that has been completed,
        the finding may be appended to a new or existing group based upon user selection
        at import time
        """
        new_findings = []
        logger.debug("starting import of %i parsed findings.", len(parsed_findings) if parsed_findings else 0)
        group_names_to_findings_dict = {}

        # Pre-sanitize and filter by minimum severity
        cleaned_findings = []
        for raw_finding in parsed_findings or []:
            sanitized = self.sanitize_severity(raw_finding)
            if Finding.SEVERITIES[sanitized.severity] > Finding.SEVERITIES[self.minimum_severity]:
                logger.debug("skipping finding due to minimum severity filter (finding=%s severity=%s min=%s)", sanitized.title, sanitized.severity, self.minimum_severity)
                continue
            cleaned_findings.append(sanitized)

        for idx, unsaved_finding in enumerate(cleaned_findings):
            is_final_finding = idx == len(cleaned_findings) - 1

            # Some parsers provide "mitigated" field but do not set timezone (because they are probably not available in the report)
            # Finding.mitigated is DateTimeField and it requires timezone
            if unsaved_finding.mitigated and not unsaved_finding.mitigated.tzinfo:
                unsaved_finding.mitigated = unsaved_finding.mitigated.replace(tzinfo=self.now.tzinfo)
            # Set some explicit fields on the finding
            unsaved_finding.test = self.test
            unsaved_finding.reporter = self.user
            unsaved_finding.last_reviewed_by = self.user
            unsaved_finding.last_reviewed = self.now
            logger.debug("process_parsed_finding: unique_id_from_tool: %s, hash_code: %s, active from report: %s, verified from report: %s", unsaved_finding.unique_id_from_tool, unsaved_finding.hash_code, unsaved_finding.active, unsaved_finding.verified)
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

            # Force parsers to use unsaved_tags (stored in below after saving)
            unsaved_finding.tags = None
            finding = self.process_cve(unsaved_finding)
            # Calculate hash_code before saving based on unsaved_endpoints and unsaved_vulnerability_ids
            finding.set_hash_code(True)

            # postprocessing will be done after processing related fields like endpoints, vulnerability ids, etc.
            unsaved_finding.save_no_options()

            # Determine how the finding should be grouped
            self.process_finding_groups(
                finding,
                group_names_to_findings_dict,
            )
            # Process any request/response pairs
            self.process_request_response_pairs(finding)
            # Process any endpoints on the endpoint, or added on the form
            self.process_endpoints(finding, self.endpoints_to_add)
            # Parsers must use unsaved_tags to store tags, so we can clean them
            cleaned_tags = clean_tags(finding.unsaved_tags)
            if isinstance(cleaned_tags, list):
                finding.tags.set(cleaned_tags)
            elif isinstance(cleaned_tags, str):
                finding.tags.set([cleaned_tags])
            # Process any files
            self.process_files(finding)
            # Process vulnerability IDs
            finding = self.process_vulnerability_ids(finding)
            # Categorize this finding as a new one
            new_findings.append(finding)
            # all data is already saved on the finding, we only need to trigger post processing in batches
            logger.debug("process_findings: self.push_to_jira=%s, self.findings_groups_enabled=%s, self.group_by=%s",
                         self.push_to_jira, self.findings_groups_enabled, self.group_by)
            push_to_jira = self.push_to_jira and (not self.findings_groups_enabled or not self.group_by)
            logger.debug("process_findings: computed push_to_jira=%s", push_to_jira)
            batch_finding_ids.append(finding.id)

            # If batch is full or we're at the end, dispatch one batched task
            if len(batch_finding_ids) >= batch_max_size or is_final_finding:
                finding_ids_batch = list(batch_finding_ids)
                batch_finding_ids.clear()
                logger.debug("process_findings: dispatching batch with push_to_jira=%s (batch_size=%d, is_final=%s)",
                             push_to_jira, len(finding_ids_batch), is_final_finding)
                if we_want_async(async_user=self.user):
                    signature = finding_helper.post_process_findings_batch_signature(
                        finding_ids_batch,
                        dedupe_option=True,
                        rules_option=True,
                        product_grading_option=True,
                        issue_updater_option=True,
                        push_to_jira=push_to_jira,
                    )
                    logger.debug("process_findings: signature created with push_to_jira=%s, signature.kwargs=%s",
                                 push_to_jira, signature.kwargs)
                    signature()
                else:
                    finding_helper.post_process_findings_batch(
                        finding_ids_batch,
                        dedupe_option=True,
                        rules_option=True,
                        product_grading_option=True,
                        issue_updater_option=True,
                        push_to_jira=push_to_jira,
                    )

            # No chord: tasks are dispatched immediately above per batch

        for (group_name, findings) in group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(
                group_name,
                findings,
                self.group_by,
                create_finding_groups_for_all_findings=self.create_finding_groups_for_all_findings,
                **kwargs,
            )
            if self.push_to_jira:
                if findings[0].finding_group is not None:
                    jira_helper.push_to_jira(findings[0].finding_group)
                else:
                    jira_helper.push_to_jira(findings[0])
            else:
                logger.debug("push_to_jira is False, not pushing to JIRA")

        # Note: All chord batching is now handled within the loop above

        # Always perform an initial grading, even though it might get overwritten later.
        perform_product_grading(self.test.engagement.product)

        sync = kwargs.get("sync", True)
        if not sync:
            return [serialize("json", [finding]) for finding in new_findings]
        return new_findings

    def close_old_findings(
        self,
        findings: list[Finding],
        **kwargs: dict,
    ) -> list[Finding]:
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

        logger.debug("IMPORT_SCAN: Closing findings no longer present in scan report")
        # Remove all the findings that are coming from the report already mitigated
        new_hash_codes = []
        new_unique_ids_from_tool = []
        for finding in findings.values():
            # Do not process closed findings in the report
            if finding.get("is_mitigated", False):
                continue
            # Grab the hash code
            if (hash_code := finding.get("hash_code")) is not None:
                new_hash_codes.append(hash_code)
            if (unique_id_from_tool := finding.get("unique_id_from_tool")) is not None:
                new_unique_ids_from_tool.append(unique_id_from_tool)
        # Get the initial filtered list of old findings to be closed without
        # considering the scope of the product or engagement
        old_findings = Finding.objects.filter(
            test__test_type=self.test.test_type,
            active=True,
        ).exclude(test=self.test)
        # Filter further based on the deduplication algorithm set on the test
        self.deduplication_algorithm = self.determine_deduplication_algorithm()
        if self.deduplication_algorithm in {"hash_code", "legacy"}:
            old_findings = old_findings.exclude(
                hash_code__in=new_hash_codes,
            )
        if self.deduplication_algorithm == "unique_id_from_tool":
            old_findings = old_findings.exclude(
                unique_id_from_tool__in=new_unique_ids_from_tool,
            )
        if self.deduplication_algorithm == "unique_id_from_tool_or_hash_code":
            old_findings = old_findings.exclude(
                (Q(hash_code__isnull=False) & Q(hash_code__in=new_hash_codes))
                | (
                    Q(unique_id_from_tool__isnull=False)
                    & Q(unique_id_from_tool__in=new_unique_ids_from_tool)
                ),
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
            old_findings = old_findings.filter(Q(service__isnull=True) | Q(service__exact=""))
        # Update the status of the findings and any endpoints
        for old_finding in old_findings:
            self.mitigate_finding(
                old_finding,
                (
                    "This finding has been automatically closed "
                    "as it is not present anymore in recent scans."
                ),
                finding_groups_enabled=self.findings_groups_enabled,
                product_grading_option=False,
            )
        # push finding groups to jira since we only only want to push whole groups
        if self.findings_groups_enabled and self.push_to_jira:
            for finding_group in {finding.finding_group for finding in old_findings if finding.finding_group is not None}:
                jira_helper.push_to_jira(finding_group)

        # Calculate grade once after all findings have been closed
        if old_findings:
            perform_product_grading(self.test.engagement.product)

        return old_findings

    def parse_findings_static_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Finding]:
        """
        Creates a test object as part of the import process as there is not one present
        at the time of import. Once the test is created, proceed with the traditional
        file import as usual from the base class
        """
        # by default test_type == scan_type
        # Create a new test if it has not already been created
        if not self.test:
            self.test = self.create_test(self.scan_type)
        logger.debug("IMPORT_SCAN: Parse findings")
        # Use the parent method for the rest of this
        return super().parse_findings_static_test_type(scan, parser)

    def parse_findings_dynamic_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Finding]:
        """
        Uses the parser to fetch any tests that may have been created
        by the API based parser, aggregates all findings from each test
        into a single test, and then renames the test is applicable
        """
        logger.debug("IMPORT_SCAN parser v2: Create Test and parse findings")
        return super().parse_findings_dynamic_test_type(scan, parser)
