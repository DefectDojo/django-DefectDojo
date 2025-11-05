import logging

from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.serializers import serialize
from django.db.models.query_utils import Q

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
from dojo.decorators import we_want_async
from dojo.importers.base_importer import BaseImporter, Parser
from dojo.importers.options import ImporterOptions
from dojo.models import (
    Development_Environment,
    Finding,
    Notes,
    Test,
    Test_Import,
)
from dojo.utils import perform_product_grading
from dojo.validators import clean_tags

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DefaultReImporterOptions(ImporterOptions):
    def validate_test(
        self,
        *args: list,
        **kwargs: dict,
    ):
        return self.validate(
            "test",
            expected_types=[Test],
            required=True,
            default=None,
            **kwargs,
        )

    def validate_environment(
        self,
        *args: list,
        **kwargs: dict,
    ):
        return self.validate(
            "environment",
            expected_types=[Development_Environment],
            required=False,
            default=None,
            **kwargs,
        )


class DefaultReImporter(BaseImporter, DefaultReImporterOptions):
    """
    The classic reimporter process used by DefectDojo

    This importer is intended to be used when mitigation of
    vulnerabilities is the ultimate tool for getting a current
    point time view of security of a given product

    Dry Run Mode:
    -------------
    When dry_run=True, the importer performs a simulation of the reimport process
    without making any database changes. This allows users to preview what would
    happen during a real reimport.

    The dry_run mode uses in-memory tracking to accurately simulate deduplication,
    including matches between findings within the same scan report. This means that
    if finding 100 and 101 in the report have the same hash_code, finding 101 will
    correctly be identified as a duplicate of finding 100, just as in a real import.

    Known Limitations in Dry Run Mode:
    - Endpoint updates are not simulated
    - Finding groups are not processed
    - JIRA integration is skipped
    - No notifications are sent
    - Test/engagement timestamps are not updated
    """

    def __init__(self, *args, **kwargs):
        super().__init__(
            self,
            *args,
            import_type=Test_Import.REIMPORT_TYPE,
            **kwargs,
        )

    def _serialize_findings_for_dry_run(self, findings: list, is_new: bool = False) -> list:
        """
        Serialize finding objects to dictionaries for dry run response.

        Args:
            findings: List of Finding objects (saved or unsaved)
            is_new: Whether these are new findings (not yet in DB)

        Returns:
            List of dictionaries with finding details
        """
        serialized = []
        for finding in findings:
            finding_dict = {
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description if hasattr(finding, "description") else None,
                "cwe": finding.cwe if hasattr(finding, "cwe") else None,
                "cve": finding.cve if hasattr(finding, "cve") else None,
                "cvssv3": finding.cvssv3 if hasattr(finding, "cvssv3") else None,
                "numerical_severity": finding.numerical_severity if hasattr(finding, "numerical_severity") else None,
            }

            # Add ID for existing findings
            if not is_new and hasattr(finding, "id") and finding.id:
                finding_dict["id"] = finding.id

            # Add additional fields if available
            if hasattr(finding, "component_name") and finding.component_name:
                finding_dict["component_name"] = finding.component_name
            if hasattr(finding, "component_version") and finding.component_version:
                finding_dict["component_version"] = finding.component_version
            if hasattr(finding, "file_path") and finding.file_path:
                finding_dict["file_path"] = finding.file_path
            if hasattr(finding, "line") and finding.line:
                finding_dict["line"] = finding.line
            if hasattr(finding, "unique_id_from_tool") and finding.unique_id_from_tool:
                finding_dict["unique_id_from_tool"] = finding.unique_id_from_tool

            serialized.append(finding_dict)

        return serialized

    def process_scan(
        self,
        scan: TemporaryUploadedFile,
        *args: list,
        **kwargs: dict,
    ) -> tuple[Test, int, int, int, int, int, Test_Import, dict]:
        """
        The full step process of taking a scan report, and converting it to
        findings in the database. This entails the following actions:
        - Verify the API scan configuration (if supplied)
        - Parse the findings
        - Process the findings
        - Update the timestamps on the test (skipped in dry_run)
        - Update/Create import history objects (skipped in dry_run)
        - Send out notifications (skipped in dry_run)
        - Update the test progress (skipped in dry_run)

        In dry_run mode, only parsing and matching logic runs, with no database writes.

        Returns:
            Tuple containing test, counts, test_import, and optional findings_details dict
        """
        logger.debug(f"REIMPORT_SCAN: parameters: {locals()}")

        if self.dry_run:
            logger.info("REIMPORT_SCAN: Running in dry-run mode - no database changes will be made")

        # Validate the Tool_Configuration
        self.verify_tool_configuration_from_test()
        # Fetch the parser based upon the string version of the scan type
        parser = self.get_parser()
        # Get the findings from the parser based on what methods the parser supplies
        # This could either mean traditional file parsing, or API pull parsing
        parsed_findings = self.parse_findings(scan, parser) or []
        # process the findings in the foreground or background
        (
            new_findings,
            reactivated_findings,
            findings_to_mitigate,
            untouched_findings,
            findings_details,
        ) = self.determine_process_method(parsed_findings, **kwargs)

        # Close any old findings in the processed list (skipped in dry_run)
        closed_findings = self.close_old_findings(findings_to_mitigate, **kwargs)

        # Skip database updates in dry_run mode
        if not self.dry_run:
            # Update the timestamps of the test object by looking at the findings imported
            logger.debug("REIMPORT_SCAN: Updating test/engagement timestamps")
            self.update_timestamps()
            # Update the test meta
            self.update_test_meta()
            # Update the test tags
            self.update_test_tags()
            # Save the test and engagement for changes to take affect
            self.test.save()
            self.test.engagement.save()

            # Create a test import history object
            test_import_history = self.update_import_history(
                new_findings=new_findings,
                closed_findings=closed_findings,
                reactivated_findings=reactivated_findings,
                untouched_findings=untouched_findings,
            )

            # Send out notifications to the user
            logger.debug("REIMPORT_SCAN: Generating notifications")
            updated_count = len(closed_findings) + len(reactivated_findings) + len(new_findings)
            self.notify_scan_added(
                self.test,
                updated_count,
                new_findings=new_findings,
                findings_reactivated=reactivated_findings,
                findings_mitigated=closed_findings,
                findings_untouched=untouched_findings,
            )
            # Update the test progress to reflect that the import has completed
            logger.debug("REIMPORT_SCAN: Updating Test progress")
            self.update_test_progress()
        else:
            test_import_history = None
            updated_count = len(new_findings) + len(reactivated_findings) + len(closed_findings)

        logger.debug("REIMPORT_SCAN: Done")
        return (
            self.test,
            updated_count,
            len(new_findings),
            len(closed_findings),
            len(reactivated_findings),
            len(untouched_findings),
            test_import_history,
            findings_details,
        )

    def process_findings(
        self,
        parsed_findings: list[Finding],
        **kwargs: dict,
    ) -> tuple[list[Finding], list[Finding], list[Finding], list[Finding], dict]:
        """
        Processes findings from the scan report. In normal mode, saves findings to the database.
        In dry_run mode, only performs matching logic without any database writes.

        This process involves first saving associated objects such as endpoints, files,
        vulnerability IDs, and request response pairs. Once all that has been completed,
        the finding may be appended to a new or existing group based upon user selection
        at import time.

        Returns:
            Tuple containing (new_findings, reactivated_findings, to_mitigate, untouched, findings_details)
            - findings_details is a dict populated in dry_run mode with serialized finding information
        """
        self.deduplication_algorithm = self.determine_deduplication_algorithm()
        # Only process findings with the same service value (or None)
        # Even though the service values is used in the hash_code calculation,
        # we need to make sure there are no side effects such as closing findings
        # for findings with a different service value
        # https://github.com/DefectDojo/django-DefectDojo/issues/12754
        if self.service is not None:
            original_findings = self.test.finding_set.all().filter(service=self.service)
        else:
            original_findings = self.test.finding_set.all().filter(Q(service__isnull=True) | Q(service__exact=""))

        logger.debug(f"original_findings_qyer: {original_findings.query}")
        self.original_items = list(original_findings)
        logger.debug(f"original_items: {[(item.id, item.hash_code) for item in self.original_items]}")
        self.new_items = []
        self.reactivated_items = []
        self.unchanged_items = []
        self.group_names_to_findings_dict = {}
        # In dry_run mode, track new findings in-memory to enable proper deduplication
        # within the same scan report (e.g., if finding 100 and 101 have same hash_code)
        self.dry_run_new_findings = [] if self.dry_run else None
        # Progressive batching for chord execution
        post_processing_task_signatures = []
        current_batch_number = 1
        max_batch_size = 1024

        logger.debug(f"starting reimport of {len(parsed_findings) if parsed_findings else 0} items.")
        logger.debug(
            "STEP 1: looping over findings from the reimported report and trying to match them to existing findings"
        )
        deduplicationLogger.debug(
            f"Algorithm used for matching new findings to existing findings: {self.deduplication_algorithm}"
        )

        # Pre-sanitize and filter by minimum severity to avoid loop control pitfalls
        cleaned_findings = []
        for raw_finding in parsed_findings or []:
            sanitized = self.sanitize_severity(raw_finding)
            if Finding.SEVERITIES[sanitized.severity] > Finding.SEVERITIES[self.minimum_severity]:
                logger.debug(
                    "skipping finding due to minimum severity filter (finding=%s severity=%s min=%s)",
                    getattr(sanitized, "title", "<no-title>"),
                    sanitized.severity,
                    self.minimum_severity,
                )
                continue
            cleaned_findings.append(sanitized)

        for idx, unsaved_finding in enumerate(cleaned_findings):
            is_final = idx == len(cleaned_findings) - 1
            # Some parsers provide "mitigated" field but do not set timezone (because they are probably not available in the report)
            # Finding.mitigated is DateTimeField and it requires timezone
            if unsaved_finding.mitigated and not unsaved_finding.mitigated.tzinfo:
                unsaved_finding.mitigated = unsaved_finding.mitigated.replace(tzinfo=self.now.tzinfo)
            # Override the test if needed
            if not hasattr(unsaved_finding, "test"):
                unsaved_finding.test = self.test
            # Set the service supplied at import time
            if self.service is not None:
                unsaved_finding.service = self.service
            # Clean any endpoints that are on the finding
            self.endpoint_manager.clean_unsaved_endpoints(unsaved_finding.unsaved_endpoints)
            # Calculate the hash code to be used to identify duplicates
            unsaved_finding.hash_code = self.calculate_unsaved_finding_hash_code(unsaved_finding)
            deduplicationLogger.debug(f"unsaved finding's hash_code: {unsaved_finding.hash_code}")
            # Match any findings to this new one coming in
            matched_findings = self.match_new_finding_to_existing_finding(unsaved_finding)
            deduplicationLogger.debug(f"found {len(matched_findings)} findings matching with current new finding")
            # Determine how to proceed based on whether matches were found or not
            if matched_findings:
                existing_finding = matched_findings[0]
                if self.dry_run:
                    # In dry_run mode, skip database writes and just categorize the finding
                    finding, force_continue = self.categorize_matched_finding_for_dry_run(
                        unsaved_finding,
                        existing_finding,
                    )
                else:
                    finding, force_continue = self.process_matched_finding(
                        unsaved_finding,
                        existing_finding,
                    )
                # Determine if we should skip the rest of the loop
                if force_continue:
                    continue
                # Update endpoints on the existing finding with those on the new finding (skip in dry_run)
                if not self.dry_run and finding.dynamic_finding:
                    logger.debug(
                        "Re-import found an existing dynamic finding for this new "
                        "finding. Checking the status of endpoints",
                    )
                    self.endpoint_manager.update_endpoint_status(
                        existing_finding,
                        unsaved_finding,
                        self.user,
                    )
            else:
                if self.dry_run:
                    # In dry_run mode, just add to new_items without saving
                    self.new_items.append(unsaved_finding)
                    # Track in-memory for deduplication within the same scan report
                    self.dry_run_new_findings.append(unsaved_finding)
                    finding = unsaved_finding
                else:
                    finding = self.process_finding_that_was_not_matched(unsaved_finding)

            # Skip post-processing and database writes in dry_run mode
            if not self.dry_run:
                # This condition __appears__ to always be true, but am afraid to remove it
                if finding:
                    # Process the rest of the items on the finding
                    finding = self.finding_post_processing(
                        finding,
                        unsaved_finding,
                    )
                    # all data is already saved on the finding, we only need to trigger post processing

                    # Execute post-processing task immediately if async, otherwise execute synchronously
                    push_to_jira = self.push_to_jira and (not self.findings_groups_enabled or not self.group_by)

                    post_processing_task_signature = finding_helper.post_process_finding_save_signature(
                        finding,
                        dedupe_option=True,
                        rules_option=True,
                        product_grading_option=False,
                        issue_updater_option=True,
                        push_to_jira=push_to_jira,
                    )
                    post_processing_task_signatures.append(post_processing_task_signature)

                # Check if we should launch a chord (batch full or end of findings)
                if we_want_async(async_user=self.user) and post_processing_task_signatures:
                    post_processing_task_signatures, current_batch_number, _ = self.maybe_launch_post_processing_chord(
                        post_processing_task_signatures,
                        current_batch_number,
                        max_batch_size,
                        is_final,
                    )
                else:
                    post_processing_task_signature()

        self.to_mitigate = set(self.original_items) - set(self.reactivated_items) - set(self.unchanged_items)
        # due to #3958 we can have duplicates inside the same report
        # this could mean that a new finding is created and right after
        # that it is detected as the 'matched existing finding' for a
        # following finding in the same report
        # this means untouched can have this finding inside it,
        # while it is in fact a new finding. So we subtract new_items
        self.untouched = (
            set(self.unchanged_items) - set(self.to_mitigate) - set(self.new_items) - set(self.reactivated_items)
        )

        # Skip database updates in dry_run mode
        if not self.dry_run:
            # Process groups
            self.process_groups_for_all_findings(**kwargs)

            # Note: All chord batching is now handled within the loop above

            # Synchronous tasks were already executed during processing, just calculate grade
            perform_product_grading(self.test.engagement.product)

        # Process the results and return them back
        return self.process_results(**kwargs)

    def close_old_findings(
        self,
        findings: list[Finding],
        **kwargs: dict,
    ) -> list[Finding]:
        """
        Updates the status of findings that were detected as "old" by the reimport
        process findings methods. In dry_run mode, returns the list without making changes.
        """
        # First check if close old findings is desired
        if self.close_old_findings_toggle is False:
            return []

        # In dry_run mode, just return the findings list without making changes
        if self.dry_run:
            return list(findings)

        logger.debug("REIMPORT_SCAN: Closing findings no longer present in scan report")
        # Determine if pushing to jira or if the finding groups are enabled
        mitigated_findings = []
        for finding in findings:
            # Get any status changes that could have occurred earlier in the process
            # for special statuses only.
            # An example of such is a finding being reported as false positive, and
            # reimport makes this change in the database. However, the findings here
            # are calculated based from the original values before the reimport, so
            # any updates made during reimport are discarded without first getting the
            # state of the finding as it stands at this moment
            finding.refresh_from_db(fields=["false_p", "risk_accepted", "out_of_scope"])
            # Ensure the finding is not already closed
            if not finding.mitigated or not finding.is_mitigated:
                logger.debug("mitigating finding: %i:%s", finding.id, finding)
                self.mitigate_finding(
                    finding,
                    f"Mitigated by {self.test.test_type} re-upload.",
                    finding_groups_enabled=self.findings_groups_enabled,
                    product_grading_option=False,
                )
                mitigated_findings.append(finding)
        # push finding groups to jira since we only only want to push whole groups
        if self.findings_groups_enabled and self.push_to_jira:
            for finding_group in {finding.finding_group for finding in findings if finding.finding_group is not None}:
                jira_helper.push_to_jira(finding_group)

        # Calculate grade once after all findings have been closed
        if mitigated_findings:
            perform_product_grading(self.test.engagement.product)

        return mitigated_findings

    def parse_findings_static_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Finding]:
        """
        Parses the findings from file and assigns them to the test
        that was supplied
        """
        logger.debug("REIMPORT_SCAN: Parse findings")
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
        logger.debug("REIMPORT_SCAN parser v2: Create parse findings")
        return super().parse_findings_dynamic_test_type(scan, parser)

    def match_new_finding_to_existing_finding(
        self,
        unsaved_finding: Finding,
    ) -> list[Finding]:
        """
        Matches a single new finding to N existing findings and returns those matches.
        In dry_run mode, also checks against in-memory findings to simulate proper deduplication
        within the same scan report.
        """
        # This code should match the logic used for deduplication out of the re-import feature.
        # See utils.py deduplicate_* functions
        deduplicationLogger.debug("return findings bases on algorithm: %s", self.deduplication_algorithm)

        # Get matches from database
        db_matches = self._get_db_matches(unsaved_finding)

        # In dry_run mode, also check in-memory findings from current scan
        if self.dry_run and self.dry_run_new_findings:
            in_memory_matches = self._get_in_memory_matches(unsaved_finding)
            # Combine matches: in-memory findings should come first (they would have lower IDs)
            if in_memory_matches:
                deduplicationLogger.debug(f"Found {len(in_memory_matches)} in-memory matches in dry_run mode")
                # Return in-memory match (simulates what would happen if it was saved)
                return [in_memory_matches[0]]

        return db_matches

    def _get_db_matches(self, unsaved_finding: Finding) -> list[Finding]:
        """Get matches from the database based on deduplication algorithm"""
        if self.deduplication_algorithm == "hash_code":
            return (
                Finding.objects.filter(
                    test=self.test,
                    hash_code=unsaved_finding.hash_code,
                )
                .exclude(hash_code=None)
                .order_by("id")
            )
        if self.deduplication_algorithm == "unique_id_from_tool":
            deduplicationLogger.debug(f"unique_id_from_tool: {unsaved_finding.unique_id_from_tool}")
            return (
                Finding.objects.filter(
                    test=self.test,
                    unique_id_from_tool=unsaved_finding.unique_id_from_tool,
                )
                .exclude(unique_id_from_tool=None)
                .order_by("id")
            )
        if self.deduplication_algorithm == "unique_id_from_tool_or_hash_code":
            deduplicationLogger.debug(f"unique_id_from_tool: {unsaved_finding.unique_id_from_tool}")
            deduplicationLogger.debug(f"hash_code: {unsaved_finding.hash_code}")
            query = Finding.objects.filter(
                Q(test=self.test),
                (Q(hash_code__isnull=False) & Q(hash_code=unsaved_finding.hash_code))
                | (Q(unique_id_from_tool__isnull=False) & Q(unique_id_from_tool=unsaved_finding.unique_id_from_tool)),
            ).order_by("id")
            deduplicationLogger.debug(query.query)
            return query
        if self.deduplication_algorithm == "legacy":
            # This is the legacy reimport behavior. Although it's pretty flawed and doesn't match the legacy algorithm for deduplication,
            # this is left as is for simplicity.
            # Re-writing the legacy deduplication here would be complicated and counter-productive.
            # If you have use cases going through this section, you're advised to create a deduplication configuration for your parser
            logger.warning(
                "Legacy reimport. In case of issue, you're advised to create a deduplication configuration in order not to go through this section"
            )
            return Finding.objects.filter(
                title__iexact=unsaved_finding.title,
                test=self.test,
                severity=unsaved_finding.severity,
                numerical_severity=Finding.get_numerical_severity(unsaved_finding.severity),
            ).order_by("id")
        logger.error(f'Internal error: unexpected deduplication_algorithm: "{self.deduplication_algorithm}"')
        return None

    def _get_in_memory_matches(self, unsaved_finding: Finding) -> list[Finding]:
        """
        Check in-memory findings for matches (used in dry_run mode).
        This simulates the deduplication that would occur within the same scan report.
        """
        matches = []
        for in_memory_finding in self.dry_run_new_findings:
            if self.deduplication_algorithm == "hash_code":
                if in_memory_finding.hash_code and in_memory_finding.hash_code == unsaved_finding.hash_code:
                    matches.append(in_memory_finding)
            elif self.deduplication_algorithm == "unique_id_from_tool":
                if (
                    in_memory_finding.unique_id_from_tool
                    and in_memory_finding.unique_id_from_tool == unsaved_finding.unique_id_from_tool
                ):
                    matches.append(in_memory_finding)
            elif self.deduplication_algorithm == "unique_id_from_tool_or_hash_code":
                if (in_memory_finding.hash_code and in_memory_finding.hash_code == unsaved_finding.hash_code) or (
                    in_memory_finding.unique_id_from_tool
                    and in_memory_finding.unique_id_from_tool == unsaved_finding.unique_id_from_tool
                ):
                    matches.append(in_memory_finding)
            elif self.deduplication_algorithm == "legacy":
                if (
                    in_memory_finding.title.lower() == unsaved_finding.title.lower()
                    and in_memory_finding.severity == unsaved_finding.severity
                ):
                    matches.append(in_memory_finding)
        return matches

    def categorize_matched_finding_for_dry_run(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
    ) -> tuple[Finding, bool]:
        """
        Categorizes a matched finding for dry_run mode without making any database changes.
        Determines whether the finding would be reactivated, unchanged, etc.

        Returns:
            Tuple of (finding, force_continue) where force_continue indicates
            whether to skip further processing of this finding
        """
        # Check if special status (false positive, out of scope, risk accepted)
        if existing_finding.false_p or existing_finding.out_of_scope or existing_finding.risk_accepted:
            # Check if statuses match exactly
            if (
                existing_finding.false_p == unsaved_finding.false_p
                and existing_finding.out_of_scope == unsaved_finding.out_of_scope
                and existing_finding.risk_accepted == unsaved_finding.risk_accepted
            ):
                self.unchanged_items.append(existing_finding)
                return existing_finding, True
            # Risk accepted and inactive - don't sync status from scanner
            if existing_finding.risk_accepted and not existing_finding.active:
                self.unchanged_items.append(existing_finding)
                return existing_finding, False
            # Status mismatch but still considered unchanged for dry run purposes
            self.unchanged_items.append(existing_finding)
            return existing_finding, False

        # Check if currently mitigated
        if existing_finding.mitigated and existing_finding.is_mitigated:
            # Check if new finding is also mitigated
            if unsaved_finding.is_mitigated:
                self.unchanged_items.append(existing_finding)
                return existing_finding, True
            # Would be reactivated (unless do_not_reactivate is set)
            if self.do_not_reactivate:
                self.unchanged_items.append(existing_finding)
                return existing_finding, True
            # Would be reactivated
            self.reactivated_items.append(existing_finding)
            return existing_finding, False

        # Active finding matched - would remain unchanged
        self.unchanged_items.append(existing_finding)
        return existing_finding, False

    def process_matched_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
    ) -> tuple[Finding, bool]:
        """
        Determine how to handle the an existing finding based on the status
        that is possesses at the time of reimport
        """
        if existing_finding.false_p or existing_finding.out_of_scope or existing_finding.risk_accepted:
            return self.process_matched_special_status_finding(
                unsaved_finding,
                existing_finding,
            )
        if existing_finding.is_mitigated:
            return self.process_matched_mitigated_finding(
                unsaved_finding,
                existing_finding,
            )
        return self.process_matched_active_finding(
            unsaved_finding,
            existing_finding,
        )

    def process_matched_special_status_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
    ) -> tuple[Finding, bool]:
        """
        Determine if there is parity between statuses of the new and existing finding.
        If so, do not touch either finding, and move on to the next unsaved finding
        """
        logger.debug(
            f"Skipping existing finding (it is marked as false positive: {existing_finding.false_p} "
            f"and/or out of scope: {existing_finding.out_of_scope} or is a risk accepted: "
            f"{existing_finding.risk_accepted}) - {existing_finding.id}: {existing_finding.title} "
            f"({existing_finding.component_name} - {existing_finding.component_version})",
        )
        # If all statuses are the same between findings, we can safely move on to the next
        # finding in the report. Return True here to force a continue in the loop
        if (
            existing_finding.false_p == unsaved_finding.false_p
            and existing_finding.out_of_scope == unsaved_finding.out_of_scope
            and existing_finding.risk_accepted == unsaved_finding.risk_accepted
        ):
            self.unchanged_items.append(existing_finding)
            return existing_finding, True
        # If the finding is risk accepted and inactive in Defectdojo we do not sync the status from the scanner
        # We also need to add the finding to 'unchanged_items' as otherwise it will get mitigated by the reimporter
        # (Risk accepted findings are not set to mitigated by Defectdojo)
        # We however do not exit the loop as we do want to update the endpoints (in case some endpoints were fixed)
        if existing_finding.risk_accepted and not existing_finding.active:
            self.unchanged_items.append(existing_finding)
            return existing_finding, False
        # The finding was not an exact match, so we need to add more details about from the
        # new finding to the existing. Return False here to make process further
        return existing_finding, False

    def process_matched_mitigated_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
    ) -> tuple[Finding, bool]:
        """
        Determine how mitigated the existing and new findings really are. We need
        to cover circumstances where mitigation timestamps are different, and
        decide which one to honor
        """
        # if the reimported item has a mitigation time, we can compare
        if unsaved_finding.is_mitigated:
            # The new finding is already mitigated, so nothing to change on the
            # the existing finding
            self.unchanged_items.append(existing_finding)
            # Look closer at the mitigation timestamp
            if unsaved_finding.mitigated:
                logger.debug(f"item mitigated time: {unsaved_finding.mitigated.timestamp()}")
                logger.debug(f"finding mitigated time: {existing_finding.mitigated.timestamp()}")
                # Determine if the mitigation timestamp is the same between the new finding
                # and the existing finding. If they are, we do not need any further processing
                if unsaved_finding.mitigated.timestamp() == existing_finding.mitigated.timestamp():
                    msg = (
                        "New imported finding and already existing finding have the same mitigation "
                        "date, will skip as they are the same."
                    )
                else:
                    msg = (
                        "New imported finding and already existing finding are both mitigated but "
                        "have different dates, not taking action"
                    )
                logger.debug(msg)
                # Return True here to force the loop to continue to the next finding
                return existing_finding, True
            # even if there is no mitigation time, skip it, because both the current finding and
            # the reimported finding are is_mitigated
            # Return True here to force the loop to continue
            return existing_finding, True
        if self.do_not_reactivate:
            logger.debug(
                "Skipping reactivating by user's choice do_not_reactivate: "
                f" - {existing_finding.id}: {existing_finding.title} "
                f"({existing_finding.component_name} - {existing_finding.component_version})",
            )
            # Search for an existing note that this finding has been skipped for reactivation
            # before this current time
            reactivated_note_text = f"Finding has skipped reactivation from {self.scan_type} re-upload with user decision do_not_reactivate."
            existing_note = existing_finding.notes.filter(
                entry=reactivated_note_text,
                author=self.user,
            )
            # If a note has not been left before, we can skip this finding
            if len(existing_note) == 0:
                note = Notes(
                    entry=reactivated_note_text,
                    author=self.user,
                )
                note.save()
                existing_finding.notes.add(note)
            # Return True here to force the loop to continue to the next finding
            return existing_finding, True
        logger.debug(
            f"Reactivating:  - {existing_finding.id}: {existing_finding.title} "
            f"({existing_finding.component_name} - {existing_finding.component_version})",
        )
        existing_finding.mitigated = None
        existing_finding.is_mitigated = False
        existing_finding.mitigated_by = None
        existing_finding.active = True
        if self.verified is not None:
            existing_finding.verified = self.verified

        component_name = getattr(unsaved_finding, "component_name", None)
        component_version = getattr(unsaved_finding, "component_version", None)
        existing_finding.component_name = existing_finding.component_name or component_name
        existing_finding.component_version = existing_finding.component_version or component_version
        if existing_finding.get_sla_configuration().restart_sla_on_reactivation:
            # restart the sla start date to the current date, finding.save() will set new sla_expiration_date
            existing_finding.sla_start_date = self.now
        existing_finding = self.process_cve(existing_finding)
        if existing_finding.get_sla_configuration().restart_sla_on_reactivation:
            # restart the sla start date to the current date, finding.save() will set new sla_expiration_date
            existing_finding.sla_start_date = self.now
        # don't dedupe before endpoints are added, postprocessing will be done on next save (in calling method)
        existing_finding.save_no_options()

        note = Notes(entry=f"Re-activated by {self.scan_type} re-upload.", author=self.user)
        note.save()
        endpoint_statuses = existing_finding.status_finding.exclude(
            Q(false_positive=True) | Q(out_of_scope=True) | Q(risk_accepted=True),
        )
        self.endpoint_manager.chunk_endpoints_and_reactivate(endpoint_statuses)
        existing_finding.notes.add(note)
        self.reactivated_items.append(existing_finding)
        # The new finding is active while the existing on is mitigated. The existing finding needs to
        # be updated in some way
        # Return False here to make sure further processing happens
        return existing_finding, False

    def process_matched_active_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
    ) -> tuple[Finding, bool]:
        """
        The existing finding must be active here, so we need to compare it
        closely with the new finding coming in and determine how to proceed
        """
        # if finding associated to new item is none of risk accepted, mitigated, false positive or out of scope
        # existing findings may be from before we had component_name/version fields
        logger.debug(
            f"Updating existing finding: {existing_finding.id}: {existing_finding.title} "
            f"({existing_finding.component_name} - {existing_finding.component_version})",
        )
        # First check that the existing finding is definitely not mitigated
        if not (existing_finding.mitigated and existing_finding.is_mitigated):
            logger.debug("Reimported item matches a finding that is currently open.")
            if unsaved_finding.is_mitigated:
                logger.debug("Reimported mitigated item matches a finding that is currently open, closing.")
                # TODO: Implement a date comparison for opened defectdojo findings before closing them by reimporting,
                # as they could be force closed by the scanner but a DD user forces it open ?
                logger.debug(
                    f"Closing: {existing_finding.id}: {existing_finding.title} "
                    f"({existing_finding.component_name} - {existing_finding.component_version})",
                )
                existing_finding.mitigated = unsaved_finding.mitigated
                existing_finding.is_mitigated = True
                existing_finding.mitigated_by = unsaved_finding.mitigated_by
                existing_finding.active = False
                if self.verified is not None:
                    existing_finding.verified = self.verified
                existing_finding = self.process_cve(existing_finding)
                existing_finding.save_no_options()

            elif unsaved_finding.risk_accepted or unsaved_finding.false_p or unsaved_finding.out_of_scope:
                logger.debug("Reimported mitigated item matches a finding that is currently open, closing.")
                logger.debug(
                    f"Closing: {existing_finding.id}: {existing_finding.title} "
                    f"({existing_finding.component_name} - {existing_finding.component_version})",
                )
                existing_finding.risk_accepted = unsaved_finding.risk_accepted
                existing_finding.false_p = unsaved_finding.false_p
                existing_finding.out_of_scope = unsaved_finding.out_of_scope
                existing_finding.active = False
                if self.verified is not None:
                    existing_finding.verified = self.verified
                existing_finding = self.process_cve(existing_finding)
                existing_finding.save_no_options()
            else:
                # if finding is the same but list of affected was changed, finding is marked as unchanged. This is a known issue
                self.unchanged_items.append(existing_finding)
        # Set the component name and version on the existing finding if it is present
        # on the old finding, but not present on the existing finding (do not override)
        component_name = getattr(unsaved_finding, "component_name", None)
        component_version = getattr(unsaved_finding, "component_version", None)
        if (component_name is not None and not existing_finding.component_name) or (
            component_version is not None and not existing_finding.component_version
        ):
            existing_finding.component_name = existing_finding.component_name or component_name
            existing_finding.component_version = existing_finding.component_version or component_version
            existing_finding.save_no_options()
        # Return False here to make sure further processing happens
        return existing_finding, False

    def process_finding_that_was_not_matched(
        self,
        unsaved_finding: Finding,
    ) -> Finding:
        """Create a new finding from the one parsed from the report"""
        # Set some explicit settings
        unsaved_finding.reporter = self.user
        unsaved_finding.last_reviewed = self.now
        unsaved_finding.last_reviewed_by = self.user
        # indicates an override. Otherwise, do not change the value of unsaved_finding.active
        if self.active is not None:
            unsaved_finding.active = self.active
        # indicates an override. Otherwise, do not change the value of verified
        if self.verified is not None:
            unsaved_finding.verified = self.verified
        # scan_date was provided, override value from parser
        if self.scan_date_override:
            unsaved_finding.date = self.scan_date.date()
        unsaved_finding = self.process_cve(unsaved_finding)
        # Hash code is already calculated earlier as it's the primary matching criteria for reimport
        # Save it. Don't dedupe before endpoints are added.
        unsaved_finding.save_no_options()
        finding = unsaved_finding
        # Force parsers to use unsaved_tags (stored in finding_post_processing function below)
        finding.tags = None
        logger.debug(
            "Reimport created new finding as no existing finding match: "
            f"{finding.id}: {finding.title} "
            f"({finding.component_name} - {finding.component_version})",
        )
        # Manage the finding grouping selection
        self.process_finding_groups(
            unsaved_finding,
            self.group_names_to_findings_dict,
        )
        # Add the new finding to the list
        self.new_items.append(unsaved_finding)
        # Process any request/response pairs
        self.process_request_response_pairs(unsaved_finding)
        return unsaved_finding

    def finding_post_processing(
        self,
        finding: Finding,
        finding_from_report: Finding,
    ) -> None:
        """
        Save all associated objects to the finding after it has been saved
        for the purpose of foreign key restrictions
        """
        self.endpoint_manager.chunk_endpoints_and_disperse(finding, finding_from_report.unsaved_endpoints)
        if len(self.endpoints_to_add) > 0:
            self.endpoint_manager.chunk_endpoints_and_disperse(finding, self.endpoints_to_add)
        # Parsers must use unsaved_tags to store tags, so we can clean them
        if finding.unsaved_tags:
            finding.tags = clean_tags(finding.unsaved_tags)
        # Process any files
        if finding_from_report.unsaved_files:
            finding.unsaved_files = finding_from_report.unsaved_files
        self.process_files(finding)
        # Process vulnerability IDs
        if finding_from_report.unsaved_vulnerability_ids:
            finding.unsaved_vulnerability_ids = finding_from_report.unsaved_vulnerability_ids
        # legacy cve field has already been processed/set earlier
        return self.process_vulnerability_ids(finding)

    def process_groups_for_all_findings(
        self,
        **kwargs: dict,
    ) -> None:
        """
        Add findings to a group that may or may not exist, based upon the users
        selection at import time
        """
        for group_name, findings in self.group_names_to_findings_dict.items():
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

        if self.findings_groups_enabled and self.push_to_jira:
            for finding_group in {
                finding.finding_group
                for finding in self.reactivated_items + self.unchanged_items
                if finding.finding_group is not None and not finding.is_mitigated
            }:
                jira_helper.push_to_jira(finding_group)

    def process_results(
        self,
        **kwargs: dict,
    ) -> tuple[list[Finding], list[Finding], list[Finding], list[Finding], dict]:
        """
        Determine how to return the results based on whether the process was
        ran asynchronous or not. Also builds findings_details for dry_run mode.
        """
        # Build findings_details for dry_run mode
        if self.dry_run:
            findings_details = {
                "new_findings": self._serialize_findings_for_dry_run(self.new_items, is_new=True),
                "reactivated_findings": self._serialize_findings_for_dry_run(self.reactivated_items),
                "closed_findings": self._serialize_findings_for_dry_run(list(self.to_mitigate)),
                "untouched_findings": self._serialize_findings_for_dry_run(list(self.untouched)),
            }
        else:
            findings_details = {}

        if not kwargs.get("sync"):
            serialized_new_items = [serialize("json", [finding]) for finding in self.new_items]
            serialized_reactivated_items = [serialize("json", [finding]) for finding in self.reactivated_items]
            serialized_to_mitigate = [serialize("json", [finding]) for finding in self.to_mitigate]
            serialized_untouched = [serialize("json", [finding]) for finding in self.untouched]
            return (
                serialized_new_items,
                serialized_reactivated_items,
                serialized_to_mitigate,
                serialized_untouched,
                findings_details,
            )
        return self.new_items, self.reactivated_items, self.to_mitigate, self.untouched, findings_details

    def calculate_unsaved_finding_hash_code(
        self,
        unsaved_finding: Finding,
    ) -> str:
        return unsaved_finding.compute_hash_code()
