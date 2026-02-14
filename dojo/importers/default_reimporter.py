import logging

from django.conf import settings
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.db.models.query_utils import Q

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.finding.deduplication import (
    find_candidates_for_deduplication_hash,
    find_candidates_for_deduplication_uid_or_hash,
    find_candidates_for_deduplication_unique_id,
    find_candidates_for_reimport_legacy,
)
from dojo.importers.base_importer import BaseImporter, Parser
from dojo.importers.options import ImporterOptions
from dojo.jira_link.helper import is_keep_in_sync_with_jira
from dojo.location.status import FindingLocationStatus
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
    """

    def __init__(self, *args, **kwargs):
        super().__init__(
            self,
            *args,
            import_type=Test_Import.REIMPORT_TYPE,
            **kwargs,
        )

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
        logger.debug(f"REIMPORT_SCAN: parameters: {locals()}")
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
        ) = self.determine_process_method(parsed_findings, **kwargs)
        # Close any old findings in the processed list if the the user specified for that
        # to occur in the form that is then passed to the kwargs
        closed_findings = self.close_old_findings(findings_to_mitigate, **kwargs)
        # Update the timestamps of the test object by looking at the findings imported
        logger.debug("REIMPORT_SCAN: Updating test/engagement timestamps")
        # Update the timestamps of the test object by looking at the findings imported
        self.update_timestamps()
        # Update the test meta
        self.update_test_meta()
        # Update the test tags
        self.update_test_tags()
        # Save the test and engagement for changes to take affect
        self.test.save()
        self.test.engagement.save()
        logger.debug("REIMPORT_SCAN: Updating test tags")
        # Create a test import history object to record the flags sent to the importer
        # This operation will return None if the user does not have the import history
        # feature enabled
        test_import_history = self.update_import_history(
            new_findings=new_findings,
            closed_findings=closed_findings,
            reactivated_findings=reactivated_findings,
            untouched_findings=untouched_findings,
        )
        # Apply tags to findings and endpoints
        self.apply_import_tags(
            new_findings=new_findings,
            closed_findings=closed_findings,
            reactivated_findings=reactivated_findings,
            untouched_findings=untouched_findings,
        )
        # Send out som notifications to the user
        logger.debug("REIMPORT_SCAN: Generating notifications")
        updated_count = (
            len(closed_findings) + len(reactivated_findings) + len(new_findings)
        )
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
        logger.debug("REIMPORT_SCAN: Done")
        return (
            self.test,
            updated_count,
            len(new_findings),
            len(closed_findings),
            len(reactivated_findings),
            len(untouched_findings),
            test_import_history,
        )

    def get_reimport_match_candidates_for_batch(
        self,
        batch_findings: list[Finding],
    ) -> tuple[dict, dict, dict]:
        """
        Fetch candidate matches for a batch of *unsaved* findings during reimport.

        This is intentionally a separate method so downstream editions (e.g. Dojo Pro)
        can override candidate retrieval without copying the full `process_findings()`
        implementation.

        Is overridden in Pro.

        Returns:
            (candidates_by_hash, candidates_by_uid, candidates_by_key)

        """
        candidates_by_hash: dict = {}
        candidates_by_uid: dict = {}
        candidates_by_key: dict = {}

        if self.deduplication_algorithm == "hash_code":
            candidates_by_hash = find_candidates_for_deduplication_hash(
                self.test,
                batch_findings,
                mode="reimport",
            )
        elif self.deduplication_algorithm == "unique_id_from_tool":
            candidates_by_uid = find_candidates_for_deduplication_unique_id(
                self.test,
                batch_findings,
                mode="reimport",
            )
        elif self.deduplication_algorithm == "unique_id_from_tool_or_hash_code":
            candidates_by_uid, candidates_by_hash = find_candidates_for_deduplication_uid_or_hash(
                self.test,
                batch_findings,
                mode="reimport",
            )
        elif self.deduplication_algorithm == "legacy":
            candidates_by_key = find_candidates_for_reimport_legacy(self.test, batch_findings)

        return candidates_by_hash, candidates_by_uid, candidates_by_key

    def add_new_finding_to_candidates(
        self,
        finding: Finding,
        candidates_by_hash: dict,
        candidates_by_uid: dict,
        candidates_by_key: dict,
    ) -> None:
        """
        Add a newly created finding to candidate dictionaries for subsequent findings in the same batch.

        This allows duplicates within the same scan report to be detected even when they're processed
        in the same batch. When a new finding is created (no match found), it is added to the candidate
        dictionaries so that subsequent findings in the same batch can match against it.

        Is overriden in Pro

        Args:
            finding: The newly created finding to add to candidates
            candidates_by_hash: Dictionary mapping hash_code to list of findings (modified in-place)
            candidates_by_uid: Dictionary mapping unique_id_from_tool to list of findings (modified in-place)
            candidates_by_key: Dictionary mapping (title_lower, severity) to list of findings (modified in-place)

        """
        if not finding:
            return

        if finding.hash_code:
            candidates_by_hash.setdefault(finding.hash_code, []).append(finding)
            deduplicationLogger.debug(
                f"Added finding {finding.id} (hash_code: {finding.hash_code}) to candidates for next findings in this report",
            )
        if finding.unique_id_from_tool:
            candidates_by_uid.setdefault(finding.unique_id_from_tool, []).append(finding)
            deduplicationLogger.debug(
                f"Added finding {finding.id} (unique_id_from_tool: {finding.unique_id_from_tool}) to candidates for next findings in this report",
            )
        if finding.title:
            legacy_key = (finding.title.lower(), finding.severity)
            candidates_by_key.setdefault(legacy_key, []).append(finding)
            deduplicationLogger.debug(
                f"Added finding {finding.id} (title: {finding.title}, severity: {finding.severity}) to candidates for next findings in this report",
            )

    def process_findings(
        self,
        parsed_findings: list[Finding],
        **kwargs: dict,
    ) -> tuple[list[Finding], list[Finding], list[Finding], list[Finding]]:
        """
        Saves findings in memory that were parsed from the scan report into the database.
        This process involves first saving associated objects such as endpoints/locations, files,
        vulnerability IDs, and request response pairs. Once all that has been completed,
        the finding may be appended to a new or existing group based upon user selection
        at import time
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

        logger.debug(f"starting reimport of {len(parsed_findings) if parsed_findings else 0} items.")
        logger.debug("STEP 1: looping over findings from the reimported report and trying to match them to existing findings")
        deduplicationLogger.debug(f"Algorithm used for matching new findings to existing findings: {self.deduplication_algorithm}")

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

        batch_finding_ids: list[int] = []
        # Batch size for deduplication/post-processing (only new findings)
        dedupe_batch_max_size = getattr(settings, "IMPORT_REIMPORT_DEDUPE_BATCH_SIZE", 1000)
        # Batch size for candidate matching (all findings, before matching)
        match_batch_max_size = getattr(settings, "IMPORT_REIMPORT_MATCH_BATCH_SIZE", 1000)

        # Process findings in batches to enable batch candidate fetching
        # This avoids the 1+N query problem by fetching all candidates for a batch at once
        for batch_start in range(0, len(cleaned_findings), match_batch_max_size):
            batch_end = min(batch_start + match_batch_max_size, len(cleaned_findings))
            batch_findings = cleaned_findings[batch_start:batch_end]
            is_final_batch = batch_end == len(cleaned_findings)

            logger.debug(f"Processing reimport batch {batch_start}-{batch_end} of {len(cleaned_findings)} findings")

            # Prepare findings in batch: set test, service, calculate hash codes
            for unsaved_finding in batch_findings:
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
                if settings.V3_FEATURE_LOCATIONS:
                    # Clean any locations that are on the finding
                    self.location_manager.clean_unsaved_locations(unsaved_finding.unsaved_locations)
                else:
                    # TODO: Delete this after the move to Locations
                    # Clean any endpoints that are on the finding
                    self.endpoint_manager.clean_unsaved_endpoints(unsaved_finding.unsaved_endpoints)
                # Calculate the hash code to be used to identify duplicates
                unsaved_finding.hash_code = self.calculate_unsaved_finding_hash_code(unsaved_finding)
                deduplicationLogger.debug(f"unsaved finding's hash_code: {unsaved_finding.hash_code}")

            # Fetch all candidates for this batch at once (batch candidate finding)
            candidates_by_hash, candidates_by_uid, candidates_by_key = self.get_reimport_match_candidates_for_batch(
                batch_findings,
            )

            # Process each finding in the batch using pre-fetched candidates
            for idx, unsaved_finding in enumerate(batch_findings):
                is_final = is_final_batch and idx == len(batch_findings) - 1

                # Match any findings to this new one coming in using pre-fetched candidates
                matched_findings = self.match_finding_to_candidate_reimport(
                    unsaved_finding,
                    candidates_by_hash=candidates_by_hash,
                    candidates_by_uid=candidates_by_uid,
                    candidates_by_key=candidates_by_key,
                )
                deduplicationLogger.debug(f"found {len(matched_findings)} findings matching with current new finding")
                # Determine how to proceed based on whether matches were found or not
                if matched_findings:
                    existing_finding = matched_findings[0]
                    finding, force_continue = self.process_matched_finding(
                        unsaved_finding,
                        existing_finding,
                    )
                    # Findings that have already exist cannot be moved to into a group
                    finding_will_be_grouped = False
                    # Determine if we should skip the rest of the loop
                    if force_continue:
                        continue
                    # Update endpoints on the existing finding with those on the new finding
                    if finding.dynamic_finding:
                        if settings.V3_FEATURE_LOCATIONS:
                            logger.debug(
                                "Re-import found an existing dynamic finding for this new "
                                "finding. Checking the status of locations",
                            )
                            self.location_manager.update_location_status(
                                existing_finding,
                                unsaved_finding,
                                self.user,
                            )
                        else:
                            # TODO: Delete this after the move to Locations
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
                    finding, finding_will_be_grouped = self.process_finding_that_was_not_matched(unsaved_finding)

                    # Add newly created finding to candidates for subsequent findings in this batch
                    self.add_new_finding_to_candidates(
                        finding,
                        candidates_by_hash,
                        candidates_by_uid,
                        candidates_by_key,
                    )

                # This condition __appears__ to always be true, but am afraid to remove it
                if finding:
                    # Process the rest of the items on the finding
                    finding = self.finding_post_processing(
                        finding,
                        unsaved_finding,
                    )
                    # all data is already saved on the finding, we only need to trigger post processing in batches
                    push_to_jira = self.push_to_jira and ((not self.findings_groups_enabled or not self.group_by) or not finding_will_be_grouped)
                    batch_finding_ids.append(finding.id)

                    # Post-processing batches (deduplication, rules, etc.) are separate from matching batches.
                    # These batches only contain "new" findings that were saved (not matched to existing findings).
                    # In reimport scenarios, typically most findings match existing ones, so only a small fraction
                    # of findings in each matching batch become new findings that need deduplication.
                    #
                    # We accumulate finding IDs across matching batches rather than dispatching at the end of each
                    # matching batch. This ensures deduplication batches stay close to the intended batch size
                    # (e.g., 1000 findings) for optimal bulk operation efficiency, even when only ~10% of findings
                    # in matching batches are new. If we dispatched at the end of each matching batch, we would
                    # end up with many small deduplication batches (e.g., ~100 findings each), reducing efficiency.
                    #
                    # The two batch types serve different purposes:
                    # - Matching batches: optimize candidate fetching (solve 1+N query problem)
                    # - Deduplication batches: optimize bulk operations (larger batches = fewer queries)
                    # They don't need to be aligned since they optimize different operations.
                    if len(batch_finding_ids) >= dedupe_batch_max_size or is_final:
                        finding_ids_batch = list(batch_finding_ids)
                        batch_finding_ids.clear()
                        dojo_dispatch_task(
                            finding_helper.post_process_findings_batch,
                            finding_ids_batch,
                            dedupe_option=True,
                            rules_option=True,
                            product_grading_option=True,
                            issue_updater_option=True,
                            push_to_jira=push_to_jira,
                            jira_instance_id=getattr(self.jira_instance, "id", None),
                        )

        # No chord: tasks are dispatched immediately above per batch

        self.to_mitigate = (set(self.original_items) - set(self.reactivated_items) - set(self.unchanged_items))
        # due to #3958 we can have duplicates inside the same report
        # this could mean that a new finding is created and right after
        # that it is detected as the 'matched existing finding' for a
        # following finding in the same report
        # this means untouched can have this finding inside it,
        # while it is in fact a new finding. So we subtract new_items
        self.untouched = set(self.unchanged_items) - set(self.to_mitigate) - set(self.new_items) - set(self.reactivated_items)
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
        process findings methods
        """
        # First check if close old findings is desired
        if self.close_old_findings_toggle is False:
            return []
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
        # We dont check if the finding jira sync is applicable quite yet until we can get in the loop
        # but this is a way to at least make it that far
        if self.findings_groups_enabled and (self.push_to_jira or getattr(self.jira_instance, "finding_jira_sync", False)):
            for finding_group in {finding.finding_group for finding in findings if finding.finding_group is not None}:
                # Check the push_to_jira flag again to potentially shorty circuit without checking for existing findings
                if self.push_to_jira or is_keep_in_sync_with_jira(finding_group, prefetched_jira_instance=self.jira_instance):
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

    def match_finding_to_candidate_reimport(
        self,
        unsaved_finding: Finding,
        candidates_by_hash: dict | None = None,
        candidates_by_uid: dict | None = None,
        candidates_by_key: dict | None = None,
    ) -> list[Finding]:
        """
        Matches a single new finding to existing findings using pre-fetched candidate dictionaries.
        This avoids individual database queries by using batch-fetched candidates.

        Args:
            unsaved_finding: The finding to match
            candidates_by_hash: Dictionary mapping hash_code to list of findings (for hash_code algorithm)
            candidates_by_uid: Dictionary mapping unique_id_from_tool to list of findings (for unique_id algorithms)
            candidates_by_key: Dictionary mapping (title_lower, severity) to list of findings (for legacy algorithm)

        Returns:
            List of matching findings, ordered by id

        """
        deduplicationLogger.debug("matching finding for reimport using algorithm: %s", self.deduplication_algorithm)

        if self.deduplication_algorithm == "hash_code":
            if candidates_by_hash is None or unsaved_finding.hash_code is None:
                return []
            matches = candidates_by_hash.get(unsaved_finding.hash_code, [])
            return sorted(matches, key=lambda f: f.id)

        if self.deduplication_algorithm == "unique_id_from_tool":
            if candidates_by_uid is None or unsaved_finding.unique_id_from_tool is None:
                return []
            matches = candidates_by_uid.get(unsaved_finding.unique_id_from_tool, [])
            return sorted(matches, key=lambda f: f.id)

        if self.deduplication_algorithm == "unique_id_from_tool_or_hash_code":
            if candidates_by_hash is None and candidates_by_uid is None:
                return []

            if unsaved_finding.hash_code is None and unsaved_finding.unique_id_from_tool is None:
                return []

            # Collect matches from both hash_code and unique_id_from_tool
            matches_by_id = {}

            if unsaved_finding.hash_code is not None:
                hash_matches = candidates_by_hash.get(unsaved_finding.hash_code, [])
                for match in hash_matches:
                    matches_by_id[match.id] = match

            if unsaved_finding.unique_id_from_tool is not None:
                uid_matches = candidates_by_uid.get(unsaved_finding.unique_id_from_tool, [])
                for match in uid_matches:
                    matches_by_id[match.id] = match

            matches = list(matches_by_id.values())
            return sorted(matches, key=lambda f: f.id)

        if self.deduplication_algorithm == "legacy":
            if candidates_by_key is None or not unsaved_finding.title:
                return []
            key = (unsaved_finding.title.lower(), unsaved_finding.severity)
            matches = candidates_by_key.get(key, [])
            return sorted(matches, key=lambda f: f.id)

        logger.error(f'Internal error: unexpected deduplication_algorithm: "{self.deduplication_algorithm}"')
        return []

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
        # We however do not exit the loop as we do want to update the endpoints/locations (in case some
        # endpoints/locations were fixed)
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
        if existing_finding.fix_available != unsaved_finding.fix_available:
            existing_finding.fix_available = unsaved_finding.fix_available
            existing_finding.fix_version = unsaved_finding.fix_version

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
        # don't dedupe before endpoints/locations are added, postprocessing will be done on next save (in calling method)
        existing_finding.save_no_options()

        note = Notes(entry=f"Re-activated by {self.scan_type} re-upload.", author=self.user)
        note.save()
        if settings.V3_FEATURE_LOCATIONS:
            # Reactivate mitigated locations
            mitigated_locations = existing_finding.locations.filter(status=FindingLocationStatus.Mitigated)
            self.location_manager.chunk_locations_and_reactivate(mitigated_locations)
        else:
            # TODO: Delete this after the move to Locations
            # Reactivate mitigated endpoints that are not false positives, out of scope, or risk accepted
            endpoint_statuses = existing_finding.status_finding.exclude(
                Q(false_positive=True)
                | Q(out_of_scope=True)
                | Q(risk_accepted=True),
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
            if existing_finding.fix_available != unsaved_finding.fix_available:
                existing_finding.fix_available = unsaved_finding.fix_available
                existing_finding.fix_version = unsaved_finding.fix_version
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
    ) -> tuple[Finding, bool]:
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
        # Save it. Don't dedupe before endpoints/locations are added.
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
        finding_will_be_grouped = self.process_finding_groups(
            unsaved_finding,
            self.group_names_to_findings_dict,
        )
        # Add the new finding to the list
        self.new_items.append(unsaved_finding)
        # Process any request/response pairs
        self.process_request_response_pairs(unsaved_finding)
        return unsaved_finding, finding_will_be_grouped

    def reconcile_vulnerability_ids(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Reconcile vulnerability IDs for an existing finding.
        Checks if IDs have changed before updating to avoid unnecessary database operations.
        Uses prefetched data if available, otherwise fetches efficiently.

        Args:
            finding: The existing finding to reconcile vulnerability IDs for.
                Must have unsaved_vulnerability_ids set.

        Returns:
            The finding object

        """
        vulnerability_ids_to_process = finding.unsaved_vulnerability_ids or []

        # Use prefetched data directly without triggering queries
        existing_vuln_ids = {v.vulnerability_id for v in finding.vulnerability_id_set.all()}
        new_vuln_ids = set(vulnerability_ids_to_process)

        # Early exit if unchanged
        if existing_vuln_ids == new_vuln_ids:
            logger.debug(
                f"Skipping vulnerability_ids update for finding {finding.id} - "
                f"vulnerability_ids unchanged: {sorted(existing_vuln_ids)}",
            )
            return finding

        # Update if changed
        finding_helper.save_vulnerability_ids(finding, vulnerability_ids_to_process, delete_existing=True)
        return finding

    def finding_post_processing(
        self,
        finding: Finding,
        finding_from_report: Finding,
    ) -> Finding:
        """
        Save all associated objects to the finding after it has been saved
        for the purpose of foreign key restrictions
        """
        if settings.V3_FEATURE_LOCATIONS:
            self.location_manager.chunk_locations_and_disperse(finding, finding_from_report.unsaved_locations)
            if len(self.endpoints_to_add) > 0:
                self.location_manager.chunk_locations_and_disperse(finding, self.endpoints_to_add)
        else:
            # TODO: Delete this after the move to Locations
            self.endpoint_manager.chunk_endpoints_and_disperse(finding, finding_from_report.unsaved_endpoints)
            if len(self.endpoints_to_add) > 0:
                self.endpoint_manager.chunk_endpoints_and_disperse(finding, self.endpoints_to_add)
        # Parsers shouldn't use the tags field, and use unsaved_tags instead.
        # Merge any tags set by parser into unsaved_tags
        tags_from_parser = finding_from_report.tags if isinstance(finding_from_report.tags, list) else []
        unsaved_tags_from_parser = finding_from_report.unsaved_tags if isinstance(finding_from_report.unsaved_tags, list) else []
        merged_tags = unsaved_tags_from_parser + tags_from_parser
        if merged_tags:
            finding_from_report.unsaved_tags = merged_tags
        if finding_from_report.unsaved_tags:
            cleaned_tags = clean_tags(finding_from_report.unsaved_tags)
            if isinstance(cleaned_tags, list):
                finding.tags.set(cleaned_tags)
            elif isinstance(cleaned_tags, str):
                finding.tags.set([cleaned_tags])
        # Process any files
        if finding_from_report.unsaved_files:
            finding.unsaved_files = finding_from_report.unsaved_files
        self.process_files(finding)
        # Process vulnerability IDs
        # Copy unsaved_vulnerability_ids from the report finding to the existing finding
        # so reconcile_vulnerability_ids can process them
        # Always set it (even if empty list) so we can clear existing IDs when report has none
        finding.unsaved_vulnerability_ids = finding_from_report.unsaved_vulnerability_ids or []
        # Store the current cve value to check if it changes
        old_cve = finding.cve
        # legacy cve field has already been processed/set earlier
        finding = self.reconcile_vulnerability_ids(finding)
        # Save the finding only if the cve field was changed by save_vulnerability_ids
        # This is temporary as the cve field will be phased out
        if finding.cve != old_cve:
            finding.save()
        return finding

    def process_groups_for_all_findings(
        self,
        **kwargs: dict,
    ) -> None:
        """
        Add findings to a group that may or may not exist, based upon the users
        selection at import time
        """
        for (group_name, findings) in self.group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(
                group_name,
                findings,
                self.group_by,
                create_finding_groups_for_all_findings=self.create_finding_groups_for_all_findings,
                **kwargs,
            )
            # We dont check if the finding jira sync is applicable quite yet until we can get in the loop
            # but this is a way to at least make it that far
            if self.push_to_jira or getattr(self.jira_instance, "finding_jira_sync", False):
                object_to_push = findings[0].finding_group if findings[0].finding_group is not None else findings[0]
                # Check the push_to_jira flag again to potentially shorty circuit without checking for existing findings
                if self.push_to_jira or is_keep_in_sync_with_jira(object_to_push, prefetched_jira_instance=self.jira_instance):
                    jira_helper.push_to_jira(object_to_push)
        # We dont check if the finding jira sync is applicable quite yet until we can get in the loop
        # but this is a way to at least make it that far
        if self.findings_groups_enabled and (self.push_to_jira or getattr(self.jira_instance, "finding_jira_sync", False)):
            for finding_group in {
                    finding.finding_group
                    for finding in self.reactivated_items + self.unchanged_items
                    if finding.finding_group is not None and not finding.is_mitigated
            }:
                # Check the push_to_jira flag again to potentially shorty circuit without checking for existing findings
                if self.push_to_jira or is_keep_in_sync_with_jira(finding_group, prefetched_jira_instance=self.jira_instance):
                    jira_helper.push_to_jira(finding_group)

    def process_results(
        self,
        **kwargs: dict,
    ) -> tuple[list[Finding], list[Finding], list[Finding], list[Finding]]:
        """Return the finding lists collected during process_findings."""
        return self.new_items, self.reactivated_items, self.to_mitigate, self.untouched

    def calculate_unsaved_finding_hash_code(
        self,
        unsaved_finding: Finding,
    ) -> str:
        # this is overridden in Pro, but will still call this via super()
        deduplicationLogger.debug("Calculating hash code for unsaved finding")
        return unsaved_finding.compute_hash_code()
