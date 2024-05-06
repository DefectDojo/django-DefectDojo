import logging
from abc import ABC
from datetime import datetime
from typing import List, Tuple

from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.serializers import deserialize, serialize
from django.db.models.query_utils import Q
from django.utils import timezone

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
import dojo.notifications.helper as notifications_helper
from dojo.importers.base_importer import BaseImporter, Parser
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Notes,
    Test,
    Test_Import,
)
from dojo.utils import is_finding_groups_enabled

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class DefaultReImporter(BaseImporter):
    """
    The classic reimporter process used by DefectDojo

    This importer is intended to be used when mitigation of
    vulnerabilities is the ultimate tool for getting a current
    point time view of security of a given product
    """
    def __init__(self, *args: list, **kwargs: dict):
        """
        Bypass the __init__ method of the BaseImporter class
        as it will raise a `NotImplemented` exception
        """
        ABC.__init__(self, *args, **kwargs)

    def __new__(self, *args: list, **kwargs: dict):
        """
        Bypass the __new__ method of the BaseImporter class
        as it will raise a `NotImplemented` exception
        """
        return ABC.__new__(self, *args, **kwargs)

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
        logger.debug(f'REIMPORT_SCAN: parameters: {locals()}')
        # Get a user in some point
        user = self.get_user_if_supplied(user=user)
        # Validate the Tool_Configuration
        test = self.verify_tool_configuration_from_test(
            kwargs.get("api_scan_configuration", None),
            test
        )
        # Make sure timezone is applied to dates
        kwargs["scan_date"], kwargs["now"] = self.add_timezone_scan_date_and_now(
            kwargs.get("scan_date"),
            now=kwargs.get("now", timezone.now())
        )
        # Fetch the parser based upon the string version of the scan type
        parser = self.get_parser(scan_type)
        # Get the findings from the parser based on what methods the parser supplies
        # This could either mean traditional file parsing, or API pull parsing
        parsed_findings = self.parse_findings(parser, scan_type, scan, test=test, engagement=engagement, **kwargs)
        # process the findings in the foreground or background
        (
            new_findings,
            reactivated_findings,
            findings_to_mitigate,
            untouched_findings,
        ) = self.determine_process_method(test, parsed_findings, user, **kwargs)
        # Close any old findings in the processed list if the the user specified for that
        # to occur in the form that is then passed to the kwargs
        closed_findings = self.close_old_findings(test, findings_to_mitigate, user, **kwargs)
        # Update the timestamps of the test object by looking at the findings imported
        logger.debug("REIMPORT_SCAN: Updating test/engagement timestamps")
        test = self.update_timestamps(test, **kwargs)
        # Update the test meta
        test = self.update_test_meta(test, **kwargs)
        # Save the test and engagement for changes to take affect
        test.save()
        test.engagement.save()
        logger.debug("REIMPORT_SCAN: Updating test tags")
        self.update_test_tags(test, kwargs.get("tags", []))
        # Create a test import history object to record the flags sent to the importer
        # This operation will return None if the user does not have the import history
        # feature enabled
        test_import_history = self.update_import_history(
            Test_Import.REIMPORT_TYPE,
            test,
            new_findings=new_findings,
            closed_findings=closed_findings,
            reactivated_findings=reactivated_findings,
            untouched_findings=untouched_findings,
            **kwargs,
        )
        # Send out som notifications to the user
        logger.debug('REIMPORT_SCAN: Generating notifications')
        updated_count = (
            len(closed_findings) + len(reactivated_findings) + len(new_findings)
        )
        notifications_helper.notify_scan_added(
            test,
            updated_count,
            new_findings=new_findings,
            findings_mitigated=closed_findings,
            findings_reactivated=reactivated_findings,
            findings_untouched=untouched_findings,
        )
        # Update the test progress to reflect that the import has completed
        logger.debug('REIMPORT_SCAN: Updating Test progress')
        self.update_test_progress(test)
        logger.debug('REIMPORT_SCAN: Done')
        return (
            test,
            updated_count,
            len(new_findings),
            len(closed_findings),
            len(reactivated_findings),
            len(untouched_findings),
            test_import_history,
        )

    def process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        **kwargs: dict,
    ) -> Tuple[List[Finding], List[Finding], List[Finding], List[Finding]]:
        """
        Saves findings in memory that were parsed from the scan report into the database.
        This process involves first saving associated objects such as endpoints, files,
        vulnerability IDs, and request response pairs. Once all that has been completed,
        the finding may be appended to a new or existing group based upon user selection
        at import time
        """

        original_items = list(test.finding_set.all())
        deduplication_algorithm = test.deduplication_algorithm
        group_names_to_findings_dict = {}
        new_items = []
        reactivated_items = []
        unchanged_items = []

        group_names_to_findings_dict = {}
        logger.debug(f"starting reimport of {len(parsed_findings) if parsed_findings else 0} items.")
        logger.debug("STEP 1: looping over findings from the reimported report and trying to match them to existing findings")
        deduplicationLogger.debug(f"Algorithm used for matching new findings to existing findings: {deduplication_algorithm}")

        for unsaved_finding in parsed_findings:
            # make sure the severity is something is digestible
            unsaved_finding = self.sanitize_severity(unsaved_finding)
            # Filter on minimum severity if applicable
            if (minimum_severity := kwargs.get("minimum_severity")) and (Finding.SEVERITIES[unsaved_finding.severity] > Finding.SEVERITIES[minimum_severity]):
                # finding's severity is below the configured threshold : ignoring the finding
                continue

            now = kwargs.get("now")
            group_by = kwargs.get("group_by")
            push_to_jira = kwargs.get("push_to_jira", False)
            # Some parsers provide "mitigated" field but do not set timezone (because they are probably not available in the report)
            # Finding.mitigated is DateTimeField and it requires timezone
            if unsaved_finding.mitigated and not unsaved_finding.mitigated.tzinfo:
                unsaved_finding.mitigated = unsaved_finding.mitigated.replace(tzinfo=now.tzinfo)
            # Override the test if needed
            if not hasattr(unsaved_finding, "test"):
                unsaved_finding.test = test
            # Set the service supplied at import time
            if service := kwargs.get("service"):
                unsaved_finding.service = service
            # Clean any endpoints that are on the finding
            self.clean_unsaved_endpoints(unsaved_finding.unsaved_endpoints)
            # Calculate the hash code to be used to identify duplicates
            unsaved_finding.hash_code = unsaved_finding.compute_hash_code()
            deduplicationLogger.debug(f"unsaved finding's hash_code: {unsaved_finding.hash_code}")
            # Match any findings to this new one coming in
            matched_findings = self.match_new_finding_to_existing_finding(unsaved_finding, test, deduplication_algorithm)
            deduplicationLogger.debug(f"found {len(matched_findings)} findings matching with current new finding")
            # Determine how to proceed based on whether matches were found or not
            if matched_findings:
                existing_finding = matched_findings[0]
                finding, force_continue = self.process_matched_finding(
                    unsaved_finding,
                    existing_finding,
                    user,
                    new_items,
                    reactivated_items,
                    unchanged_items,
                    **kwargs
                )
                # Determine if we should skip the rest of the loop
                if force_continue:
                    continue
                # Update endpoints on the existing finding with those on the new finding
                if finding.dynamic_finding:
                    logger.debug(
                        "Re-import found an existing dynamic finding for this new "
                        "finding. Checking the status of endpoints"
                    )
                    self.update_endpoint_status(existing_finding, unsaved_finding, user)
            else:
                finding = self.process_finding_that_was_not_matched(
                    unsaved_finding,
                    user,
                    group_names_to_findings_dict,
                    new_items,
                    reactivated_items,
                    unchanged_items,
                    **kwargs
                )
            # This condition __appears__ to always be true, but am afraid to remove it
            if finding:
                # Process the rest of the items on the finding
                finding = self.finding_post_processing(
                    finding,
                    unsaved_finding,
                    test,
                    new_items,
                    reactivated_items,
                    unchanged_items,
                    **kwargs
                )
                # finding = new finding or existing finding still in the upload report
                # to avoid pushing a finding group multiple times, we push those outside of the loop
                if is_finding_groups_enabled() and group_by:
                    finding.save()
                else:
                    finding.save(push_to_jira=push_to_jira)

        to_mitigate = (set(original_items) - set(reactivated_items) - set(unchanged_items))
        # due to #3958 we can have duplicates inside the same report
        # this could mean that a new finding is created and right after
        # that it is detected as the 'matched existing finding' for a
        # following finding in the same report
        # this means untouched can have this finding inside it,
        # while it is in fact a new finding. So we subtract new_items
        untouched = set(unchanged_items) - set(to_mitigate) - set(new_items)
        # Process groups
        self.process_groups_for_all_findings(
            group_names_to_findings_dict,
            reactivated_items,
            unchanged_items,
            **kwargs,
        )
        # Process the results and return them back
        return self.process_results(
            new_items,
            reactivated_items,
            to_mitigate,
            untouched,
            **kwargs,
        )

    def close_old_findings(
        self,
        test: Test,
        findings: List[Finding],
        user: Dojo_User,
        scan_date: datetime = timezone.now(),
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Updates the status of findings that were detected as "old" by the reimport
        process findings methods
        """
        # First check if close old findings is desired
        if kwargs.get("close_old_findings") is False:
            return []
        logger.debug("REIMPORT_SCAN: Closing findings no longer present in scan report")
        # Determine if pushing to jira or if the finding groups are enabled
        push_to_jira = kwargs.get("push_to_jira", False)
        finding_groups_enabled = is_finding_groups_enabled()
        mitigated_findings = []
        for finding in findings:
            if not finding.mitigated or not finding.is_mitigated:
                logger.debug("mitigating finding: %i:%s", finding.id, finding)
                self.mitigate_finding(
                    finding,
                    user,
                    scan_date,
                    f"Mitigated by {test.test_type} re-upload.",
                    finding_groups_enabled,
                    push_to_jira,
                )
                mitigated_findings.append(finding)
        # push finding groups to jira since we only only want to push whole groups
        if finding_groups_enabled and push_to_jira:
            for finding_group in {finding.finding_group for finding in findings if finding.finding_group is not None}:
                jira_helper.push_to_jira(finding_group)

        return mitigated_findings

    def parse_findings_static_test_type(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        test: Test = None,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Parses the findings from file and assigns them to the test
        that was supplied
        """
        logger.debug("REIMPORT_SCAN: Parse findings")
        # Use the parent method for the rest of this
        return BaseImporter.parse_findings_static_test_type(
            self,
            parser,
            scan_type,
            scan,
            test=test,
            **kwargs,
        )

    def parse_findings_dynamic_test_type(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Uses the parser to fetch any tests that may have been created
        by the API based parser, aggregates all findings from each test
        into a single test, and then renames the test is applicable
        """
        logger.debug("REIMPORT_SCAN parser v2: Create parse findings")
        return BaseImporter.parse_findings_dynamic_test_type(
            self,
            parser,
            scan_type,
            scan,
            **kwargs,
        )

    def sync_process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        **kwargs: dict,
    ) -> Tuple[List[Finding], List[Finding], List[Finding], List[Finding]]:
        """
        Processes findings in a synchronous manner such that all findings
        will be processed in a worker/process/thread
        """
        return self.process_findings(
            test,
            parsed_findings,
            user,
            sync=True,
            **kwargs,
        )

    def async_process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        **kwargs: dict,
    ) -> Tuple[List[Finding], List[Finding], List[Finding], List[Finding]]:
        """
        Processes findings in chunks within N number of processes. The
        ASYNC_FINDING_IMPORT_CHUNK_SIZE setting will determine how many
        findings will be processed in a given worker/process/thread
        """
        chunk_list = self.chunk_objects(parsed_findings)
        new_findings = []
        reactivated_findings = []
        findings_to_mitigate = []
        untouched_findings = []
        # First kick off all the workers
        for findings_list in chunk_list:
            result = self.process_findings(
                test,
                findings_list,
                user,
                sync=False,
                **kwargs,
            )
            # Since I dont want to wait until the task is done right now, save the id
            # So I can check on the task later
            results_list += [result]
        # After all tasks have been started, time to pull the results
        logger.debug("REIMPORT_SCAN: Collecting Findings")
        for results in results_list:
            (
                serial_new_findings,
                serial_reactivated_findings,
                serial_findings_to_mitigate,
                serial_untouched_findings,
            ) = results.get()
            new_findings += [
                next(deserialize("json", finding)).object
                for finding in serial_new_findings
            ]
            reactivated_findings += [
                next(deserialize("json", finding)).object
                for finding in serial_reactivated_findings
            ]
            findings_to_mitigate += [
                next(deserialize("json", finding)).object
                for finding in serial_findings_to_mitigate
            ]
            untouched_findings += [
                next(deserialize("json", finding)).object
                for finding in serial_untouched_findings
            ]
            logger.debug("REIMPORT_SCAN: All Findings Collected")
            # Indicate that the test is not complete yet as endpoints will still be rolling in.
            test.percent_complete = 50
            test.save()
            self.update_test_progress(test, sync=False)

        return new_findings, reactivated_findings, findings_to_mitigate, untouched_findings

    def match_new_finding_to_existing_finding(
        self,
        unsaved_finding: Finding,
        test: Test,
        deduplication_algorithm: str,
    ) -> List[Finding]:
        """
        Matches a single new finding to N existing findings and then returns those matches
        """
        # This code should match the logic used for deduplication out of the re-import feature.
        # See utils.py deduplicate_* functions
        deduplicationLogger.debug('return findings bases on algorithm: %s', deduplication_algorithm)
        if deduplication_algorithm == 'hash_code':
            return Finding.objects.filter(
                test=test,
                hash_code=unsaved_finding.hash_code
            ).exclude(hash_code=None).order_by('id')
        elif deduplication_algorithm == 'unique_id_from_tool':
            return Finding.objects.filter(
                test=test,
                unique_id_from_tool=unsaved_finding.unique_id_from_tool
            ).exclude(unique_id_from_tool=None).order_by('id')
        elif deduplication_algorithm == 'unique_id_from_tool_or_hash_code':
            query = Finding.objects.filter(
                Q(test=test),
                (Q(hash_code__isnull=False) & Q(hash_code=unsaved_finding.hash_code))
                | (Q(unique_id_from_tool__isnull=False) & Q(unique_id_from_tool=unsaved_finding.unique_id_from_tool))
            ).order_by('id')
            deduplicationLogger.debug(query.query)
            return query
        elif deduplication_algorithm == 'legacy':
            # This is the legacy reimport behavior. Although it's pretty flawed and doesn't match the legacy algorithm for deduplication,
            # this is left as is for simplicity.
            # Re-writing the legacy deduplication here would be complicated and counter-productive.
            # If you have use cases going through this section, you're advised to create a deduplication configuration for your parser
            logger.debug("Legacy reimport. In case of issue, you're advised to create a deduplication configuration in order not to go through this section")
            return Finding.objects.filter(
                    title=unsaved_finding.title,
                    test=test,
                    severity=unsaved_finding.severity,
                    numerical_severity=Finding.get_numerical_severity(unsaved_finding.severity)).order_by('id')
        else:
            logger.error(f"Internal error: unexpected deduplication_algorithm: \"{deduplication_algorithm}\"")
            return None

    def process_matched_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
        user: Dojo_User,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> Tuple[Finding, bool]:
        """
        Determine how to handle the an existing finding based on the status
        that is possesses at the time of reimport
        """
        if existing_finding.false_p or existing_finding.out_of_scope or existing_finding.risk_accepted:
            return self.process_matched_special_status_finding(
                unsaved_finding,
                existing_finding,
                user,
                new_items,
                reactivated_items,
                unchanged_items,
                **kwargs
            )
        elif existing_finding.is_mitigated:
            return self.process_matched_mitigated_finding(
                unsaved_finding,
                existing_finding,
                user,
                new_items,
                reactivated_items,
                unchanged_items,
                **kwargs
            )
        else:
            return self.process_matched_active_finding(
                unsaved_finding,
                existing_finding,
                user,
                new_items,
                reactivated_items,
                unchanged_items,
                **kwargs
            )

    def process_matched_special_status_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
        user: Dojo_User,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> Tuple[Finding, bool]:
        """
        Determine if there is parity between statuses of the new and existing finding.
        If so, do not touch either finding, and move on to the next unsaved finding
        """
        logger.debug(
            f"Skipping existing finding (it is marked as false positive: {existing_finding.false_p} "
            f"and/or out of scope: {existing_finding.out_of_scope} or is a risk accepted: "
            f"{existing_finding.risk_accepted}) - {existing_finding.id}: {existing_finding.title} "
            f"({existing_finding.component_name} - {existing_finding.component_version})"
        )
        # If all statuses are the same between findings, we can safely move on to the next
        # finding in the report. Return True here to force a continue in the loop
        if (
            existing_finding.false_p == unsaved_finding.false_p
            and existing_finding.out_of_scope == unsaved_finding.out_of_scope
            and existing_finding.risk_accepted == unsaved_finding.risk_accepted
        ):
            unchanged_items.append(existing_finding)
            return existing_finding, True
        # The finding was not an exact match, so we need to add more details about from the
        # new finding to the existing. Return False here to make process further
        return existing_finding, False

    def process_matched_mitigated_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
        user: Dojo_User,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> Tuple[Finding, bool]:
        """
        Determine how mitigated the existing and new findings really are. We need
        to cover circumstances where mitigation timestamps are different, and
        decide which one to honor
        """
        # if the reimported item has a mitigation time, we can compare
        scan_type = kwargs.get("scan_type")
        verified = kwargs.get("verified")
        if unsaved_finding.is_mitigated:
            # The new finding is already mitigated, so nothing to change on the
            # the existing finding
            unchanged_items.append(existing_finding)
            # Look closer at the mitigation timestamp
            if unsaved_finding.mitigated:
                logger.debug(f"item mitigated time: {unsaved_finding.mitigated.timestamp()}")
                logger.debug(f"finding mitigated time: {existing_finding.mitigated.timestamp()}")
                # Determine if the mitigation timestamp is the same between the new finding
                # and the existing finding. If they are, we do not need any further processing
                if unsaved_finding.mitigated.timestamp() == existing_finding.mitigated.timestamp():
                    logger.debug(
                        "New imported finding and already existing finding have the same mitigation "
                        "date, will skip as they are the same."
                    )
                    # Return True here to force the loop to continue
                    return existing_finding, True
                else:
                    logger.debug(
                        "New imported finding and already existing finding are both mitigated but "
                        "have different dates, not taking action"
                    )
                    # Return True here to force the loop to continue
                    return existing_finding, True
            else:
                # even if there is no mitigation time, skip it, because both the current finding and
                # the reimported finding are is_mitigated
                # Return True here to force the loop to continue
                return existing_finding, True
        else:
            if kwargs.get("do_not_reactivate"):
                logger.debug(
                    "Skipping reactivating by user's choice do_not_reactivate: "
                    f" - {existing_finding.id}: {existing_finding.title} "
                    f"({existing_finding.component_name} - {existing_finding.component_version})"
                )
                # Search for an existing note that this finding has been skipped for reactivation
                # before this current time
                existing_note = existing_finding.notes.filter(
                    entry=f"Finding has skipped reactivation from {scan_type} re-upload with user decision do_not_reactivate.",
                    author=user,
                )
                # If a note has not been left before, we can skip this finding
                if len(existing_note) == 0:
                    note = Notes(
                        entry=f"Finding has skipped reactivation from {scan_type} re-upload with user decision do_not_reactivate.",
                        author=user,
                    )
                    note.save()
                    existing_finding.notes.add(note)
                    existing_finding.save(dedupe_option=False)
                # Return True here to force the loop to continue
                return existing_finding, True
            else:
                logger.debug(
                    f"Reactivating:  - {existing_finding.id}: {existing_finding.title} "
                    f"({existing_finding.component_name} - {existing_finding.component_version})"
                )
                existing_finding.mitigated = None
                existing_finding.is_mitigated = False
                existing_finding.mitigated_by = None
                existing_finding.active = True
                if verified is not None:
                    existing_finding.verified = verified

        component_name = getattr(unsaved_finding, "component_name", None)
        component_version = getattr(unsaved_finding, "component_version", None)
        existing_finding.component_name = existing_finding.component_name or component_name
        existing_finding.component_version = existing_finding.component_version or component_version
        existing_finding.save(dedupe_option=False)
        # don't dedupe before endpoints are added
        existing_finding.save(dedupe_option=False)
        note = Notes(entry=f"Re-activated by {scan_type} re-upload.", author=user)
        note.save()
        endpoint_statuses = existing_finding.status_finding.exclude(
            Q(false_positive=True)
            | Q(out_of_scope=True)
            | Q(risk_accepted=True)
        )
        self.chunk_endpoints_and_reactivate(endpoint_statuses)
        existing_finding.notes.add(note)
        reactivated_items.append(existing_finding)
        # The new finding is active while the existing on is mitigated. The existing finding needs to
        # be updated in some way
        # Return False here to make sure further processing happens
        return existing_finding, False

    def process_matched_active_finding(
        self,
        unsaved_finding: Finding,
        existing_finding: Finding,
        user: Dojo_User,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> Tuple[Finding, bool]:
        """
        The existing finding must be active here, so we need to compare it
        closely with the new finding coming in and determine how to proceed
        """
        # if finding associated to new item is none of risk accepted, mitigated, false positive or out of scope
        # existing findings may be from before we had component_name/version fields
        logger.debug(
            f"Updating existing finding: {existing_finding.id}: {existing_finding.title} "
            f"({existing_finding.component_name} - {existing_finding.component_version})"
        )
        # First check that the existing finding is definitely not mitigated
        if not (existing_finding.mitigated and existing_finding.is_mitigated):
            verified = kwargs.get("verified")
            logger.debug("Reimported item matches a finding that is currently open.")
            if unsaved_finding.is_mitigated:
                logger.debug("Reimported mitigated item matches a finding that is currently open, closing.")
                # TODO: Implement a date comparison for opened defectdojo findings before closing them by reimporting,
                # as they could be force closed by the scanner but a DD user forces it open ?
                logger.debug(
                    f"Closing: {existing_finding.id}: {existing_finding.title} "
                    f"({existing_finding.component_name} - {existing_finding.component_version})"
                )
                existing_finding.mitigated = unsaved_finding.mitigated
                existing_finding.is_mitigated = True
                existing_finding.mitigated_by = unsaved_finding.mitigated_by
                existing_finding.active = False
                if verified is not None:
                    existing_finding.verified = verified
            elif unsaved_finding.risk_accepted or unsaved_finding.false_p or unsaved_finding.out_of_scope:
                logger.debug('Reimported mitigated item matches a finding that is currently open, closing.')
                logger.debug(
                    f"Closing: {existing_finding.id}: {existing_finding.title} "
                    f"({existing_finding.component_name} - {existing_finding.component_version})"
                )
                existing_finding.risk_accepted = unsaved_finding.risk_accepted
                existing_finding.false_p = unsaved_finding.false_p
                existing_finding.out_of_scope = unsaved_finding.out_of_scope
                existing_finding.active = False
                if verified is not None:
                    existing_finding.verified = verified
            else:
                # if finding is the same but list of affected was changed, finding is marked as unchanged. This is a known issue
                unchanged_items.append(existing_finding)
        # Set the component name and version on the existing finding if it is present
        # on the old finding, but not present on the existing finding (do not override)
        component_name = getattr(unsaved_finding, "component_name", None)
        component_version = getattr(unsaved_finding, "component_version", None)
        if (component_name is not None and not existing_finding.component_name) or (
            component_version is not None and not existing_finding.component_version
        ):
            existing_finding.component_name = existing_finding.component_name or component_name
            existing_finding.component_version = existing_finding.component_version or component_version
            existing_finding.save(dedupe_option=False)
        # Return False here to make sure further processing happens
        return existing_finding, False

    def process_finding_that_was_not_matched(
        self,
        unsaved_finding: Finding,
        user: Dojo_User,
        group_names_to_findings_dict: dict,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> Finding:
        """
        Create a new finding from the one parsed from the report
        """
        # Set some explicit settings
        unsaved_finding.reporter = user
        unsaved_finding.last_reviewed = timezone.now()
        unsaved_finding.last_reviewed_by = user
        # indicates an override. Otherwise, do not change the value of unsaved_finding.active
        if (active := kwargs.get("active")) is not None:
            unsaved_finding.active = active
        # indicates an override. Otherwise, do not change the value of verified
        if (verified := kwargs.get("verified")) is not None:
            unsaved_finding.verified = verified
        # scan_date was provided, override value from parser
        if (scan_date := kwargs.get("scan_date")) is not None:
            unsaved_finding.date = scan_date.date()
        # Save it. Don't dedupe before endpoints are added.
        unsaved_finding.save(dedupe_option=False)
        finding = unsaved_finding
        logger.debug(
            "Reimport created new finding as no existing finding match: "
            f"{finding.id}: {finding.title} "
            f"({finding.component_name} - {finding.component_version})"
        )
        # Manage the finding grouping selection
        self.process_finding_groups(
            unsaved_finding,
            kwargs.get("group_by"),
            group_names_to_findings_dict,
        )
        # Add the new finding to the list
        new_items.append(unsaved_finding)
        # Process any request/response pairs
        self.process_request_response_pairs(unsaved_finding)
        return unsaved_finding

    def finding_post_processing(
        self,
        finding: Finding,
        finding_from_report: Finding,
        test: Test,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> None:
        """
        Save all associated objects to the finding after it has been saved
        for the purpose of foreign key restrictions
        """
        self.chunk_endpoints_and_disperse(finding, test, finding_from_report.unsaved_endpoints)
        if endpoints_to_add := kwargs.get("endpoints_to_add"):
            self.chunk_endpoints_and_disperse(finding, test, endpoints_to_add)
        # Update finding tags
        if finding_from_report.unsaved_tags:
            finding.tags = finding_from_report.unsaved_tags
        # Process any files
        if finding_from_report.unsaved_files:
            finding.unsaved_files = finding_from_report.unsaved_files
        self.process_files(finding)
        # Process vulnerability IDs
        finding = self.process_vulnerability_ids(finding)

        return finding

    def process_groups_for_all_findings(
        self,
        group_names_to_findings_dict: dict,
        reactivated_items: List[Finding],
        unchanged_items: List[Finding],
        **kwargs: dict,
    ) -> None:
        """
        Add findings to a group that may or may not exist, based upon the users
        selection at import time
        """
        push_to_jira = kwargs.get("push_to_jira", False)
        for (group_name, findings) in group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(
                group_name,
                findings,
                **kwargs
            )
            if push_to_jira:
                if findings[0].finding_group is not None:
                    jira_helper.push_to_jira(findings[0].finding_group)
                else:
                    jira_helper.push_to_jira(findings[0])

        if is_finding_groups_enabled() and push_to_jira:
            for finding_group in {
                    finding.finding_group
                    for finding in reactivated_items + unchanged_items
                    if finding.finding_group is not None and not finding.is_mitigated
            }:
                jira_helper.push_to_jira(finding_group)

    def process_results(
        self,
        new_items: List[Finding],
        reactivated_items: List[Finding],
        to_mitigate: List[Finding],
        untouched: List[Finding],
        **kwargs: dict,
    ) -> Tuple[List[Finding], List[Finding], List[Finding], List[Finding]]:
        """
        Determine how to to return the results based on whether the process was
        ran asynchronous or not
        """
        if not kwargs.get("sync", False):
            serialized_new_items = [
                serialize("json", [finding]) for finding in new_items
            ]
            serialized_reactivated_items = [
                serialize("json", [finding]) for finding in reactivated_items
            ]
            serialized_to_mitigate = [
                serialize("json", [finding]) for finding in to_mitigate
            ]
            serialized_untouched = [
                serialize("json", [finding]) for finding in untouched
            ]
            return (
                serialized_new_items,
                serialized_reactivated_items,
                serialized_to_mitigate,
                serialized_untouched,
            )
        else:
            return new_items, reactivated_items, to_mitigate, untouched
