import base64
import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.db import IntegrityError
from django.urls import reverse
from django.utils.timezone import make_aware

import dojo.finding.helper as finding_helper
from dojo.importers.endpoint_manager import EndpointManager
from dojo.importers.options import ImporterOptions
from dojo.models import (
    # Import History States
    IMPORT_CLOSED_FINDING,
    IMPORT_CREATED_FINDING,
    IMPORT_REACTIVATED_FINDING,
    IMPORT_UNTOUCHED_FINDING,
    # Finding Severities
    SEVERITIES,
    BurpRawRequestResponse,
    Endpoint,
    FileUpload,
    Finding,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    Vulnerability_Id,
)
from dojo.notifications.helper import create_notification
from dojo.tools.factory import get_parser
from dojo.utils import max_safe

logger = logging.getLogger(__name__)


class Parser:

    """
    This class is used as an alias to a given parser
    and is purely for the sake of type hinting
    """

    def get_findings(scan_type: str, test: Test) -> list[Finding]:
        """
        Stub function to make the hinting happier. The actual class
        is loosely obligated to have this function defined.

        TODO This should be enforced in the future, but here is not the place
        TODO once this enforced, this stub class should be removed
        """


class BaseImporter(ImporterOptions):

    """
    A collection of utilities used by various importers within DefectDojo.
    Some of these commonalities may be fully used by children importers,
    or even extended
    """

    def __init__(
        self,
        *args: list,
        **kwargs: dict,
    ):
        """
        Initializing or constructing this parent class is prohibited
        and will raise a `NotImplemented` exception
        """
        ImporterOptions.__init__(self, *args, **kwargs)
        self.endpoint_manager = EndpointManager()

    def check_child_implementation_exception(self):
        """
        This is a helper function for a quick check to ensure that the methods of the
        BaseImporter are not being used directly
        """
        if isinstance(self, BaseImporter):
            msg = (
                "The BaseImporter class must not be used directly. "
                "Please use a class that extends the BaseImporter class."
            )
            raise NotImplementedError(msg)

    def process_scan(
        self,
        scan: TemporaryUploadedFile,
        *args: list,
        **kwargs: dict,
    ) -> tuple[Test, int, int, int, int, int, Test_Import]:
        """
        A helper method that executes the entire import process in a single method.
        This includes parsing the file, processing the findings, and returning the
        statistics from the import
        """
        self.check_child_implementation_exception()

    def process_findings(
        self,
        parsed_findings: list[Finding],
        **kwargs: dict,
    ) -> list[Finding]:
        """
        Make the conversion from unsaved Findings in memory to Findings that are saved in the
        database with and ID associated with them. This processor will also save any associated
        objects such as endpoints, vulnerability IDs, and request/response pairs
        """
        self.check_child_implementation_exception()

    def close_old_findings(
        self,
        findings: list[Finding],
        **kwargs: dict,
    ) -> list[Finding]:
        """
        Identify any findings that have been imported before,
        but are no longer present in later reports so that
        we can automatically close them as "implied mitigated"

        This function will vary by importer, so it is marked as
        abstract with a prohibitive exception raised if the
        method is attempted to to be used by the BaseImporter class
        """
        self.check_child_implementation_exception()

    def get_parser(self) -> Parser:
        """
        Returns the correct parser based on the the test type supplied. If a test type
        is supplied that does not have a parser created for it, an exception is raised
        from the factory `get_parser` function
        """
        return get_parser(self.scan_type)

    def process_scan_file(
        self,
        scan: TemporaryUploadedFile,
    ) -> TemporaryUploadedFile:
        """
        Make any preprocessing actions or changes on the report before submitting
        to the parser to generate findings from the file
        """
        return scan

    def parse_findings_static_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Finding]:
        """
        Parse the scan report submitted with the parser class and generate some findings
        that are not saved to the database yet. This step is crucial in determining if
        there are any errors in the parser before creating any new resources
        """
        # Ensure that a test is present when calling this method as there are cases where
        # the test will be created by this function in a child class
        if self.test is None or not isinstance(self.test, Test):
            msg = "A test must be supplied to parse the file"
            raise ValidationError(msg)
        try:
            return parser.get_findings(scan, self.test)
        except ValueError as e:
            logger.warning(e)
            raise ValidationError(e)

    def parse_dynamic_test_type_tests(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Test]:
        """Use the API configuration object to get the tests to be used by the parser"""
        try:
            return parser.get_tests(self.scan_type, scan)
        except ValueError as e:
            logger.warning(e)
            raise ValidationError(e)

    def parse_dynamic_test_type_findings_from_tests(
        self,
        tests: list[Test],
    ) -> list[Finding]:
        """
        Currently we only support import one Test
        so for parser that support multiple tests (like SARIF)
        we aggregate all the findings into one uniq test
        """
        parsed_findings = []
        for test_raw in tests:
            parsed_findings.extend(test_raw.findings)
        return parsed_findings

    def parse_findings_dynamic_test_type(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Finding]:
        """
        Use the API configuration object to get the tests to be used by the parser
        to dump findings into

        This version of this function is intended to be extended by children classes
        """
        tests = self.parse_dynamic_test_type_tests(scan, parser)
        return self.parse_dynamic_test_type_findings_from_tests(tests)

    def parse_findings(
        self,
        scan: TemporaryUploadedFile,
        parser: Parser,
    ) -> list[Finding]:
        """
        Determine how to parse the findings based on the presence of the
        `get_tests` function on the parser object

        This function will vary by importer, so it is marked as
        abstract with a prohibitive exception raised if the
        method is attempted to to be used by the BaseImporter class
        """
        self.check_child_implementation_exception()

    def sync_process_findings(
        self,
        parsed_findings: list[Finding],
        **kwargs: dict,
    ) -> tuple[list[Finding], list[Finding], list[Finding], list[Finding]]:
        """
        Processes findings in a synchronous manner such that all findings
        will be processed in a worker/process/thread
        """
        return self.process_findings(parsed_findings, sync=True, **kwargs)

    def determine_process_method(
        self,
        parsed_findings: list[Finding],
        **kwargs: dict,
    ) -> list[Finding]:
        return self.sync_process_findings(
            parsed_findings,
            **kwargs,
        )

    def determine_deduplication_algorithm(self) -> str:
        """
        Determines what dedupe algorithm to use for the Test being processed.
        :return: A string representing the dedupe algorithm to use.
        """
        return self.test.deduplication_algorithm

    def update_test_meta(self):
        """
        Update the test with some values stored in the kwargs dict. The common
        fields used today are `version`, `branch_tag`, `build_id`, and `commit_hash`
        """
        # Add the extra fields to the test if they are specified here
        if not self.version.isspace():
            self.test.version = self.version
        if not self.branch_tag.isspace():
            self.test.branch_tag = self.branch_tag
        if not self.build_id.isspace():
            self.test.build_id = self.build_id
        if not self.commit_hash.isspace():
            self.test.commit_hash = self.commit_hash

        return

    def update_timestamps(self):
        """
        Update the target end dates for tests as imports are occurring:
        - Import
          - Updates to the test target date are largely non impacting.
            However, there is a possibility that the engagement is a CI/CD
            engagement, so the target end should be updated
        - Reimport
          - Updates to the test target date are very important as we are
            constantly reusing the same test over and over
          - In the (likely) event the engagement is a CI/CD type, the target
            end date should be updated as well
        """
        # Update the target end of the engagement if it is a CI/CD engagement
        # If the supplied scan date is greater than the current configured
        # target end date on the engagement
        if self.test.engagement.engagement_type == "CI/CD":
            self.test.engagement.target_end = max_safe(
                [self.scan_date.date(), self.test.engagement.target_end],
            )
        # Set the target end date on the test in a similar fashion
        max_test_start_date = max_safe([self.scan_date, self.test.target_end])
        # Quick check to make sure we have a datetime that is timezone aware
        # so that we can suppress naive datetime warnings
        if not max_test_start_date.tzinfo:
            max_test_start_date = make_aware(max_test_start_date)
        self.test.target_end = max_test_start_date

    def update_test_tags(self):
        """
        Update the list of tags on the test if they are supplied
        at import time
        """
        # Make sure the list is not empty as we do not want to overwrite
        # any existing tags
        if self.tags is not None and len(self.tags) > 0:
            self.test.tags.set(self.tags)

    def update_import_history(
        self,
        new_findings: list[Finding] | None = None,
        closed_findings: list[Finding] | None = None,
        reactivated_findings: list[Finding] | None = None,
        untouched_findings: list[Finding] | None = None,
    ) -> Test_Import:
        """Creates a record of the import or reimport operation that has occurred."""
        # Quick fail check to determine if we even wanted this
        if untouched_findings is None:
            untouched_findings = []
        if reactivated_findings is None:
            reactivated_findings = []
        if closed_findings is None:
            closed_findings = []
        if new_findings is None:
            new_findings = []
        if settings.TRACK_IMPORT_HISTORY is False:
            return None
        # Log the current state of what has occurred in case there could be
        # deviation from what is displayed in the view
        logger.debug(
            f"new: {len(new_findings)} "
            f"closed: {len(closed_findings)} "
            f"reactivated: {len(reactivated_findings)} "
            f"untouched: {len(untouched_findings)} ",
        )
        # Create a dictionary to stuff into the test import object
        import_settings = {}
        import_settings["active"] = self.active
        import_settings["verified"] = self.verified
        import_settings["minimum_severity"] = self.minimum_severity
        import_settings["close_old_findings"] = self.close_old_findings_toggle
        import_settings["push_to_jira"] = self.push_to_jira
        import_settings["tags"] = self.tags
        # Add the list of endpoints that were added exclusively at import time
        if len(self.endpoints_to_add) > 0:
            import_settings["endpoints"] = [str(endpoint) for endpoint in self.endpoints_to_add]
        # Create the test import object
        test_import = Test_Import.objects.create(
            test=self.test,
            import_settings=import_settings,
            version=self.version,
            branch_tag=self.branch_tag,
            build_id=self.build_id,
            commit_hash=self.commit_hash,
            type=self.import_type,
        )

        # Create a history record for each finding
        for finding in closed_findings:
            self.create_import_history_record_safe(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_CLOSED_FINDING,
            ))
        for finding in new_findings:
            self.create_import_history_record_safe(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_CREATED_FINDING,
            ))
        for finding in reactivated_findings:
            self.create_import_history_record_safe(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_REACTIVATED_FINDING,
            ))
        for finding in untouched_findings:
            self.create_import_history_record_safe(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_UNTOUCHED_FINDING,
            ))

        # Add any tags to the findings imported if necessary
        if self.apply_tags_to_findings and self.tags:
            for finding in test_import.findings_affected.all():
                for tag in self.tags:
                    self.add_tags_safe(finding, tag)
        # Add any tags to any endpoints of the findings imported if necessary
        if self.apply_tags_to_endpoints and self.tags:
            for finding in test_import.findings_affected.all():
                for endpoint in finding.endpoints.all():
                    for tag in self.tags:
                        self.add_tags_safe(endpoint, tag)

        return test_import

    def create_import_history_record_safe(
        self,
        test_import_finding_action,
    ):
        """Creates an import history record, while catching any IntegrityErrors that might happen because of the background job having deleted a finding"""
        logger.debug(f"creating Test_Import_Finding_Action for finding: {test_import_finding_action.finding.id} action: {test_import_finding_action.action}")
        try:
            test_import_finding_action.save()
        except IntegrityError as e:
            # This try catch makes us look we don't know what we're doing, but in https://github.com/DefectDojo/django-DefectDojo/issues/6217 we decided that for now this is the best solution
            logger.warning("Error creating Test_Import_Finding_Action: %s", e)
            logger.debug("Error creating Test_Import_Finding_Action, finding marked as duplicate and deleted ?")

    def add_tags_safe(
        self,
        finding_or_endpoint,
        tag,
    ):
        """Adds tags to a finding or endpoint, while catching any IntegrityErrors that might happen because of the background job having deleted a finding"""
        if not isinstance(finding_or_endpoint, Finding) and not isinstance(finding_or_endpoint, Endpoint):
            msg = "finding_or_endpoint must be a Finding or Endpoint object"
            raise TypeError(msg)

        msg = "finding" if isinstance(finding_or_endpoint, Finding) else "endpoint" if isinstance(finding_or_endpoint, Endpoint) else "unknown"
        logger.debug(f" adding tag: {tag} to " + msg + f"{finding_or_endpoint.id}")

        try:
            finding_or_endpoint.tags.add(tag)
        except IntegrityError as e:
            # This try catch makes us look we don't know what we're doing, but in https://github.com/DefectDojo/django-DefectDojo/issues/6217 we decided that for now this is the best solution
            logger.warning("Error adding tag: %s", e)
            logger.debug("Error adding tag, finding marked as duplicate and deleted ?")

    def construct_imported_message(
        self,
        finding_count: int = 0,
        new_finding_count: int = 0,
        closed_finding_count: int = 0,
        reactivated_finding_count: int = 0,
        untouched_finding_count: int = 0,
    ) -> str:
        """
        Constructs a success message to be displayed on screen in the UI as a digest for the user.
        This digest includes counts for the findings in the following status:
        - Created: New findings that have not been created before
        - Closed: Findings that were not detected in the report any longer, so the original was closed
        - Reactivated: Findings that were once closed, but has reappeared in the report again
        - Untouched: Findings that have not changed between now, and the last import/reimport
        """
        # Only construct this message if there is any change in finding status
        if finding_count > 0:
            # Set the base message to indicate how many findings were parsed from the report
            message = f"{self.scan_type} processed a total of {finding_count} findings"
            if self.import_type == Test_Import.IMPORT_TYPE:
                # Check for close old findings context to determine if more detail should be added
                if self.close_old_findings_toggle:
                    message += f" and closed {closed_finding_count} findings"
            if self.import_type == Test_Import.REIMPORT_TYPE:
                # Add more details for any status changes recorded
                if new_finding_count:
                    message += f" created {new_finding_count} findings"
                if closed_finding_count:
                    message += f" closed {closed_finding_count} findings"
                if reactivated_finding_count:
                    message += f" reactivated {reactivated_finding_count} findings"
                if untouched_finding_count:
                    message += f" did not touch {untouched_finding_count} findings"
            # Drop a period at the end
            message += "."
        else:
            # Set the message to convey that all findings processed are identical to the last time an import/reimport occurred
            message = "No findings were added/updated/closed/reactivated as the findings in Defect Dojo are identical to those in the uploaded report."

        return message

    def update_test_progress(
        self,
        percentage_value: int = 100,
    ):
        """
        This function is added to the async queue at the end of all finding import tasks
        and after endpoint task, so this should only run after all the other ones are done.
        It's purpose is to update the percent completion of the test to 100 percent
        """
        self.test.percent_complete = percentage_value
        self.test.save()

    def get_or_create_test_type(
        self,
        test_type_name: str,
    ) -> Test_Type:
        """
        Ensures that a test type exists for a given test. This function can be called
        in the following circumstances:
        - Ensuring a test type exists for import
        - Ensuring a test type exists for reimport with auto-create context
        - Creating a new test type for dynamic test types such as generic and sarif
        """
        test_type, created = Test_Type.objects.get_or_create(name=test_type_name)
        if created:
            logger.info(f"Created new Test_Type with name {test_type.name} because a report is being imported")
            test_type.dynamically_generated = True
            test_type.save()
        return test_type

    def verify_tool_configuration_from_test(self):
        """
        Verify that the Tool_Configuration supplied along with the
        test is found on the product. If not, then raise a validation
        error that will bubble up back to the user

        if f there is a case where the Tool_Configuration supplied to
        this function does not match the one saved on the test, then
        we will user the one supplied rather than the one on the test.
        """
        # Do not bother with any of the verification if a Tool_Configuration is not supplied
        if self.api_scan_configuration is None:
            # Return early as there is no value in validating further
            return
        # Validate that the test has a value
        if self.test is not None:
            # Make sure the Tool_Configuration is connected to the product that the test is
            if self.api_scan_configuration.product != self.test.engagement.product:
                msg = "API Scan Configuration has to be from same product as the Test"
                raise ValidationError(msg)
            # If the Tool_Configuration on the test is not the same as the one supplied, then lets
            # use the one that is supplied
            if self.test.api_scan_configuration != self.api_scan_configuration:
                self.test.api_scan_configuration = self.api_scan_configuration
                self.test.save()

    def verify_tool_configuration_from_engagement(self):
        """
        Verify that the Tool_Configuration supplied along with the
        engagement is found on the product. If not, then raise a validation
        error that will bubble up back to the user

        if there is a case where the Tool_Configuration supplied to
        this function does not match the one saved on the engagement, then
        we will user the one supplied rather than the one on the engagement.
        """
        # Do not bother with any of the verification if a Tool_Configuration is not supplied
        if self.api_scan_configuration is None:
            # Return early as there is no value in validating further
            return
        # Validate that the engagement has a value
        if self.engagement is not None:
            # Make sure the Tool_Configuration is connected to the engagement that the test is
            if self.api_scan_configuration.product != self.engagement.product:
                msg = "API Scan Configuration has to be from same product as the Engagement"
                raise ValidationError(msg)

    def sanitize_severity(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Sanitization on the finding severity such that only the following
        severities may be set on the finding:
        - Critical, High, Medium, Low, Info
        There is a simple conversion process to convert any of the following
        to a value of Info
        - info, informational, Informational, None, none
        If not, raise a ValidationError explaining as such
        """
        # Checks around Informational/Info severity
        starts_with_info = finding.severity.lower().startswith("info")
        lower_none = finding.severity.lower() == "none"
        not_info = finding.severity != "Info"
        # Make the comparisons
        if not_info and (starts_with_info or lower_none):
            # Correct the severity
            finding.severity = "Info"
        # Ensure the final severity is one of the supported options
        if finding.severity not in SEVERITIES:
            msg = (
                f'Finding severity "{finding.severity}" is not supported. '
                f"Any of the following are supported: {SEVERITIES}."
            )
            raise ValidationError(msg)
        # Set the numerical severity on the finding based on the cleaned severity
        finding.numerical_severity = Finding.get_numerical_severity(finding.severity)
        # Return the finding if all else is good
        return finding

    def process_finding_groups(
        self,
        finding: Finding,
        group_names_to_findings_dict: dict,
    ) -> None:
        """
        Determines how to handle an incoming finding with respect to grouping
        if finding groups are enabled, use the supplied grouping mechanism to
        store a reference of how the finding should be grouped
        """
        if self.findings_groups_enabled and self.group_by:
            # If finding groups are enabled, group all findings by group name
            name = finding_helper.get_group_by_group_name(finding, self.group_by)
            if name is not None:
                if name in group_names_to_findings_dict:
                    group_names_to_findings_dict[name].append(finding)
                else:
                    group_names_to_findings_dict[name] = [finding]

    def process_request_response_pairs(
        self,
        finding: Finding,
    ) -> None:
        """
        Search the unsaved finding for the following attributes to determine
        if the data can be saved to the finding
        - unsaved_req_resp
        - unsaved_request
        - unsaved_response
        Create BurpRawRequestResponse objects linked to the finding without
        returning the finding afterward
        """
        if len(unsaved_req_resp := getattr(finding, "unsaved_req_resp", [])) > 0:
            for req_resp in unsaved_req_resp:
                burp_rr = BurpRawRequestResponse(
                    finding=finding,
                    burpRequestBase64=base64.b64encode(req_resp["req"].encode("utf-8")),
                    burpResponseBase64=base64.b64encode(req_resp["resp"].encode("utf-8")))
                burp_rr.clean()
                burp_rr.save()

        unsaved_request = getattr(finding, "unsaved_request", None)
        unsaved_response = getattr(finding, "unsaved_response", None)
        if unsaved_request is not None and unsaved_response is not None:
            burp_rr = BurpRawRequestResponse(
                finding=finding,
                burpRequestBase64=base64.b64encode(unsaved_request.encode()),
                burpResponseBase64=base64.b64encode(unsaved_response.encode()))
            burp_rr.clean()
            burp_rr.save()

    def process_endpoints(
        self,
        finding: Finding,
        endpoints_to_add: list[Endpoint],
    ) -> None:
        """
        Process any endpoints to add to the finding. Endpoints could come from two places
        - Directly from the report
        - Supplied by the user from the import form
        These endpoints will be processed in to endpoints objects and associated with the
        finding and and product
        """
        # Save the unsaved endpoints
        self.endpoint_manager.chunk_endpoints_and_disperse(finding, finding.unsaved_endpoints)
        # Check for any that were added in the form
        if len(endpoints_to_add) > 0:
            logger.debug("endpoints_to_add: %s", endpoints_to_add)
            self.endpoint_manager.chunk_endpoints_and_disperse(finding, endpoints_to_add)

    def process_vulnerability_ids(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Parse the `unsaved_vulnerability_ids` field from findings after they are parsed
        to create `Vulnerability_Id` objects with the finding associated correctly
        """
        # Synchronize the cve field with the unsaved_vulnerability_ids
        # We do this to be as flexible as possible to handle the fields until
        # the cve field is not needed anymore and can be removed.
        if finding.unsaved_vulnerability_ids and finding.cve:
            # Make sure the first entry of the list is the value of the cve field
            finding.unsaved_vulnerability_ids.insert(0, finding.cve)
        elif finding.unsaved_vulnerability_ids and not finding.cve:
            # If the cve field is not set, use the first entry of the list to set it
            finding.cve = finding.unsaved_vulnerability_ids[0]
        elif not finding.unsaved_vulnerability_ids and finding.cve:
            # If there is no list, make one with the value of the cve field
            finding.unsaved_vulnerability_ids = [finding.cve]

        if finding.unsaved_vulnerability_ids:
            # Remove old vulnerability ids - keeping this call only because of flake8
            Vulnerability_Id.objects.filter(finding=finding).delete()

            # user the helper function
            finding_helper.save_vulnerability_ids(finding, finding.unsaved_vulnerability_ids)

        return finding

    def process_files(
        self,
        finding: Finding,
    ) -> None:
        """
        Some parsers may supply files in the form of base64 encoded blobs,
        so lets save them in the form of an attached file on the finding
        object
        """
        if finding.unsaved_files:
            for unsaved_file in finding.unsaved_files:
                data = base64.b64decode(unsaved_file.get("data"))
                title = unsaved_file.get("title", "<No title>")
                file_upload, _ = FileUpload.objects.get_or_create(title=title)
                file_upload.file.save(title, ContentFile(data))
                file_upload.save()
                finding.files.add(file_upload)

    def mitigate_finding(
        self,
        finding: Finding,
        note_message: str,
        *,
        finding_groups_enabled: bool,
    ) -> None:
        """
        Mitigates a finding, all endpoint statuses, leaves a note on the finding
        with a record of what happened, and then saves the finding. Changes to
        this finding will also be synced with some ticket tracking system as well
        as groups
        """
        finding.active = False
        finding.is_mitigated = True
        if not finding.mitigated:
            finding.mitigated = self.scan_date
        finding.mitigated_by = self.user
        finding.notes.create(
            author=self.user,
            entry=note_message,
        )
        # Mitigate the endpoint statuses
        self.endpoint_manager.mitigate_endpoint_status(finding.status_finding.all(), self.user, kwuser=self.user, sync=True)
        # to avoid pushing a finding group multiple times, we push those outside of the loop
        if finding_groups_enabled and finding.finding_group:
            # don't try to dedupe findings that we are closing
            finding.save(dedupe_option=False)
        else:
            finding.save(dedupe_option=False, push_to_jira=self.push_to_jira)

    def notify_scan_added(
        self,
        test,
        updated_count,
        new_findings=None,
        findings_mitigated=None,
        findings_reactivated=None,
        findings_untouched=None,
    ):
        if findings_untouched is None:
            findings_untouched = []
        if findings_reactivated is None:
            findings_reactivated = []
        if findings_mitigated is None:
            findings_mitigated = []
        if new_findings is None:
            new_findings = []
        logger.debug("Scan added notifications")

        new_findings = sorted(new_findings, key=lambda x: x.numerical_severity)
        findings_mitigated = sorted(findings_mitigated, key=lambda x: x.numerical_severity)
        findings_reactivated = sorted(findings_reactivated, key=lambda x: x.numerical_severity)
        findings_untouched = sorted(findings_untouched, key=lambda x: x.numerical_severity)

        title = (
            f"Created/Updated {updated_count} findings for {test.engagement.product}: {test.engagement.name}: {test}"
        )

        create_notification(
            event="scan_added_empty" if updated_count == 0 else "scan_added",
            title=title,
            findings_new=new_findings,
            findings_mitigated=findings_mitigated,
            findings_reactivated=findings_reactivated,
            finding_count=updated_count,
            test=test,
            engagement=test.engagement,
            product=test.engagement.product,
            findings_untouched=findings_untouched,
            url=reverse("view_test", args=(test.id,)),
            url_api=reverse("test-detail", args=(test.id,)),
        )
