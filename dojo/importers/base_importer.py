import base64
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Tuple

from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, ValidationError
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.urls import reverse
from django.utils import timezone
from django.utils.timezone import make_aware

import dojo.finding.helper as finding_helper
from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.endpoint.utils import endpoint_get_or_create
from dojo.importers.endpoint_manager import DefaultReImporterEndpointManager
from dojo.models import (
    # Import History States
    IMPORT_CLOSED_FINDING,
    IMPORT_CREATED_FINDING,
    IMPORT_REACTIVATED_FINDING,
    IMPORT_UNTOUCHED_FINDING,
    # Finding Severities
    SEVERITIES,
    BurpRawRequestResponse,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    # models
    Engagement,
    FileUpload,
    Finding,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    Tool_Configuration,
    Vulnerability_Id,
)
from dojo.tools.factory import get_parser
from dojo.utils import get_current_user, is_finding_groups_enabled, max_safe

logger = logging.getLogger(__name__)


class Parser:
    """
    This class is used as an alias to a given parser
    and is purely for the sake of type hinting
    """

    def get_findings(scan_type: str) -> List[Finding]:
        """
        Stub function to make the hinting happier. The actual class
        is loosely obligated to have this function defined.

        TODO This should be enforced in the future, but here is not the place
        TODO once this enforced, this stub class should be removed
        """
        pass


class BaseImporter(ABC, DefaultReImporterEndpointManager):
    """
    A collection of utilities used by various importers within DefectDojo.
    Some of these commonalities may be fully used by children importers,
    or even extended
    """
    def __init__(self, *args: list, **kwargs: dict):
        """
        Initializing or constructing this parent class is prohibited
        and will raise a `NotImplemented` exception
        """
        self.new_or_init(*args, **kwargs)

    def __new__(self, *args: list, **kwargs: dict):
        """
        Initializing or constructing this parent class is prohibited
        and will raise a `NotImplemented` exception
        """
        instance = super().__new__(self, *args, **kwargs)
        instance.new_or_init(*args, **kwargs)
        return instance

    def new_or_init(self, *args: list, **kwargs: dict):
        """
        Ensures that that the parent BaseImporter class is not
        instantiated directly
        """
        self.check_child_implementation_exception()

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

    @abstractmethod
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
        A helper method that executes the entire import process in a single method.
        This includes parsing the file, processing the findings, and returning the
        statistics from the import
        """
        self.check_child_implementation_exception()

    @abstractmethod
    @dojo_async_task
    @app.task(ignore_result=False)
    def process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Make the conversion from unsaved Findings in memory to Findings that are saved in the
        database with and ID associated with them. This processor will also save any associated
        objects such as endpoints, vulnerability IDs, and request/response pairs
        """
        self.check_child_implementation_exception()

    @abstractmethod
    def close_old_findings(
        self,
        test: Test,
        findings: List[Finding],
        user: Dojo_User,
        scan_date: datetime = timezone.now(),
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Identify any findings that have been imported before,
        but are no longer present in later reports so that
        we can automatically close them as "implied mitigated"

        This function will vary by importer, so it is marked as
        abstract with a prohibitive exception raised if the
        method is attempted to to be used by the BaseImporter class
        """
        self.check_child_implementation_exception()

    def get_parser(
        self,
        scan_type: str,
    ) -> Parser:
        """
        Returns the correct parser based on the the test type supplied. If a test type
        is supplied that does not have a parser created for it, an exception is raised
        from the factory `get_parser` function
        """
        return get_parser(scan_type)

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
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        test: Test = None,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Parse the scan report submitted with the parser class and generate some findings
        that are not saved to the database yet. This step is crucial in determining if
        there are any errors in the parser before creating any new resources
        """
        # Ensure that a test is present when calling this method as there are cases where
        # the test will be created by this function in a child class
        if test is None or not isinstance(test, Test):
            msg = "A test must be supplied to parse the file"
            raise ValidationError(msg)
        try:
            return parser.get_findings(scan, test)
        except ValueError as e:
            logger.warning(e)
            raise ValidationError(e)

    def parse_dynamic_test_type_tests(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        **kwargs: dict,
    ) -> List[Test]:
        """
        Use the API configuration object to get the tests to be used by the parser
        """
        try:
            return parser.get_tests(scan_type, scan)
        except ValueError as e:
            logger.warning(e)
            raise ValidationError(e)

    def parse_dynamic_test_type_findings_from_tests(
        self,
        tests: List[Test],
        **kwargs: dict,
    ) -> List[Finding]:
        """
        currently we only support import one Test
        so for parser that support multiple tests (like SARIF)
        we aggregate all the findings into one uniq test
        """
        parsed_findings = []
        for test_raw in tests:
            parsed_findings.extend(test_raw.findings)
        return parsed_findings

    def parse_findings_dynamic_test_type(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Use the API configuration object to get the tests to be used by the parser
        to dump findings into

        This version of this function is intended to be extended by children classes
        """
        tests = self.parse_dynamic_test_type_tests(
            parser,
            scan_type,
            scan,
            **kwargs,
        )
        return self.parse_dynamic_test_type_findings_from_tests(tests, **kwargs)

    def parse_findings(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        test: Test = None,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Determine how to parse the findings based on the presence of the
        `get_tests` function on the parser object
        """
        if hasattr(parser, 'get_tests'):
            return self.parse_findings_dynamic_test_type(
                parser,
                scan_type,
                scan,
                **kwargs,
            )
        else:
            return self.parse_findings_static_test_type(
                parser,
                scan_type,
                scan,
                test=test,
                **kwargs,
            )

    def determine_process_method(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        Determines whether to process the scan iteratively, or in chunks,
        based upon the ASYNC_FINDING_IMPORT setting
        """
        if settings.ASYNC_FINDING_IMPORT:
            return self.async_process_findings(
                test,
                parsed_findings,
                user,
                **kwargs,
            )
        else:
            return self.sync_process_findings(
                test,
                parsed_findings,
                user,
                **kwargs,
            )

    def update_test_meta(
        self,
        test: Test,
        **kwargs: dict,
    ) -> Test:
        """
        Update the test with some values stored in the kwargs dict. The common
        fields used today are `version`, `branch_tag`, `build_id`, and `commit_hash`
        """
        # Add the extra fields to the test if they are specified here
        if (version := kwargs.get("version", None)) is not None:
            test.version = version
        if (branch_tag := kwargs.get("branch_tag", None)) is not None:
            test.branch_tag = branch_tag
        if (build_id := kwargs.get("build_id", None)) is not None:
            test.build_id = build_id
        if (commit_hash := kwargs.get("commit_hash", None)) is not None:
            test.commit_hash = commit_hash

        return test

    def update_timestamps(
        self,
        test: Test,
        **kwargs: dict,
    ) -> Test:
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
        # Make sure there is at least something in the scan date field
        scan_date = kwargs.get("scan_date")
        if scan_date is None:
            scan_date = kwargs.get("now")
        # Update the target end of the engagement if it is a CI/CD engagement
        # If the supplied scan date is greater than the current configured
        # target end date on the engagement
        if test.engagement.engagement_type == 'CI/CD':
            test.engagement.target_end = max_safe([scan_date.date(), test.engagement.target_end])
        # Set the target end date on the test in a similar fashion
        max_test_start_date = max_safe([scan_date, test.target_end])
        # Quick check to make sure we have a datetime that is timezone aware
        # so that we can suppress naive datetime warnings
        if not max_test_start_date.tzinfo:
            max_test_start_date = make_aware(max_test_start_date)
        test.target_end = max_test_start_date

        return test

    def update_test_tags(
        self,
        test: Test,
        tags: List[str],
    ) -> None:
        """
        Update the list of tags on the test if they are supplied
        at import time
        """
        # Make sure the list is not empty as we do not want to overwrite
        # any existing tags
        if tags is not None and len(tags) > 0:
            test.tags = tags
        # Save the test for changes to be applied
        # TODO this may be a redundant save, and may be able to be pruned
        test.save()

    def update_import_history(
        self,
        type: str,
        test: Test,
        new_findings: List[Finding] = [],
        closed_findings: List[Finding] = [],
        reactivated_findings: List[Finding] = [],
        untouched_findings: List[Finding] = [],
        **kwargs: dict,
    ) -> Test_Import:
        """
        Creates a record of the import or reimport operation that has occurred.
        """
        # Quick fail check to determine if we even wanted this
        if settings.TRACK_IMPORT_HISTORY is False:
            return None
        # Log the current state of what has occurred in case there could be
        # deviation from what is displayed in the view
        logger.debug(
            f"new: {len(new_findings)} "
            f"closed: {len(closed_findings)} "
            f"reactivated: {len(reactivated_findings)} "
            f"untouched: {len(untouched_findings)} "
        )
        # Create a dictionary to stuff into the test import object
        import_settings = {}
        import_settings['active'] = kwargs.get("active")
        import_settings['verified'] = kwargs.get("verified")
        import_settings['minimum_severity'] = kwargs.get("minimum_severity")
        import_settings['close_old_findings'] = kwargs.get("close_old_findings")
        import_settings['push_to_jira'] = kwargs.get("push_to_jira")
        import_settings['tags'] = kwargs.get("tags")
        # Add the list of endpoints that were added exclusively at import time
        if (endpoints_to_add := kwargs.get("endpoints_to_add")) and len(endpoints_to_add) > 0:
            import_settings['endpoints'] = [str(endpoint) for endpoint in endpoints_to_add]
        # Create the test import object
        test_import = Test_Import.objects.create(
            test=test,
            import_settings=import_settings,
            version=kwargs.get("version"),
            branch_tag=kwargs.get("branch_tag"),
            build_id=kwargs.get("build_id"),
            commit_hash=kwargs.get("commit_hash"),
            type=type,
        )
        # Define all of the respective import finding actions for the test import object
        test_import_finding_action_list = []
        for finding in closed_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for closed finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_CLOSED_FINDING,
            ))
        for finding in new_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for created finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_CREATED_FINDING,
            ))
        for finding in reactivated_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for reactivated finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_REACTIVATED_FINDING,
            ))
        for finding in untouched_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for untouched finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(
                test_import=test_import,
                finding=finding,
                action=IMPORT_UNTOUCHED_FINDING,
            ))
        # Bulk create all the defined objects
        Test_Import_Finding_Action.objects.bulk_create(test_import_finding_action_list)
        # Add any tags to the findings imported if necessary
        if kwargs.get("apply_tags_to_findings", False) and (tags := kwargs.get("tags")):
            for finding in test_import.findings_affected.all():
                for tag in tags:
                    finding.tags.add(tag)
        # Add any tags to any endpoints of the findings imported if necessary
        if kwargs.get("apply_tags_to_endpoints", False) and (tags := kwargs.get("tags")):
            for finding in test_import.findings_affected.all():
                for endpoint in finding.endpoints.all():
                    for tag in tags:
                        endpoint.tags.add(tag)

        return test_import

    def construct_imported_message(
        self,
        scan_type: str,
        import_type: str,
        finding_count: int = 0,
        new_finding_count: int = 0,
        closed_finding_count: int = 0,
        reactivated_finding_count: int = 0,
        untouched_finding_count: int = 0,
        **kwargs: dict,
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
            message = f"{scan_type} processed a total of {finding_count} findings"
            if import_type == Test_Import.IMPORT_TYPE:
                # Check for close old findings context to determine if more detail should be added
                if kwargs.get("close_old_findings", False):
                    message += f" and closed {closed_finding_count} findings"
            if import_type == Test_Import.REIMPORT_TYPE:
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

    def chunk_objects(
        self,
        object_list: List[Finding | Endpoint],
        chunk_size: int = settings.ASYNC_FINDING_IMPORT_CHUNK_SIZE,
    ) -> List[List[Finding | Endpoint]]:
        """
        Split a single large list into a list of lists of size `chunk_size`.
        For Example
        ```
        >>> chunk_objects([A, B, C, D, E], 2)
        >>> [[A, B], [B, C], [E]]
        ```
        """
        # Break the list of parsed findings into "chunk_size" lists
        chunk_list = [object_list[i:i + chunk_size] for i in range(0, len(object_list), chunk_size)]
        logger.debug(f"IMPORT_SCAN: Split endpoints/findings into {len(chunk_list)} chunks of {chunk_size}")
        return chunk_list

    def chunk_endpoints_and_disperse(
        self,
        finding: Finding,
        test: Test,
        endpoints: List[Endpoint],
        **kwargs: dict,
    ) -> None:
        """
        Determines whether to asynchronously process endpoints on a finding or not. if so,
        chunk up the findings to be dispersed into individual celery workers. Otherwise,
        only use one worker
        """
        if settings.ASYNC_FINDING_IMPORT:
            chunked_list = self.chunk_objects(endpoints)
            # If there is only one chunk, then do not bother with async
            if len(chunked_list) < 2:
                self.add_endpoints_to_unsaved_finding(finding, test, endpoints, sync=True)
                return []
            # First kick off all the workers
            for endpoints_list in chunked_list:
                self.add_endpoints_to_unsaved_finding(finding, test, endpoints_list, sync=False)
        else:
            # Do not run this asynchronously or chunk the endpoints
            self.add_endpoints_to_unsaved_finding(finding, test, endpoints, sync=True)
        return None

    def clean_unsaved_endpoints(
        self,
        endpoints: List[Endpoint]
    ) -> None:
        """
        Clean endpoints that are supplied. For any endpoints that fail this validation
        process, raise a message that broken endpoints are being stored
        """
        for endpoint in endpoints:
            try:
                endpoint.clean()
            except ValidationError as e:
                logger.warning(f"DefectDojo is storing broken endpoint because cleaning wasn't successful: {e}")
        return None

    @dojo_async_task
    @app.task()
    def add_endpoints_to_unsaved_finding(
        self,
        finding: Finding,
        test: Test,
        endpoints: List[Endpoint],
        **kwargs: dict,
    ) -> None:
        """
        Creates Endpoint objects for a single finding and creates the link via the endpoint status
        """
        logger.debug(f"IMPORT_SCAN: Adding {len(endpoints)} endpoints to finding: {finding}")
        self.clean_unsaved_endpoints(endpoints)
        for endpoint in endpoints:
            ep = None
            try:
                ep, _ = endpoint_get_or_create(
                    protocol=endpoint.protocol,
                    userinfo=endpoint.userinfo,
                    host=endpoint.host,
                    port=endpoint.port,
                    path=endpoint.path,
                    query=endpoint.query,
                    fragment=endpoint.fragment,
                    product=test.engagement.product)
            except (MultipleObjectsReturned):
                msg = (
                    f"Endpoints in your database are broken. "
                    f"Please access {reverse('endpoint_migrate')} and migrate them to new format or remove them."
                )
                raise Exception(msg)

            Endpoint_Status.objects.get_or_create(
                finding=finding,
                endpoint=ep,
                defaults={'date': finding.date})
        logger.debug(f"IMPORT_SCAN: {len(endpoints)} imported")
        return None

    @dojo_async_task
    @app.task()
    def update_test_progress(
        self,
        test: Test,
        **kwargs: dict,
    ) -> None:
        """
        This function is added to the async queue at the end of all finding import tasks
        and after endpoint task, so this should only run after all the other ones are done.
        It's purpose is to update the percent completion of the test to 100 percent
        """
        test.percent_complete = 100
        test.save()
        return None

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
        return test_type

    def add_timezone_scan_date_and_now(
        self,
        scan_date: datetime = None,
        now: datetime = timezone.now(),
    ) -> Tuple[datetime, datetime]:
        """
        Add timezone information the scan date set at import time. In the event the
        scan date is not supplied, fall back on the current time so that the test
        can have a time for the target start and end
        """
        # Add timezone information to the scan date if it is not already present
        if scan_date is not None and not scan_date.tzinfo:
            scan_date = timezone.make_aware(scan_date)
        # Add timezone information to the current time if it is not already present
        if now is None:
            now = timezone.now()
        elif not now.tzinfo:
            now = timezone.make_aware(now)

        return scan_date, now

    def get_user_if_supplied(
        self,
        user: Dojo_User = None,
    ) -> Dojo_User:
        """
        Determines whether the user supplied at import time should
        be used or not. If the user supplied is not actually a user,
        the current authorized user will be fetched instead
        """
        if user is None:
            return get_current_user()
        return user

    def verify_tool_configuration_from_test(
        self,
        api_scan_configuration: Tool_Configuration,
        test: Test,
    ) -> Test:
        """
        Verify that the Tool_Configuration supplied along with the
        test is found on the product. If not, then raise a validation
        error that will bubble up back to the user

        if f there is a case where the Tool_Configuration supplied to
        this function does not match the one saved on the test, then
        we will user the one supplied rather than the one on the test.
        """
        # Do not bother with any of the verification if a Tool_Configuration is not supplied
        if api_scan_configuration is None:
            # Return early as there is no value in validating further
            return test
        # Ensure that a test was supplied
        elif not isinstance(test, Test):
            msg = "A test must be supplied to verify the Tool_Configuration against"
            raise ValidationError(msg)
        # Validate that the test has a value
        elif test is not None:
            # Make sure the Tool_Configuration is connected to the product that the test is
            if api_scan_configuration.product != test.engagement.product:
                msg = "API Scan Configuration has to be from same product as the Test"
                raise ValidationError(msg)
            # If the Tool_Configuration on the test is not the same as the one supplied, then lets
            # use the one that is supplied
            if test.api_scan_configuration != api_scan_configuration:
                test.api_scan_configuration = api_scan_configuration
                test.save()
            # Return the test here for an early exit
            return test

    def verify_tool_configuration_from_engagement(
        self,
        api_scan_configuration: Tool_Configuration,
        engagement: Engagement,
    ) -> Test | Engagement:
        """
        Verify that the Tool_Configuration supplied along with the
        engagement is found on the product. If not, then raise a validation
        error that will bubble up back to the user

        if there is a case where the Tool_Configuration supplied to
        this function does not match the one saved on the engagement, then
        we will user the one supplied rather than the one on the engagement.
        """
        # Do not bother with any of the verification if a Tool_Configuration is not supplied
        if api_scan_configuration is None:
            # Return early as there is no value in validating further
            return engagement
        # Ensure that an engagement was supplied
        elif not isinstance(engagement, Engagement):
            msg = "An engagement must be supplied to verify the Tool_Configuration against"
            raise ValidationError(msg)
        # Validate that the engagement has a value
        elif engagement is not None and isinstance(engagement, Engagement):
            # Make sure the Tool_Configuration is connected to the engagement that the test is
            if api_scan_configuration.product != engagement.product:
                msg = "API Scan Configuration has to be from same product as the Engagement"
                raise ValidationError(msg)
            # Return the test here for an early exit
            return engagement

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
        starts_with_info = finding.severity.lower().startswith('info')
        lower_none = finding.severity.lower() == 'none'
        not_info = finding.severity != 'Info'
        # Make the comparisons
        if not_info and (starts_with_info or lower_none):
            # Correct the severity
            finding.severity = 'Info'
        # Ensure the final severity is one of the supported options
        if finding.severity not in SEVERITIES:
            msg = (
                f"Finding severity \"{finding.severity}\" is not supported. "
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
        group_by: str,
        group_names_to_findings_dict: dict,
    ) -> None:
        """
        Determines how to handle an incoming finding with respect to grouping
        if finding groups are enabled, use the supplied grouping mechanism to
        store a reference of how the finding should be grouped
        """
        if is_finding_groups_enabled() and group_by:
            # If finding groups are enabled, group all findings by group name
            name = finding_helper.get_group_by_group_name(finding, group_by)
            if name is not None:
                if name in group_names_to_findings_dict:
                    group_names_to_findings_dict[name].append(finding)
                else:
                    group_names_to_findings_dict[name] = [finding]

    def process_request_response_pairs(
        self,
        finding: Finding
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
        if len(unsaved_req_resp := getattr(finding, 'unsaved_req_resp', [])) > 0:
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
        endpoints_to_add: List[Endpoint],
    ) -> None:
        """
        Process any endpoints to add to the finding. Endpoints could come from two places
        - Directly from the report
        - Supplied by the user from the import form
        These endpoints will be processed in to endpoints objects and associated with the
        finding and and product
        """
        # Save the unsaved endpoints
        self.chunk_endpoints_and_disperse(finding, finding.test, finding.unsaved_endpoints)
        # Check for any that were added in the form
        if len(endpoints_to_add) > 0:
            logger.debug('endpoints_to_add: %s', endpoints_to_add)
            self.chunk_endpoints_and_disperse(finding, finding.test, endpoints_to_add)

    def process_vulnerability_ids(
        self,
        finding: Finding
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
            # Remove duplicates
            finding.unsaved_vulnerability_ids = list(dict.fromkeys(finding.unsaved_vulnerability_ids))
            # Add all vulnerability ids to the database
            for vulnerability_id in finding.unsaved_vulnerability_ids:
                Vulnerability_Id(
                    vulnerability_id=vulnerability_id,
                    finding=finding,
                ).save()

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
                data = base64.b64decode(unsaved_file.get('data'))
                title = unsaved_file.get('title', '<No title>')
                file_upload, _ = FileUpload.objects.get_or_create(title=title)
                file_upload.file.save(title, ContentFile(data))
                file_upload.save()
                finding.files.add(file_upload)

    def mitigate_finding(
        self,
        finding: Finding,
        user: Dojo_User,
        scan_date: datetime,
        note_message: str,
        finding_groups_enabled: bool,
        push_to_jira: bool,
    ) -> None:
        """
        Mitigates a finding, all endpoint statuses, leaves a note on the finding
        with a record of what happened, and then saves the finding. Changes to
        this finding will also be synced with some ticket tracking system as well
        as groups
        """
        finding.active = False
        finding.is_mitigated = True
        finding.mitigated = scan_date
        finding.mitigated_by = user
        finding.notes.create(
            author=user,
            entry=note_message,
        )
        # Mitigate the endpoint statuses
        self.mitigate_endpoint_status(finding.status_finding.all(), user, kwuser=user, sync=True)
        # to avoid pushing a finding group multiple times, we push those outside of the loop
        if finding_groups_enabled and finding.finding_group:
            # don't try to dedupe findings that we are closing
            finding.save(dedupe_option=False)
        else:
            finding.save(dedupe_option=False, push_to_jira=push_to_jira)
