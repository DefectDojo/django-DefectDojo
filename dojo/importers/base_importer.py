import logging
from typing import List, Tuple
from abc import ABC, abstractmethod
from datetime import datetime

from django.core.files.uploadedfile import TemporaryUploadedFile
from django.utils.timezone import make_aware
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.exceptions import MultipleObjectsReturned
from django.urls import reverse

from dojo.decorators import dojo_async_task
from dojo.celery import app
from dojo.utils import max_safe
from dojo.endpoint.utils import endpoint_get_or_create
from dojo.tools.factory import get_parser
from dojo.models import (
    # models
    Engagement,
    Test_Type,
    Test,
    Finding,
    Endpoint,
    Endpoint_Status,
    Development_Environment,
    Dojo_User,
    Test_Import,
    Test_Import_Finding_Action,
    Vulnerability_Id,
    # Import History States
    IMPORT_CLOSED_FINDING,
    IMPORT_CREATED_FINDING,
    IMPORT_REACTIVATED_FINDING,
    IMPORT_UNTOUCHED_FINDING,
)


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


class BaseImporter(ABC):
    """
    A collection of utilities sed by various importers within DefectDojo.
    Some of these commonalities may be fully used by children importers,
    or even extended
    """
    def __init__(self, *args: list, **kwargs: dict):
        self.new_or_init(args, kwargs)

    def __new__(self, *args: list, **kwargs: dict):
        self.new_or_init(args, kwargs)

    def new_or_init(self, *args: list, **kwargs: dict):
        """
        Initializing or constructing this parent class is prohibited
        and will raise a `NotImplemented` exception
        """
        self.check_child_implementation_exception()

    def check_child_implementation_exception(self):
        """
        This is a helper function for a quick check to ensure that the methods of the
        BaseImporter are not being used directly
        """
        if isinstance(self, BaseImporter):
            raise NotImplementedError((
                "The Import class must not be used directly. "
                "Please use a class that extends the Import class."
            ))

    @abstractmethod
    def process_scan(
        self,
        scan: TemporaryUploadedFile,
        scan_type: str,
        engagement: Engagement = None,
        test: Test = None,
        user: Dojo_User = None,
        development_environment: Development_Environment = None,
        parsed_findings: List[Finding] = None,
        **kwargs: dict,
    ) -> Tuple[Test, int, int, int, int, int, Test_Import]:
        """
        TODO FILL ME IN PLEASE
        """
        self.check_child_implementation_exception()

    @abstractmethod
    def process_findings(
        self,
        test: Test,
        parsed_findings: List[Finding],
        user: Dojo_User,
        scan_type: str,
        **kwargs: dict,
    ) -> List[Finding]:
        """
        TODO FILL ME IN PLEASE
        """
        self.check_child_implementation_exception()

    @abstractmethod
    def close_old_findings(
        self,
        test: Test,
        findings: List[Finding],
        scan_date: datetime,
        user: Dojo_User,
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

    def parse_findings_from_file(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
        test: Test,
    ) -> List[Finding]:
        """
        Parse the scan report submitted with the parser class and generate some findings
        that are not saved to the database yet. This step is crucial in determining if
        there are any errors in the parser before creating any new resources
        """
        logger.debug(f"REIMPORT_SCAN: Parse findings from {scan_type}")
        try:
            return parser.get_findings(scan, test)
        except ValueError as e:
            logger.warning(e)
            raise ValidationError(e)

    def parse_findings_from_api_configuration(
        self,
        parser: Parser,
        scan_type: str,
        scan: TemporaryUploadedFile,
    ) -> List[Finding]:
        """
        Use the API configuration object to get the tests to be used by the parser
        to dump findings into

        This version of this function is intended to be extended by children classes
        """
        self.check_child_implementation_exception()
        logger.debug("REIMPORT_SCAN parser v2: Create parse findings")
        try:
            return parser.get_tests(scan_type, scan)
        except ValueError as e:
            logger.warning(e)
            raise ValidationError(e)

    def parse_findings(
        self,
        parser: Parser,
        scan_type: str,
        test: Test,
        scan: TemporaryUploadedFile,
    ) -> List[Finding]:
        """
        Determine how to parse the findings based on the presence of the
        `get_tests` function on the parser object
        """
        if hasattr(parser, 'get_tests'):
            return self.parse_findings_from_api_configuration(
                parser,
                scan_type,
                scan,
            )
        else:
            return self.parse_findings_from_file(
                parser,
                scan_type,
                scan,
                test,
            )

    def update_timestamps(
        self,
        test: Test,
        version: str = None,
        branch_tag: str = None,
        build_id: str = None,
        commit_hash: str = None,
        now: datetime = timezone.now(),
        scan_date: datetime = None
    ) -> None:
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
        if scan_date is not None:
            scan_date = now
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
        # Add the extra fields to the test if they are specified here
        if version is not None:
            test.version = version
        if branch_tag is not None:
            test.branch_tag = branch_tag
        if build_id is not None:
            test.build_id = build_id
        if commit_hash is not None:
            test.commit_hash = commit_hash
        # Save the test and engagement for changes to take affect
        test.save()
        test.engagement.save()

    def update_tags(
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
        endpoints_to_add: List[Endpoint | str],
        import_options: dict = {},
        new_findings: List[Finding] = [],
        closed_findings: List[Finding] = [],
        reactivated_findings: List[Finding] = [],
        untouched_findings: List[Finding] = [],
    ) -> Test_Import:
        """
        Creates a record of the import or reimport operation that has occurred. The `import_options` dict expects
        something along these lines:
        ```
        {
            active: True,
            verified: True,
            tags: ["value-one", "value-two"],
            minimum_severity: "Low",
            push_to_jira: False,
            close_old_findings: False,
            version: "some value",
            branch_tag: "some value",
            build_id: "some value",
            commit_hash: "some value",
        }
        ```
        This `import_options` dict will be split up into two sections of the import history:
        - Test options such as version, branch tag, build ID, and commit hash
        - Finding specific flags such as active/verified, push to jira, close old findings, and min severity
        """
        # Log the current state of what has occurred in case there could be
        # deviation from what is displayed in the view
        logger.debug((
            f"new: {len(new_findings)} "
            f"closed: {len(closed_findings)} "
            f"reactivated: {len(reactivated_findings)} "
            f"untouched: {len(untouched_findings)} "
        ))
        # Create a dictionary to stuff into the test import object
        import_settings = {}
        import_settings['active'] = import_options.get("active")
        import_settings['verified'] = import_options.get("verified")
        import_settings['minimum_severity'] = import_options.get("minimum_severity")
        import_settings['close_old_findings'] = import_options.get("close_old_findings")
        import_settings['push_to_jira'] = import_options.get("push_to_jira")
        import_settings['tags'] = import_options.get("tags")
        # Add the list of endpoints that were added exclusively at import time
        if endpoints_to_add:
            import_settings['endpoints'] = [str(endpoint) for endpoint in endpoints_to_add]
        # Create the test import object
        test_import = Test_Import.objects.create(
            test=test,
            import_settings=import_settings,
            version=import_options.get("version"),
            branch_tag=import_options.get("branch_tag"),
            build_id=import_options.get("build_id"),
            commit_hash=import_options.get("commit_hash"),
            type=type,
        )
        # Define all of the respective import finding actions for the test import object
        test_import_finding_action_list = []
        for finding in closed_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for closed finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_CLOSED_FINDING))
        for finding in new_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for created finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_CREATED_FINDING))
        for finding in reactivated_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for reactivated finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_REACTIVATED_FINDING))
        for finding in untouched_findings:
            logger.debug(f"preparing Test_Import_Finding_Action for untouched finding: {finding.id}")
            test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_UNTOUCHED_FINDING))
        # Bulk create all the defined objects
        Test_Import_Finding_Action.objects.bulk_create(test_import_finding_action_list)

        return test_import

    def construct_imported_message(
        self,
        scan_type: str,
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
            message = f"{scan_type} processed a total of {finding_count} findings"
            # Add more details for any status changes recorded
            if new_finding_count:
                message += f" created {new_finding_count} findings"
            if closed_finding_count:
                message += f" closed {closed_finding_count} findings"
            if reactivated_finding_count:
                message += f" reactivated {reactivated_finding_count} findings"
            if untouched_finding_count:
                message += f" did not touch {untouched_finding_count} findings"

            message += "."
        else:
            # Set the message to convey that all findings processed are identical to the last time an import/reimport occurred
            message = "No findings were added/updated/closed/reactivated as the findings in Defect Dojo are identical to those in the uploaded report."

        return message

    def handle_vulnerability_ids(
        self,
        finding: Finding
    ) -> None:
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
                Vulnerability_Id.objects.create(
                    vulnerability_id=vulnerability_id,
                    finding=finding,
                )

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
        chunk_list = [list[i:i + chunk_size] for i in range(0, len(list), chunk_size)]
        logger.debug('IMPORT_SCAN: Split endpoints into ' + str(len(chunk_list)) + ' chunks of ' + str(chunk_size))
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
        for endpoint in endpoints:
            try:
                endpoint.clean()
            except ValidationError as e:
                logger.warning(f"DefectDojo is storing broken endpoint because cleaning wasn't successful: {e}")
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
                raise Exception((
                    f"Endpoints in your database are broken. "
                    f"Please access {reverse('endpoint_migrate')} and migrate them to new format or remove them."
                ))

            Endpoint_Status.objects.get_or_create(
                finding=finding,
                endpoint=ep,
                defaults={'date': finding.date})

        logger.debug(f"IMPORT_SCAN: {len(endpoints)} imported")

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
