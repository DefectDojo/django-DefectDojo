from django.core.exceptions import ValidationError
from django.core.exceptions import MultipleObjectsReturned
from django.conf import settings
from dojo.decorators import dojo_async_task
from dojo.celery import app
from dojo.endpoint.utils import endpoint_get_or_create
from dojo.utils import max_safe
from dojo.models import IMPORT_CLOSED_FINDING, IMPORT_CREATED_FINDING, \
    IMPORT_REACTIVATED_FINDING, IMPORT_UNTOUCHED_FINDING, Test_Import, Test_Import_Finding_Action, \
    Endpoint_Status, Vulnerability_Id
import logging


logger = logging.getLogger(__name__)


def update_timestamps(test, version, branch_tag, build_id, commit_hash, now, scan_date):
    if not scan_date:
        scan_date = now

    if test.engagement.engagement_type == 'CI/CD':
        test.engagement.target_end = max_safe([scan_date.date(), test.engagement.target_end])

    test.target_end = max_safe([scan_date, test.target_end])

    if version:
        test.version = version

    if branch_tag:
        test.branch_tag = branch_tag
        test.engagement.version = version

    if build_id:
        test.build_id = build_id

    if branch_tag:
        test.commit_hash = commit_hash

    test.save()
    test.engagement.save()


def update_import_history(type, active, verified, tags, minimum_severity, endpoints_to_add, version, branch_tag,
                            build_id, commit_hash, push_to_jira, close_old_findings, test,
                            new_findings=[], closed_findings=[], reactivated_findings=[], untouched_findings=[]):
    logger.debug("new: %d closed: %d reactivated: %d untouched: %d", len(new_findings), len(closed_findings), len(reactivated_findings), len(untouched_findings))
    # json field
    import_settings = {}
    import_settings['active'] = active
    import_settings['verified'] = verified
    import_settings['minimum_severity'] = minimum_severity
    import_settings['close_old_findings'] = close_old_findings
    import_settings['push_to_jira'] = push_to_jira
    import_settings['tags'] = tags

    # tags=tags TODO no tags field in api for reimport it seems
    if endpoints_to_add:
        import_settings['endpoints'] = [str(endpoint) for endpoint in endpoints_to_add]

    test_import = Test_Import(test=test, import_settings=import_settings, version=version, branch_tag=branch_tag, build_id=build_id, commit_hash=commit_hash, type=type)
    test_import.save()

    test_import_finding_action_list = []
    for finding in closed_findings:
        logger.debug('preparing Test_Import_Finding_Action for closed finding: %i', finding.id)
        test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_CLOSED_FINDING))
    for finding in new_findings:
        logger.debug('preparing Test_Import_Finding_Action for created finding: %i', finding.id)
        test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_CREATED_FINDING))
    for finding in reactivated_findings:
        logger.debug('preparing Test_Import_Finding_Action for reactivated finding: %i', finding.id)
        test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_REACTIVATED_FINDING))
    for finding in untouched_findings:
        logger.debug('preparing Test_Import_Finding_Action for untouched finding: %i', finding.id)
        test_import_finding_action_list.append(Test_Import_Finding_Action(test_import=test_import, finding=finding, action=IMPORT_UNTOUCHED_FINDING))

    Test_Import_Finding_Action.objects.bulk_create(test_import_finding_action_list)

    return test_import


def construct_imported_message(scan_type, finding_count=0, new_finding_count=0, closed_finding_count=0, reactivated_finding_count=0, untouched_finding_count=0):
    if finding_count:
        message = f'{scan_type} processed a total of {finding_count} findings'

        if new_finding_count:
            message = message + ' created %d findings' % (new_finding_count)
        if closed_finding_count:
            message = message + ' closed %d findings' % (closed_finding_count)
        if reactivated_finding_count:
            message = message + ' reactivated %d findings' % (reactivated_finding_count)
        if untouched_finding_count:
            message = message + ' did not touch %d findings' % (untouched_finding_count)

        message = message + "."
    else:
        message = 'No findings were added/updated/closed/reactivated as the findings in Defect Dojo are identical to those in the uploaded report.'

    return message


def chunk_list(list):
    chunk_size = settings.ASYNC_FINDING_IMPORT_CHUNK_SIZE
    # Break the list of parsed findings into "chunk_size" lists
    chunk_list = [list[i:i + chunk_size] for i in range(0, len(list), chunk_size)]
    logger.debug('IMPORT_SCAN: Split endpoints into ' + str(len(chunk_list)) + ' chunks of ' + str(chunk_size))
    return chunk_list


def chunk_endpoints_and_disperse(finding, test, endpoints, **kwargs):
    chunked_list = chunk_list(endpoints)
    # If there is only one chunk, then do not bother with async
    if len(chunked_list) < 2:
        add_endpoints_to_unsaved_finding(finding, test, endpoints, sync=True)
        return []
    # First kick off all the workers
    for endpoints_list in chunked_list:
        add_endpoints_to_unsaved_finding(finding, test, endpoints_list, sync=False)


# Since adding a model to a ManyToMany relationship does not require an additional
# save, there is no need to keep track of when the task finishes.
@dojo_async_task
@app.task()
def add_endpoints_to_unsaved_finding(finding, test, endpoints, **kwargs):
    logger.debug('IMPORT_SCAN: Adding ' + str(len(endpoints)) + ' endpoints to finding:' + str(finding))
    for endpoint in endpoints:
        try:
            endpoint.clean()
        except ValidationError as e:
            logger.warning("DefectDojo is storing broken endpoint because cleaning wasn't successful: "
                            "{}".format(e))
        ep = None
        try:
            ep, created = endpoint_get_or_create(
                protocol=endpoint.protocol,
                userinfo=endpoint.userinfo,
                host=endpoint.host,
                port=endpoint.port,
                path=endpoint.path,
                query=endpoint.query,
                fragment=endpoint.fragment,
                product=test.engagement.product)
        except (MultipleObjectsReturned):
            raise Exception("Endpoints in your database are broken. Please access {} and migrate them to new format or "
                            "remove them.".format(reverse('endpoint_migrate')))

        eps, created = Endpoint_Status.objects.get_or_create(
            finding=finding,
            endpoint=ep,
            defaults={'date': finding.date})

    logger.debug('IMPORT_SCAN: ' + str(len(endpoints)) + ' imported')


# This function is added to the async queue at the end of all finding import tasks
# and after endpoint task, so this should only run after all the other ones are done
@dojo_async_task
@app.task()
def update_test_progress(test, **kwargs):
    test.percent_complete = 100
    test.save()


def handle_vulnerability_ids(finding):
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
