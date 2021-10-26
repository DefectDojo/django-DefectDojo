from django.conf import settings
from dojo.models import Engagement, Finding, Q, Product, Test
from django.utils import timezone
import logging
from dojo.utils import get_last_object_or_none, get_object_or_none


ENGAGEMENT_NAME_AUTO = 'Auto Created via API'
PRODUCT_TYPE_NAME_AUTO = '_Auto Created via API'


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

"""
Common code for reimporting from APIV2 or from the GUI
"""


def get_deduplication_algorithm_from_conf(scan_type):
    # Default algorithm
    deduplication_algorithm = 'legacy'
    # Check for an override for this scan_type in the deduplication configuration
    if hasattr(settings, 'DEDUPLICATION_ALGORITHM_PER_PARSER') and scan_type in settings.DEDUPLICATION_ALGORITHM_PER_PARSER:
        deduplication_algorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER[scan_type]
    return deduplication_algorithm


def match_new_finding_to_existing_finding(new_finding, test, deduplication_algorithm, scan_type):
    # This code should match the logic used for deduplication out of the re-import feature.
    # See utils.py deduplicate_* functions
    deduplicationLogger.debug('return findings bases on algorithm: %s', deduplication_algorithm)
    if deduplication_algorithm == 'hash_code':
        return Finding.objects.filter(
            test=test,
            hash_code=new_finding.hash_code).exclude(
                        hash_code=None).order_by('id')
    elif deduplication_algorithm == 'unique_id_from_tool':
        return Finding.objects.filter(
            test=test,
            unique_id_from_tool=new_finding.unique_id_from_tool).exclude(
                        unique_id_from_tool=None).order_by('id')
    elif deduplication_algorithm == 'unique_id_from_tool_or_hash_code':
        query = Finding.objects.filter(
            Q(test=test),
            (Q(hash_code__isnull=False) & Q(hash_code=new_finding.hash_code)) |
            (Q(unique_id_from_tool__isnull=False) & Q(unique_id_from_tool=new_finding.unique_id_from_tool))).order_by('id')
        deduplicationLogger.debug(query.query)
        return query
    elif deduplication_algorithm == 'legacy':
        # This is the legacy reimport behavior. Although it's pretty flawed and doesn't match the legacy algorithm for deduplication,
        # this is left as is for simplicity.
        # Re-writing the legacy deduplication here would be complicated and counter-productive.
        # If you have use cases going through this section, you're advised to create a deduplication configuration for your parser
        logger.debug("Legacy reimport. In case of issue, you're advised to create a deduplication configuration in order not to go through this section")
        return Finding.objects.filter(
                title=new_finding.title,
                test=test,
                severity=new_finding.severity,
                numerical_severity=Finding.get_numerical_severity(new_finding.severity)).order_by('id')
    else:
        logger.error("Internal error: unexpected deduplication_algorithm: '%s' ", deduplication_algorithm)
        return None


def update_endpoint_status(existing_finding, new_finding, user):
    # New endpoints are already added in serializers.py / views.py (see comment "# for existing findings: make sure endpoints are present or created")
    # So we only need to mitigate endpoints that are no longer present
    existing_finding_endpoint_status_list = existing_finding.endpoint_status.all()
    new_finding_endpoints_list = new_finding.unsaved_endpoints
    endpoint_status_to_mitigate = list(
        filter(
            lambda existing_finding_endpoint_status: existing_finding_endpoint_status.endpoint not in new_finding_endpoints_list,
            existing_finding_endpoint_status_list)
    )
    for endpoint_status in endpoint_status_to_mitigate:
        mitigate_endpoint_status(endpoint_status, user)


def mitigate_endpoint_status(endpoint_status, user):
    logger.debug("Re-import: mitigating endpoint %s that is no longer present", str(endpoint_status.endpoint))
    endpoint_status.mitigated_by = user
    endpoint_status.mitigated_time = timezone.now()
    endpoint_status.mitigated = True
    endpoint_status.last_modified = timezone.now()
    endpoint_status.save()


def get_import_meta_data_from_dict(data):
    test_id = data.get('test', None)
    if isinstance(test_id, Test):
        test_id = test_id.id
    scan_type = data.get('scan_type', None)

    test_title = data.get('test_title', None)
    engagement_id = data.get('engagement', None)
    if isinstance(engagement_id, Engagement):
        engagement_id = engagement_id.id
    engagement_name = data.get('engagement_name', None)
    product_id = data.get('product', None)
    product_name = data.get('product_name', None)

    return test_id, test_title, scan_type, engagement_id, engagement_name, product_id, product_name


def get_target_product_if_exists(product_id=None, product_name=None):
    if product_id:
        return get_object_or_none(Product, pk=product_id)
    elif product_name:
        return get_object_or_none(Product, name=product_name)
    else:
        return None


def get_target_engagement_if_exists(engagement_id=None, engagement_name=None, product=None):
    if engagement_id:
        engagement = get_object_or_none(Engagement, pk=engagement_id)
        logger.debug('Using existing engagement by id: %s', engagement_id)
        return engagement

    if not product:
        # if there's no product, then for sure there's no engagement either
        return None

    engagement = get_last_object_or_none(Engagement, product=product, name=engagement_name)
    return engagement


def get_target_test_if_exists(test_id=None, test_title=None, scan_type=None, engagement=None):
    if test_id:
        test = get_object_or_none(Test, pk=test_id)
        logger.debug('Using existing Test by id: %s', test_id)
        return test

    if not engagement:
        return None

    if test_title:
        return get_last_object_or_none(Test, engagement=engagement, title=test_title, scan_type=scan_type)

    return get_last_object_or_none(Test, engagement=engagement, scan_type=scan_type)
