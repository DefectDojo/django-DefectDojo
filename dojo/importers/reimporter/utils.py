from datetime import timedelta
from django.conf import settings
from django.shortcuts import get_object_or_404
from dojo.models import Engagement, Finding, Q, Product, Product_Type
from django.utils import timezone
import logging
from dojo.utils import get_object_or_none


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
    engagement_id = data.get('engagement', None)
    engagement_name = data.get('engagement_name', None)
    product_id = data.get('product', None)
    product_name = data.get('product_name', None)
    product_type_id = data.get('product_type', None)
    product_type_name = data.get('product_type_name', None)
    return engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name


def validate_import_metadata(data):
    engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name = get_import_meta_data_from_dict(data)
    if engagement_id:
        return None
    elif product_id or product_name:
        return None
    elif (product_type_id or product_type_name) and product_name:
        return None
    return 'engagement or product/product_name needed or product_type_id/name and product_name needed'


def auto_create_engagement(engagement_name, product):
    # TODO VS: Set lead as current user?
    engagement, _ = Engagement.objects.get_or_create(name=engagement_name, product=product, target_start=timezone.now(), target_end=timezone.now() + timedelta(days=365))
    return engagement


# TODO VS: change 404 into none
def auto_create_product(engagement_id=None, engagement_name=None, product_id=None, product_name=None, product_type_id=None, product_type_name=None):
    product_type = get_target_product_type_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)
    if not product_type:
        product_type, created = Product_Type.objects.get_or_create(name=PRODUCT_TYPE_NAME_AUTO)
        if created:
            logger.info('Created new product_type %i:%s', product_type.id, product_type.name)

    product, _ = Product.objects.get_or_create(name=product_name, prod_type=product_type)
    return product


def get_target_product_type_if_exists(engagement_id=None, engagement_name=None, product_id=None, product_name=None, product_type_id=None, product_type_name=None):
    if product_type_id:
        logger.debug('looking up product_type by id %s', product_type_id)
        return get_object_or_404(Product_Type, pk=product_type_id)
    elif product_type_name:
        logger.debug('looking up product_type by name %s', product_type_name)
        return get_object_or_404(Product_Type, name=product_type_name)
    else:
        return None


def get_target_product_if_exists(engagement_id=None, engagement_name=None, product_id=None, product_name=None, product_type_id=None, product_type_name=None):
    if product_id:
        return get_object_or_404(Product, pk=product_id)
    elif product_name:
        return get_object_or_none(Product, name=product_name)
    else:
        return None


def get_engagement_name(engagement_id=None, engagement_name=None, product_id=None, product_name=None, product_type_id=None, product_type_name=None):
    if not engagement_name:
        engagement_name = ENGAGEMENT_NAME_AUTO
    return engagement_name


def get_target_engagement_if_exists(engagement_id=None, engagement_name=None, product_id=None, product_name=None, product_type_id=None, product_type_name=None):
    if engagement_id:
        engagement = get_object_or_404(Engagement, pk=engagement_id)
        logger.debug('Using existing engagement by id: %s', engagement_id)
        return engagement

    product = get_target_product_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)
    if not product:
        # if there's no product, then for sure there's no engagement either
        return None

    # TODO VS: Check if it doesn't by accident select engagement by name from another product
    engagement = get_object_or_none(Engagement, product=product, name=get_engagement_name(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name))
    return engagement


def get_or_create_engagement(engagement_id=None, engagement_name=None, product_id=None, product_name=None, product_type_id=None, product_type_name=None):
    engagement = get_target_engagement_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)

    if not engagement:
        product = get_target_product_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)

        if not product:
            if product_name:
                product = auto_create_product(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)
            else:
                raise ValueError('unable to create product, missing product_name')

        logger.info('Creating new engagement: %s', get_engagement_name(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name))
        return auto_create_engagement(get_engagement_name(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name), product)
    else:
        logger.debug('Using existing engagement %i:%s', engagement.id, engagement.name)

    return engagement
