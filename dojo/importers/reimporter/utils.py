from datetime import timedelta
from crum import get_current_user
from django.conf import settings
from dojo.importers import utils as importer_utils
from dojo.models import Engagement, Finding, Q, Product, Product_Member, Product_Type, Product_Type_Member, Role, Test
from django.utils import timezone
from dojo.decorators import dojo_async_task
from dojo.celery import app
import logging
from dojo.utils import get_last_object_or_none, get_object_or_none


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

"""
Common code for reimporting from APIV2 or from the GUI
"""


def match_new_finding_to_existing_finding(new_finding, test, deduplication_algorithm):
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
    # Determine if this can be run async
    if settings.ASYNC_FINDING_IMPORT:
        chunk_list = importer_utils.chunk_list(endpoint_status_to_mitigate)
        # If there is only one chunk, then do not bother with async
        if len(chunk_list) < 2:
            mitigate_endpoint_status(endpoint_status_to_mitigate, user, kwuser=user, sync=True)
            return
        # First kick off all the workers
        for endpoint_status_list in chunk_list:
            mitigate_endpoint_status(endpoint_status_list, user, kwuser=user, sync=False)
    else:
        mitigate_endpoint_status(endpoint_status_to_mitigate, user, kwuser=user, sync=True)


@dojo_async_task
@app.task()
def mitigate_endpoint_status(endpoint_status_list, user, **kwargs):
    for endpoint_status in endpoint_status_list:
        logger.debug("Re-import: mitigating endpoint %s that is no longer present", str(endpoint_status.endpoint))
        endpoint_status.mitigated_by = user
        endpoint_status.mitigated_time = timezone.now()
        endpoint_status.mitigated = True
        endpoint_status.last_modified = timezone.now()
        endpoint_status.save()


@dojo_async_task
@app.task()
def reactivate_endpoint_status(endpoint_status_list, **kwargs):
    for endpoint_status in endpoint_status_list:
        logger.debug("Re-import: reactivating endpoint %s that is present in this scan", str(endpoint_status.endpoint))
        endpoint_status.mitigated_by = None
        endpoint_status.mitigated_time = None
        endpoint_status.mitigated = False
        endpoint_status.last_modified = timezone.now()
        endpoint_status.save()


def get_target_product_if_exists(product_name=None, product_type_name=None):
    if product_name:
        product = get_object_or_none(Product, name=product_name)
        if product:
            # product type name must match if provided
            if product_type_name:
                if product.prod_type.name == product_type_name:
                    return product
            else:
                return product

    return None


def get_target_product_type_if_exists(product_type_name=None):
    if product_type_name:
        return get_object_or_none(Product_Type, name=product_type_name)
    else:
        return None


def get_target_product_by_id_if_exists(product_id=None):
    product = None
    if product_id:
        product = get_object_or_none(Product, pk=product_id)
        logger.debug('Using existing product by id: %s', product_id)
    return product


def get_target_engagement_if_exists(engagement_id=None, engagement_name=None, product=None):
    if engagement_id:
        engagement = get_object_or_none(Engagement, pk=engagement_id)
        logger.debug('Using existing engagement by id: %s', engagement_id)
        return engagement

    if not product:
        # if there's no product, then for sure there's no engagement either
        return None

    # engagement name is not unique unfortunately
    engagement = get_last_object_or_none(Engagement, product=product, name=engagement_name)
    return engagement


def get_target_test_if_exists(test_id=None, test_title=None, scan_type=None, engagement=None):
    """
    Retrieves the target test to reimport. This can be as simple as looking up the test via the `test_id` parameter.
    If there is no `test_id` provided, we lookup the latest test inside the provided engagement that satisfies
    the provided scan_type and test_title.
    """
    if test_id:
        test = get_object_or_none(Test, pk=test_id)
        logger.debug('Using existing Test by id: %s', test_id)
        return test

    if not engagement:
        return None

    if test_title:
        return get_last_object_or_none(Test, engagement=engagement, title=test_title, scan_type=scan_type)

    return get_last_object_or_none(Test, engagement=engagement, scan_type=scan_type)


def get_or_create_product(product_name=None, product_type_name=None, auto_create_context=None):
    # try to find the product (withing the provided product_type)
    product = get_target_product_if_exists(product_name, product_type_name)
    if product:
        return product

    # not found .... create it
    if not auto_create_context:
        raise ValueError('auto_create_context not True, unable to create non-existing product')
    else:
        product_type, created = Product_Type.objects.get_or_create(name=product_type_name)
        if created:
            member = Product_Type_Member()
            member.user = get_current_user()
            member.product_type = product_type
            member.role = Role.objects.get(is_owner=True)
            member.save()

        product = Product.objects.create(name=product_name, prod_type=product_type)
        member = Product_Member()
        member.user = get_current_user()
        member.product = product
        member.role = Role.objects.get(is_owner=True)
        member.save()

        return product


def get_or_create_engagement(engagement_id=None, engagement_name=None, product_name=None, product_type_name=None, auto_create_context=None):
    # try to find the engagement (and product)
    product = get_target_product_if_exists(product_name, product_type_name)
    engagement = get_target_engagement_if_exists(engagement_id, engagement_name, product)
    if engagement:
        return engagement

    # not found .... create it
    if not auto_create_context:
        raise ValueError('auto_create_context not True, unable to create non-existing engagement')
    else:
        product = get_or_create_product(product_name, product_type_name, auto_create_context)

        if not product:
            raise ValueError('no product, unable to create engagement')

        engagement = Engagement.objects.create(engagement_type="CI/CD", name=engagement_name, product=product, lead=get_current_user(), target_start=timezone.now().date(), target_end=(timezone.now() + timedelta(days=365)).date())

        return engagement
