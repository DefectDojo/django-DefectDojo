import contextlib
import logging

from django.conf import settings
from django.db.models import Q

from dojo.celery import app
from dojo.location.models import Location
from dojo.models import Endpoint, Engagement, Finding, Product, Test

logger = logging.getLogger(__name__)


@app.task
def propagate_tags_on_product(product_id, *args, **kwargs):
    with contextlib.suppress(Product.DoesNotExist):
        product = Product.objects.get(id=product_id)
        propagate_tags_on_product_sync(product)


def propagate_tags_on_product_sync(product):
    # enagagements
    logger.debug("Propagating tags from %s to all engagements", product)
    propagate_tags_on_object_list(Engagement.objects.filter(product=product))
    # tests
    logger.debug("Propagating tags from %s to all tests", product)
    propagate_tags_on_object_list(Test.objects.filter(engagement__product=product))
    # findings
    logger.debug("Propagating tags from %s to all findings", product)
    propagate_tags_on_object_list(Finding.objects.filter(test__engagement__product=product))
    if settings.V3_FEATURE_LOCATIONS:
        # Locations
        logger.debug("Propagating tags from %s to all locations", product)
        propagate_tags_on_object_list(
            Location.objects.filter(
                # Locations linked directly to a product via LocationProductReference
                Q(products__product=product)
                # Locations linked indirectly to a product via LocationFindingReference
                | Q(findings__finding__test__engagement__product=product),
            ).distinct(),
        )
    else:
        # TODO: Delete this after the move to Locations
        # endpoints
        logger.debug("Propagating tags from %s to all endpoints", product)
        propagate_tags_on_object_list(Endpoint.objects.filter(product=product))


def propagate_tags_on_object_list(object_list):
    for obj in object_list:
        if obj and obj.id is not None:
            logger.debug(f"\tPropagating tags to {type(obj)} - {obj}")
            obj.save()
