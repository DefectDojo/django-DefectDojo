import contextlib
import logging

from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.models import Endpoint, Engagement, Finding, Product, Test

logger = logging.getLogger(__name__)


@dojo_async_task
@app.task
def propagate_tags_on_product(product_id, *args, **kwargs):
    with contextlib.suppress(Product.DoesNotExist):
        product = Product.objects.get(id=product_id)
        propagate_tags_on_product_sync(product)


def propagate_tags_on_product_sync(product):
    # enagagements
    logger.debug(f"Propagating tags from {product} to all engagements")
    propagate_tags_on_object_list(Engagement.objects.filter(product=product))
    # tests
    logger.debug(f"Propagating tags from {product} to all tests")
    propagate_tags_on_object_list(Test.objects.filter(engagement__product=product))
    # findings
    logger.debug(f"Propagating tags from {product} to all findings")
    propagate_tags_on_object_list(Finding.objects.filter(test__engagement__product=product))
    # endpoints
    logger.debug(f"Propagating tags from {product} to all endpoints")
    propagate_tags_on_object_list(Endpoint.objects.filter(product=product))


def propagate_tags_on_object_list(object_list):
    for obj in object_list:
        if obj and obj.id is not None:
            logger.debug(f"\tPropagating tags to {type(obj)} - {obj}")
            obj.save()
