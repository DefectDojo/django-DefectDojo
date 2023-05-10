from dojo.celery import app
from celery.utils.log import get_task_logger
from dojo.models import Product, Engagement, Test, Finding, Endpoint


logger = get_task_logger(__name__)


@app.task
def propagate_tags_on_product(product_id, *args, **kwargs):
    product = Product.objects.get(id=product_id)
    # enagagements
    logger.debug(f"Propogating tags from {product} to all engagements")
    propagate_tags_on_object_list(Engagement.objects.filter(product=product))
    # tests
    logger.debug(f"Propogating tags from {product} to all tests")
    propagate_tags_on_object_list(Test.objects.filter(engagement__product=product))
    # findings
    logger.debug(f"Propogating tags from {product} to all findings")
    propagate_tags_on_object_list(Finding.objects.filter(test__engagement__product=product))
    # endpoints
    logger.debug(f"Propogating tags from {product} to all endpoints")
    propagate_tags_on_object_list(Endpoint.objects.filter(product=product))


def propagate_tags_on_object_list(object_list):
    for obj in object_list:
        logger.debug(f"\tPropogating tags to {str(type(obj))} - {str(obj)}")
        obj.save()
