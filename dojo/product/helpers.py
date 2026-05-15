import contextlib
import logging

from dojo.celery import app
from dojo.models import Product
from dojo.tags.inheritance import (
    _LOCATION_PREFETCH_FOR_INHERITANCE,  # noqa: F401 -- backward compat re-export
    _inherited_tag_names_for_location,  # noqa: F401 -- backward compat re-export
    _sync_inheritance_for_qs,  # noqa: F401 -- backward compat re-export
    apply_inherited_tags_for_endpoints,  # noqa: F401 -- backward compat re-export
    apply_inherited_tags_for_findings,  # noqa: F401 -- backward compat re-export
    propagate_tags_on_product_sync,
)

logger = logging.getLogger(__name__)


@app.task
def propagate_tags_on_product(product_id, *args, **kwargs):
    with contextlib.suppress(Product.DoesNotExist):
        product = Product.objects.get(id=product_id)
        propagate_tags_on_product_sync(product)
