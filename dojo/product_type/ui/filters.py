import logging

from django_filters import CharFilter, OrderingFilter

from dojo.filters import DojoFilter
from dojo.product_type.models import Product_Type

logger = logging.getLogger(__name__)


class ProductTypeFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Product_Type
        exclude = []
        include = ("name",)
