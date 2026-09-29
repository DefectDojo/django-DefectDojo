from django.core.validators import EMPTY_VALUES
from django.db.models import Exists, OuterRef

from dojo.authorization.roles_permissions import Permissions
from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.product.queries import get_authorized_products

# Relations that leave the Location and reach another product's rows, mapped to the
# reference model that carries them and the path from that model to its product.
OUTWARD_RELATIONS = {
    "products": (LocationProductReference, "product__in"),
    "findings": (LocationFindingReference, "finding__test__engagement__product__in"),
}


class OutwardRelationScopedFilterSet:

    """Bounds every declared predicate that joins out of a Location to the caller's products."""

    def filter_queryset(self, queryset):
        """
        Match each predicate against the caller's own references only.

        A Location is shared by every product that references it, so a predicate that
        joins outward can be satisfied by a reference the caller cannot see. Narrowing
        the result afterwards does not help: that is a second, independent join, and the
        row still qualifies through its own product.
        """
        user = getattr(self, "user", None) or getattr(getattr(self, "request", None), "user", None)
        authorized_products = get_authorized_products(Permissions.Product_View, user)
        for name, value in self.form.cleaned_data.items():
            declared = self.filters[name]
            relation, _, remainder = (declared.field_name or "").partition("__")
            outward = OUTWARD_RELATIONS.get(relation)
            if outward is None or value in EMPTY_VALUES:
                queryset = declared.filter(queryset, value)
                continue
            reference_model, product_path = outward
            lookup = "in" if isinstance(value, list | tuple) else declared.lookup_expr
            # Two calls, not one dict: the predicate and the product bound can spell the
            # same lookup, and a dict would silently drop one of them.
            matching_references = reference_model.objects.filter(
                location=OuterRef("pk"),
                **{f"{remainder}__{lookup}" if remainder else lookup: value},
            ).filter(**{product_path: authorized_products})
            queryset = (
                queryset.exclude(Exists(matching_references))
                if declared.exclude
                else queryset.filter(Exists(matching_references))
            )
        return queryset
