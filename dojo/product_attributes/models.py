"""
Editable lookup tables for the Asset/Product ``platform``, ``lifecycle`` and
``origin`` fields.

These three fields used to be fixed ``CharField(choices=...)`` enums on
:class:`dojo.product.models.Product`. They are now customer-editable lookup tables,
following the same pattern as :class:`dojo.development_environment.models.Development_Environment`.

Each option carries:

* ``value`` -- the immutable machine string. This is what the ``Product`` foreign key
  is keyed on over the API (a ``SlugRelatedField``), what the automation rules engine
  compares against, and what appears in webhook payloads. It is seeded from the old
  choice codes so existing API clients, imports and exports keep working unchanged.
* ``name`` -- the human-facing label shown in dropdowns and on the asset. This is the
  part administrators edit.
* ``icon`` -- an optional Font Awesome class used by the classic UI display tags.
* ``display_order`` -- optional ordering for the dropdown.
"""
from django.db import models
from django.urls import reverse


class ProductAttributeOption(models.Model):

    """Abstract base for the three asset attribute lookup tables."""

    # The reverse() url name of the classic-UI edit view; set by each concrete model.
    edit_url_name: str = ""

    value = models.CharField(
        max_length=50,
        unique=True,
        help_text="Stable machine value used by the API, imports and automation rules. "
                  "Immutable once created.",
    )
    name = models.CharField(
        max_length=200,
        help_text="Label shown in dropdowns and on the asset.",
    )
    icon = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Optional Font Awesome icon class (classic UI only).",
    )
    display_order = models.IntegerField(
        default=0,
        help_text="Optional ordering for the dropdown (lower first).",
    )

    class Meta:
        abstract = True
        ordering = ["display_order", "name"]

    def __str__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": str(self),
                 "url": reverse(self.edit_url_name, args=(self.id,))}]


class Product_Platform(ProductAttributeOption):
    edit_url_name = "edit_product_platform"


class Product_Lifecycle(ProductAttributeOption):
    edit_url_name = "edit_product_lifecycle"


class Product_Origin(ProductAttributeOption):
    edit_url_name = "edit_product_origin"
