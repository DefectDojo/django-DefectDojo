from __future__ import annotations

from typing import TYPE_CHECKING, Self

from auditlog.registry import auditlog
from django.db import transaction
from django.db.models import (
    CASCADE,
    RESTRICT,
    CharField,
    DateTimeField,
    ForeignKey,
    Index,
    OneToOneField,
    Q,
    QuerySet,
    UniqueConstraint,
)
from django.utils.translation import gettext_lazy as _
from tagulous.models import TagField

from dojo.base_models.base import BaseModel, BaseModelWithoutTimeMeta
from dojo.base_models.validators import validate_not_empty
from dojo.location.manager import (
    LocationFindingReferenceManager,
    LocationFindingReferenceQueryset,
    LocationManager,
    LocationProductReferenceManager,
    LocationProductReferenceQueryset,
    LocationQueryset,
)
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import Dojo_User, Finding, Product, _manage_inherited_tags, copy_model_util
from dojo.settings import settings

if TYPE_CHECKING:
    from datetime import datetime


class Location(BaseModel):

    """Internal metadata for a location. Managed automatically by subclasses."""

    location_type = CharField(
        verbose_name=_("Location type"),
        max_length=12,
        null=False,
        blank=False,
        editable=False,
        validators=[validate_not_empty],
        help_text=_("The type of location that is stored. This field is automatically managed"),
    )
    location_value = CharField(
        verbose_name=_("Location Value"),
        max_length=2048,
        null=False,
        blank=False,
        editable=False,
        validators=[validate_not_empty],
        help_text=_("The string representation of a given location. This field is automatically managed"),
    )
    tags = TagField(
        verbose_name=_("Tags"),
        blank=True,
        force_lowercase=True,
        related_name="location_tags",
        help_text=_("A tag that can be used to differentiate a Location"),
    )
    inherited_tags = TagField(
        blank=True,
        force_lowercase=True,
        help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"),
    )

    objects = LocationManager().from_queryset(LocationQueryset)()

    def __str__(self):
        return self.location_value

    def status_from_finding(self, finding: Finding) -> str:
        """Determine the status the reference should carry based on the status of the finding"""
        # Set the default status to Active to be on the safe side
        status = FindingLocationStatus.Active
        # First determine the status based on the finding status
        finding_status = finding.status()
        if any(f_status in finding_status for f_status in ["Mitigated", "Inactive", "Duplicate"]):
            status = FindingLocationStatus.Mitigated
        elif "False Positive" in finding_status:
            status = FindingLocationStatus.FalsePositive
        elif "Risk Accepted" in finding_status:
            status = FindingLocationStatus.RiskAccepted
        return status

    def status_from_product(self, product: Product) -> str:
        """Determine the status the reference should carry based on the status of the product"""
        # Set the default status to non vulnerable by default
        status = ProductLocationStatus.Mitigated
        # First determine the status based on the number of findings present
        if self.findings.filter(
            finding__test__engagement__product=product,
            status=FindingLocationStatus.Active,
        ).exists():
            status = ProductLocationStatus.Active
        return status

    def associate_with_finding(
        self,
        finding: Finding,
        status: FindingLocationStatus | None = None,
        auditor: Dojo_User | None = None,
        audit_time: datetime | None = None,
    ) -> LocationFindingReference:
        """
        Get or create a LocationFindingReference for this location and finding,
        updating the status each time. Also associates the related product.
        """
        # Determine the status
        if status is None:
            status = self.status_from_finding(finding)
        # Setup some context aware updated fields
        context_fields = {"status": status}
        # Check for an auditor
        if auditor is not None:
            context_fields["auditor"] = auditor
        # Check for an audit timestamp
        if audit_time is not None:
            context_fields["audit_time"] = audit_time
        # Determine if we need to update
        # Ensure atomicity to prevent race conditions
        with transaction.atomic():
            # Associate the finding with the location
            reference = LocationFindingReference.objects.update_or_create(
                location=self,
                finding=finding,
                defaults=context_fields,
            )[0]
            # Now associate the product for this finding (already uses update_or_create)
            self.associate_with_product(finding.test.engagement.product)

            return reference

    def associate_with_product(
        self,
        product: Product,
        status: ProductLocationStatus | None = None,
    ) -> LocationProductReference:
        """
        Get or create a LocationProductReference for this location and product,
        updating the status each time.
        """
        if status is None:
            status = self.status_from_product(product)
        # Use a transaction for safety in concurrent scenarios
        with transaction.atomic():
            return LocationProductReference.objects.update_or_create(
                location=self,
                product=product,
                defaults={"status": status},
            )[0]

    def disassociate_from_finding(
        self,
        finding: Finding,
    ) -> None:
        with transaction.atomic():
            LocationFindingReference.objects.filter(
                location=self,
                finding=finding,
            ).delete()

    def disassociate_from_product(
        self,
        product: Product,
    ) -> None:
        with transaction.atomic():
            LocationProductReference.objects.filter(
                location=self,
                product=product,
            ).delete()

    @property
    def active_annotated_findings(self):
        """
        This is a hack used exclusively to generate endpoint reports where findings
        are fetched from the findings rather than the findings being fetched directly.
        """
        # If we prefetched refs, expose the actual Finding objects
        if hasattr(self, "_active_annotated_findings"):
            return [ref.finding for ref in self._active_annotated_findings]
        return []

    def all_related_products(self) -> QuerySet[Product]:
        return Product.objects.filter(
            Q(locations__location=self)
            | Q(engagement__test__finding__locations__location=self),
        ).distinct()

    def products_to_inherit_tags_from(self) -> list[Product]:
        from dojo.utils import get_system_setting  # noqa: PLC0415
        system_wide_inherit = get_system_setting("enable_product_tag_inheritance")
        return [
            product for product
            in self.all_related_products()
            if product.enable_product_tag_inheritance or system_wide_inherit
        ]

    def inherit_tags(self, potentially_existing_tags):
        # get a copy of the tags to be inherited
        incoming_inherited_tags = [tag.name for product in self.products_to_inherit_tags_from() for tag in product.tags.all()]
        _manage_inherited_tags(self, incoming_inherited_tags, potentially_existing_tags=potentially_existing_tags)

    class Meta:
        verbose_name = "Locations - Location"
        verbose_name_plural = "Locations - Locations"
        indexes = [
            Index(fields=["location_type"]),
            Index(fields=["location_value"]),
        ]


class AbstractLocation(BaseModelWithoutTimeMeta):
    location = OneToOneField(
        Location,
        on_delete=CASCADE,
        editable=False,
        null=False,
        related_name="%(class)s",
    )

    class Meta:
        abstract = True

    @classmethod
    def get_location_type(cls) -> str:
        """Return the type of location (e.g., 'url')."""
        msg = "Subclasses must implement get_location_type"
        raise NotImplementedError(msg)

    def get_location_value(self) -> str:
        """Return the string representation of this location."""
        msg = "Subclasses must implement get_location_value"
        raise NotImplementedError(msg)

    @staticmethod
    def create_location_from_value(value: str) -> Self:
        """
        Dynamically create a Location and subclass instance based on location_type
        and location_value. Uses parse_string_value from the correct subclass.
        """
        msg = "Subclasses must implement create_location_from_value"
        raise NotImplementedError(msg)

    def pre_save_logic(self):
        """Automatically create or update the associated Location."""
        location_value = self.get_location_value()
        location_type = self.get_location_type()

        if not hasattr(self, "location"):
            self.location = Location.objects.create(
                location_type=location_type,
                location_value=location_value,
            )
        else:
            self.location.location_type = location_type
            self.location.location_value = location_value
            self.location.save(update_fields=["location_type", "location_value"])


class LocationFindingReference(BaseModel):

    """Manually managed One-2-Many field to represent the relationship of a finding and a location."""

    location = ForeignKey(Location, on_delete=CASCADE, related_name="findings")
    finding = ForeignKey(Finding, on_delete=CASCADE, related_name="locations")
    auditor = ForeignKey(Dojo_User, editable=True, null=True, blank=True, on_delete=RESTRICT, help_text=_("The user who audited the location"))
    audit_time = DateTimeField(editable=False, null=True, blank=True, help_text=_("The time when the audit was performed"))
    status = CharField(
        verbose_name=_("Status"),
        choices=FindingLocationStatus.choices,
        max_length=16,
        null=False,
        blank=False,
        default=FindingLocationStatus.Active,
        editable=True,
        validators=[validate_not_empty],
        help_text=_("The status of the the given Location"),
    )

    objects = LocationFindingReferenceManager().from_queryset(LocationFindingReferenceQueryset)()

    def __str__(self) -> str:
        """Return the string representation of a LocationProductReference."""
        return f"{self.location} - Finding: {self.finding} ({self.status})"

    def copy(self, finding) -> Self:
        copy = copy_model_util(self)
        copy.finding = finding
        copy.location = self.location
        copy.save()
        return copy

    def set_status(self, status: FindingLocationStatus, auditor: Dojo_User, audit_time: datetime) -> None:
        self.status = status
        self.auditor = auditor
        self.audit_time = audit_time
        self.save()

    class Meta:
        verbose_name = "Locations - FindingReference"
        verbose_name_plural = "Locations - FindingReferences"
        constraints = [
            UniqueConstraint(
                fields=["location", "finding"],
                name="unique_location_and_finding",
            ),
        ]
        indexes = [
            Index(fields=["location"]),
            Index(fields=["finding"]),
        ]


class LocationProductReference(BaseModel):

    """Manually managed One-2-Many field to represent the relationship of a product and a location."""

    location = ForeignKey(Location, on_delete=CASCADE, related_name="products")
    product = ForeignKey(Product, on_delete=CASCADE, related_name="locations")
    status = CharField(
        verbose_name=_("Status"),
        choices=ProductLocationStatus.choices,
        max_length=16,
        null=False,
        blank=False,
        default=ProductLocationStatus.Mitigated,
        editable=True,
        validators=[validate_not_empty],
        help_text=_("The status of the the given Location"),
    )

    objects = LocationProductReferenceManager().from_queryset(LocationProductReferenceQueryset)()

    def __str__(self) -> str:
        """Return the string representation of a LocationProductReference."""
        return f"{self.location} - Product: {self.product} ({self.status})"

    class Meta:
        verbose_name = "Locations - ProductReference"
        verbose_name_plural = "Locations - ProductReferences"
        constraints = [
            UniqueConstraint(
                fields=["location", "product"],
                name="unique_location_and_product",
            ),
        ]
        indexes = [
            Index(fields=["location"]),
            Index(fields=["product"]),
        ]


if settings.ENABLE_AUDITLOG:
    auditlog.register(Location)
