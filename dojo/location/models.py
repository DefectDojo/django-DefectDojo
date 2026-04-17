from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Self

from django.core.validators import MinLengthValidator
from django.db import transaction
from django.db.models import (
    CASCADE,
    RESTRICT,
    CharField,
    DateTimeField,
    ForeignKey,
    Index,
    JSONField,
    Model,
    OneToOneField,
    Q,
    QuerySet,
    TextChoices,
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
from dojo.tools.locations import LocationAssociationData

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from dojo.tools.locations import LocationData


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
        relationship: str = "",
        relationship_data: dict | None = None,
    ) -> LocationFindingReference:
        """
        Get or create a LocationFindingReference for this location and finding.
        Also associates the related product.
        """
        # Check if there is an existing reference for this finding and location
        # If this method is being used to set the status
        if LocationFindingReference.objects.filter(
            location=self,
            finding=finding,
        ).exists():
            return LocationFindingReference.objects.get(
                location=self,
                finding=finding,
            )
        # Determine the status
        if status is None:
            status = self.status_from_finding(finding)
        # Setup some context aware updated fields
        context_fields = {
            "status": status,
            "relationship": relationship,
            "relationship_data": relationship_data if relationship_data is not None else {},
        }
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
        relationship: str = "",
        relationship_data: dict | None = None,
    ) -> LocationProductReference:
        """Get or create a LocationProductReference for this location and product"""
        # Check if there is an existing reference for this finding and location
        # If this method is being used to set the status
        if LocationProductReference.objects.filter(
            location=self,
            product=product,
        ).exists():
            return LocationProductReference.objects.get(
                location=self,
                product=product,
            )
        if status is None:
            status = self.status_from_product(product)
        # Use a transaction for safety in concurrent scenarios
        with transaction.atomic():
            return LocationProductReference.objects.update_or_create(
                location=self,
                product=product,
                defaults={
                    "status": status,
                    "relationship": relationship,
                    "relationship_data": relationship_data if relationship_data is not None else {},
                },
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
    identity_hash = CharField(
        null=False,
        blank=False,
        max_length=64,
        editable=False,
        unique=True,
        db_index=True,
        validators=[MinLengthValidator(64)],
        help_text=_("The hash of the location for uniqueness"),
    )

    class Meta:
        abstract = True

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and str(self) == str(other)

    def clean(self, *args: list, **kwargs: dict) -> None:
        self.set_identity_hash()
        super().clean(*args, **kwargs)

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

    def set_identity_hash(self):
        self.identity_hash = hashlib.blake2b(str(self).encode(), digest_size=32).hexdigest()

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

    @classmethod
    def from_location_data(cls, location_data: LocationData) -> Self:
        """
        Checks that the given LocationData object represents this type, then calls #_from_location_data_impl() to build
        one based on its contents. Saving boilerplate checking is all.
        """
        if location_data.type != cls.get_location_type():
            error_message = f"Cannot create instance of {cls} from LocationData of type {location_data.type}"
            raise ValueError(error_message)
        return cls._from_location_data_impl(location_data)

    @classmethod
    def _from_location_data_impl(cls, location_data: LocationData) -> Self:
        """Given a LocationData object trusted to represent this type, build a Location object from its contents."""
        msg = "Subclasses must implement _from_location_data_impl"
        raise NotImplementedError(msg)

    def get_association_data(self) -> LocationAssociationData:
        """
        Return the LocationAssociationData associated with this AbstractLocation. For convenience, if one does not
        exist, this returns an empty (falsey) LocationAssociationData that defaults to the empty values expected by
        the backing ReferenceDataMixin models.
        """
        return getattr(self, "_association_data", LocationAssociationData())

    @classmethod
    def get_or_create_from_object(cls, location: Self) -> Self:
        """Given an object of this type, this method should get/create the object and return it."""
        msg = "Subclasses must implement get_or_create_from_object"
        raise NotImplementedError(msg)

    @classmethod
    def bulk_get_or_create(cls, locations: Iterable[Self]) -> list[Self]:
        """
        Get or create multiple locations in bulk.

        For each location, looks up by identity_hash. Creates missing ones using
        bulk_create for both the parent Location rows and the subtype rows.
        Returns the full list of saved instances (existing + newly created),
        in the same order as the input. Duplicate inputs map to the same saved instance.
        """
        if not locations:
            return []

        # Create the list of hashes of the supplied locations; we will also use this to reconstruct the initial ordering
        # of locations we return (which would otherwise be lost if duplicates are represented in `locations`).
        hashes = []
        for loc in locations:
            # Sanity check the given locations list is homogenous
            if not isinstance(loc, cls):
                error_message = f"Invalid location type; expected {cls} but got {type(loc)}"
                raise TypeError(error_message)
            hashes.append(loc.identity_hash)

        # Look up existing objects, grouping by hash
        existing_by_hash = {
            obj.identity_hash: obj
            for obj in cls.objects.filter(identity_hash__in=hashes).select_related("location")
        }

        # Create the list of new locations to create
        new_locations = []
        for loc in locations:
            if loc.identity_hash not in existing_by_hash:
                new_locations.append(loc)
                # Mark it so we don't try to create duplicates within the same batch
                existing_by_hash[loc.identity_hash] = loc
            else:
                # Preserve association data from the input onto the existing saved object, in case we're associating
                # existing locations with findings/products
                saved = existing_by_hash[loc.identity_hash]
                if hasattr(loc, "_association_data") and not hasattr(saved, "_association_data"):
                    saved._association_data = loc._association_data

        # Create 'em
        if new_locations:
            location_type = cls.get_location_type()
            with transaction.atomic():
                # Bulk create parent Locations
                parents = [
                    Location(
                        location_type=location_type,
                        location_value=loc.get_location_value(),
                    )
                    for loc in new_locations
                ]
                Location.objects.bulk_create(parents, batch_size=1000)

                # Assign Location FKs to the subtypes, then bulk create them.
                for loc, parent in zip(new_locations, parents, strict=True):
                    loc.location_id = parent.id
                    loc.location = parent
                # Note there is a subtle race condition here, if somehow one of our newly-created locations conflicts
                # with an existing one (e.g. from a separate thread that commits while this is running). Setting
                # `ignore_conflicts=True` here would prevent this step from raising an IntegrityError, but would leave
                # dangling parent Location objects that were created above. Rather than performing a cleanup in that
                # (unlikely?) case, just allow the transaction to rollback.
                cls.objects.bulk_create(new_locations, batch_size=1000)

        # Return in input order (minus dupes)
        return [existing_by_hash[h] for h in hashes]


class ReferenceDataMixin(Model):

    """Provides fields for relationship data relevant to a Location and Finding/Product reference."""

    class RelationshipType(TextChoices):
        OWNED_BY = "owned_by", _("is owned by")
        USED_BY = "used_by", _("is used by")

    relationship = CharField(
        max_length=16,
        null=False,
        blank=True,
        choices=RelationshipType.choices,
        default="",
        help_text=_("The relationship between two locations"),
    )
    relationship_data = JSONField(
        null=False,
        blank=True,
        default=dict,
        help_text=_("Any extra data about this relationship"),
    )

    class Meta:
        abstract = True


class LocationFindingReference(BaseModel, ReferenceDataMixin):

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


class LocationProductReference(BaseModel, ReferenceDataMixin):

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

    def __str__(self) -> str:
        """Return the string representation of a LocationProductReference."""
        return f"{self.location} - Product: {self.product} ({self.status})"
