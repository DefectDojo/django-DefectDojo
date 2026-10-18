"""
Writes behind the legacy ``/api/v2/endpoints`` and ``/api/v2/endpoint_status`` routes.

With Locations enabled those routes are served from Locations: an "endpoint" row is a
``LocationProductReference`` to a URL Location, and an "endpoint status" row is a
``LocationFindingReference``. The functions here turn a legacy Endpoint or Endpoint_Status
write into the equivalent Location write, so automation built against the Endpoint API keeps
working. They take model instances and plain values, never requests or serializers.

A Location is shared by every product that recorded the same URL, while a legacy Endpoint
belonged to exactly one product. Every write here therefore acts on one product's
references and leaves the other products' references to the same Location alone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from dojo.authorization.roles_permissions import Permissions
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.queries import locations_shared_outside, remove_location_references
from dojo.location.status import FindingLocationStatus
from dojo.models import DojoMeta, Product
from dojo.product.queries import get_authorized_products
from dojo.url.models import URL

if TYPE_CHECKING:
    from dojo.models import Dojo_User, Finding

# The legacy Endpoint field names, mapped to the URL field each one is stored in.
ENDPOINT_URL_FIELDS = {
    "protocol": "protocol",
    "userinfo": "user_info",
    "host": "host",
    "port": "port",
    "path": "path",
    "query": "query",
    "fragment": "fragment",
}

# The legacy Endpoint_Status flags, in the order the endpoint backfill resolves them: when
# more than one is set, the first one wins. A Location reference holds one status.
ENDPOINT_STATUS_FLAGS = (
    ("risk_accepted", FindingLocationStatus.RiskAccepted),
    ("false_positive", FindingLocationStatus.FalsePositive),
    ("out_of_scope", FindingLocationStatus.OutOfScope),
    ("mitigated", FindingLocationStatus.Mitigated),
)


def flags_from_status(status: str) -> dict[str, bool]:
    """The legacy Endpoint_Status flags that a reference status reads back as."""
    return {flag: status == flag_status for flag, flag_status in ENDPOINT_STATUS_FLAGS}


def status_from_flags(current: str, requested: dict[str, bool]) -> FindingLocationStatus:
    """
    The reference status a legacy flag write leaves behind.

    A flag the request sets to true wins over one already set, so ``{"mitigated": true}``
    on a false-positive row mitigates it, the way a client writing that flag expects. Among
    flags set together, the backfill's order decides. Clearing the flag that is set leaves
    the row Active.
    """
    flags = flags_from_status(current)
    flags.update(requested)
    for candidates in (requested, flags):
        for flag, flag_status in ENDPOINT_STATUS_FLAGS:
            if candidates.get(flag):
                return flag_status
    return FindingLocationStatus.Active


def build_url(**endpoint_fields) -> URL:
    """
    An unsaved, cleaned URL from legacy Endpoint field values.

    Raises ``ValidationError`` for values the URL model does not accept.
    """
    url = URL.from_parts(**{ENDPOINT_URL_FIELDS[name]: endpoint_fields.get(name) for name in ENDPOINT_URL_FIELDS})
    if not url.host:
        msg = "Host must not be empty"
        raise ValidationError(msg)
    url.clean()
    # Field validators (protocol, port range, query and fragment format). The location link
    # does not exist yet, and an identity that already exists is reused, not an error.
    url.full_clean(exclude=["location", "identity_hash"], validate_unique=False)
    return url


def product_reference_for(product: Product, url: URL) -> LocationProductReference | None:
    """The product's existing reference to the Location ``url`` identifies, if any."""
    return LocationProductReference.objects.filter(
        product=product,
        location__url__identity_hash=url.identity_hash,
    ).first()


def sync_product_reference_status(location: Location, product: Product) -> None:
    """Recompute a product reference's status after a change to its finding references."""
    LocationProductReference.objects.filter(location=location, product=product).update(
        status=location.status_from_product(product),
    )


def can_write_location_tags(location: Location, user: Dojo_User) -> bool:
    """
    Whether ``user`` may change the tag set of ``location``.

    A Location has one tag set, shared by every product that references it. A legacy
    Endpoint's tags were its product's alone, so a tag write here is allowed only when the
    user may edit every product that would see the change.
    """
    editable = get_authorized_products(Permissions.Product_Edit, user=user)
    return not locations_shared_outside(Location.objects.filter(pk=location.pk), editable).exists()


def set_location_tags(location: Location, tags: list[str], user: Dojo_User) -> None:
    if not can_write_location_tags(location, user):
        msg = (
            "The tags on this endpoint are shared with an asset you cannot edit, so they cannot "
            "be changed through the Endpoint API."
        )
        raise ValidationError(msg)
    location.tags.set(tags)


def create_product_reference(product: Product, url: URL, *, tags: list[str] | None, user: Dojo_User) -> LocationProductReference:
    """Record ``url`` on ``product``, the way creating a legacy Endpoint did."""
    with transaction.atomic():
        location = URL.get_or_create_from_object(url).location
        reference = location.associate_with_product(product)
        if tags is not None:
            set_location_tags(location, tags, user)
    return reference


def move_product_reference(reference: LocationProductReference, url: URL) -> LocationProductReference:
    """
    Give one product's endpoint a new address, the way editing a legacy Endpoint did.

    When the Location belongs to this product alone and the new address is not recorded
    yet, the URL is changed in place, so the Location keeps its id, tags and metadata.
    Otherwise the reference, this product's finding references and its metadata move to the
    Location for the new address, and the old Location is deleted if nothing else uses it.
    """
    product = reference.product
    old_location = reference.location
    products = Product.objects.filter(pk=product.pk)
    with transaction.atomic():
        existing = URL.objects.filter(identity_hash=url.identity_hash).select_related("location").first()
        shared = locations_shared_outside(Location.objects.filter(pk=old_location.pk), products).exists()
        if existing is None and not shared:
            current = old_location.url
            for url_field in ENDPOINT_URL_FIELDS.values():
                setattr(current, url_field, getattr(url, url_field))
            current.clean()
            current.save()
            reference.refresh_from_db()
            return reference

        new_location = (existing or URL.get_or_create_from_object(url)).location
        finding_references = LocationFindingReference.objects.filter(
            location=old_location,
            finding__test__engagement__product=product,
        )
        for finding_reference in finding_references:
            if LocationFindingReference.objects.filter(location=new_location, finding_id=finding_reference.finding_id).exists():
                finding_reference.delete()
            else:
                finding_reference.location = new_location
                finding_reference.save()
        metadata = DojoMeta.objects.filter(location=old_location, location_product=product)
        DojoMeta.objects.filter(
            location=new_location,
            location_product=product,
            name__in=metadata.values("name"),
        ).delete()
        metadata.update(location=new_location)
        reference.location = new_location
        reference.save()
        Location.objects.filter(pk=old_location.pk, products__isnull=True, findings__isnull=True).delete()
        sync_product_reference_status(new_location, product)
    return reference


def delete_product_reference(reference: LocationProductReference) -> None:
    """
    Remove one product's endpoint, the way deleting a legacy Endpoint did.

    Deletes the product's reference, its findings' references and its metadata on the
    Location, then the Location itself when no other product or finding uses it.
    """
    with transaction.atomic():
        DojoMeta.objects.filter(location_id=reference.location_id, location_product_id=reference.product_id).delete()
        remove_location_references(
            Location.objects.filter(pk=reference.location_id),
            Product.objects.filter(pk=reference.product_id),
        )


def _audit(status: str, user: Dojo_User, mitigated_by: Dojo_User | None) -> Dojo_User:
    # The legacy mitigated_by field names who mitigated. Other statuses record who set them.
    if status == FindingLocationStatus.Mitigated and mitigated_by is not None:
        return mitigated_by
    return user


def create_finding_reference(
    product_reference: LocationProductReference,
    finding: Finding,
    flags: dict[str, bool],
    *,
    user: Dojo_User,
    mitigated_by: Dojo_User | None = None,
) -> LocationFindingReference:
    """Link a finding to one of its product's endpoints, the way creating an Endpoint_Status did."""
    status = status_from_flags(FindingLocationStatus.Active, flags)
    audited = status != FindingLocationStatus.Active
    with transaction.atomic():
        reference = product_reference.location.associate_with_finding(
            finding,
            status=status,
            auditor=_audit(status, user, mitigated_by) if audited else None,
            audit_time=timezone.now() if audited else None,
        )
        sync_product_reference_status(product_reference.location, product_reference.product)
    return reference


def update_finding_reference(
    reference: LocationFindingReference,
    flags: dict[str, bool],
    *,
    user: Dojo_User,
    mitigated_by: Dojo_User | None = None,
) -> LocationFindingReference:
    """Apply legacy Endpoint_Status flag writes to a finding reference."""
    status = status_from_flags(reference.status, flags)
    with transaction.atomic():
        if status != reference.status:
            reference.set_status(status, _audit(status, user, mitigated_by), timezone.now())
            sync_product_reference_status(reference.location, reference.finding.test.engagement.product)
        elif status == FindingLocationStatus.Mitigated and mitigated_by is not None and mitigated_by != reference.auditor:
            reference.auditor = mitigated_by
            reference.save()
    return reference


def delete_finding_reference(reference: LocationFindingReference) -> None:
    """Unlink a finding from an endpoint, the way deleting an Endpoint_Status did."""
    location = reference.location
    product = reference.finding.test.engagement.product
    with transaction.atomic():
        reference.delete()
        sync_product_reference_status(location, product)


def finding_endpoint_references(finding: Finding) -> list[LocationProductReference]:
    """
    A finding's endpoints: its product's references to the URL Locations the finding is on.

    Reads ``finding.locations`` and each Location's product references, so a caller that
    prefetched ``locations__location__products`` pays no query per finding.
    """
    product_id = finding.test.engagement.product_id
    return [
        product_reference
        for finding_reference in finding.locations.all()
        if finding_reference.location.location_type == URL.LOCATION_TYPE
        for product_reference in finding_reference.location.products.all()
        if product_reference.product_id == product_id
    ]


def set_finding_endpoints(finding: Finding, product_references: list[LocationProductReference]) -> None:
    """
    Make a finding's URL locations exactly those of ``product_references``.

    The legacy ``endpoints`` field on a finding replaced its endpoint set: endpoints still in
    the list kept their status, the others were unlinked, and new ones were linked. Only URL
    references are touched; code and dependency locations are not endpoints.
    """
    wanted = {reference.location_id: reference.location for reference in product_references}
    product = finding.test.engagement.product
    with transaction.atomic():
        current = LocationFindingReference.objects.filter(finding=finding, location__location_type=URL.LOCATION_TYPE)
        unlinked = current.exclude(location_id__in=wanted)
        changed = set(unlinked.values_list("location_id", flat=True))
        unlinked.delete()
        linked = set(current.values_list("location_id", flat=True))
        for location_id, location in wanted.items():
            if location_id not in linked:
                location.associate_with_finding(finding)
                changed.add(location_id)
        for location in Location.objects.filter(pk__in=changed):
            sync_product_reference_status(location, product)
