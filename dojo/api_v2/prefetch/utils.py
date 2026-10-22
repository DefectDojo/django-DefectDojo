from django.db.models.fields import related

from dojo.location.feature import locations_enabled
from dojo.models import Finding, Product

# Reverse one-to-many relations advertised as prefetchable, per model.
#
# ``get_prefetchable_fields`` discovers forward ForeignKeys and many-to-many fields
# from the model's descriptors. Reverse ForeignKeys are deliberately not discovered
# the same way: the reverse side of a model is every FK that points at it
# (``burprawrequestresponse_set``, ``jira_issue``, ``test_import_finding_action``, ...),
# and most of those would only be noise in the ``?prefetch=`` enum. Reverse relations
# are therefore opted in here, one ``related_name`` at a time.
#
# ``LocationFindingReference.finding`` and ``LocationProductReference.product`` both
# declare ``related_name="locations"``. Under V3 a finding's ``endpoints`` field carries
# those reference ids, so ``?prefetch=locations`` is how an API client resolves them to
# a location type and value in the same request.
#
# The table is also the request-time allowlist: ``_Prefetcher`` skips any reverse
# relation not listed here, so ``?prefetch=finding_set`` on a test (every finding in
# the test, unbounded) is not served just because the name resolves on the model.
#
# On findings, ``locations`` returns the same rows as ``endpoints`` does under V3
# (see ``_Prefetcher.get_field_value_override``). It is listed anyway so the option
# has its V3 name in the documented enum.
_PREFETCHABLE_REVERSE_RELATIONS = {
    Finding: ("locations",),
    Product: ("locations",),
}


def _is_many_to_many_relation(field):
    """
    Check if a field specified a many-to-many relationship as defined by django.
    This is the case if the field is an instance of the ManyToManyDescriptor as generated
    by the django framework

    Args:
        field (django.db.models.fields): The field to check

    Returns:
        bool: true if the field is a many-to-many relationship

    """
    return isinstance(field, related.ManyToManyDescriptor)


def _is_one_to_many_relation(field):
    """
    Check if a field specifies a reverse one-to-many relationship, i.e. the
    "many" side of a ForeignKey. Example: ``Finding.locations`` is the reverse
    of ``LocationFindingReference.finding`` (``related_name="locations"``).

    Django exposes these through the ``ReverseManyToOneDescriptor``, and accessing
    the attribute yields a ``RelatedManager`` -- exactly like a many-to-many
    field. ``ManyToManyDescriptor`` subclasses ``ReverseManyToOneDescriptor``, so
    the many-to-many case is excluded here; ``_is_many_to_many_relation`` covers it.

    Args:
        field (django.db.models.fields): The field to check

    Returns:
        bool: true if the field is a reverse one-to-many relationship

    """
    return isinstance(field, related.ReverseManyToOneDescriptor) and not isinstance(
        field, related.ManyToManyDescriptor,
    )


def _is_one_to_one_relation(field):
    """
    Check if a field specified a one-to-one relationship as defined by django.
    This is the case if the field is an instance of the ForwardManyToOne as generated
    by the django framework

    Args:
        field (django.db.models.fields): The field to check

    Returns:
        bool: true if the field is a one-to-one relationship

    """
    return isinstance(field, related.ForwardManyToOneDescriptor)


def is_prefetchable_reverse_relation(model, field_name):
    """
    Check if a reverse one-to-many relation is opted in to prefetching for the given
    model (or one of its parents, so a subclass of ``Finding`` inherits the entry).

    Args:
        model (django.db.models.Model): the model class the field is read from
        field_name (str): the name of the reverse relation

    Returns:
        bool: true if ``_PREFETCHABLE_REVERSE_RELATIONS`` lists the relation

    """
    return any(
        issubclass(model, opted_in_model) and field_name in field_names
        for opted_in_model, field_names in _PREFETCHABLE_REVERSE_RELATIONS.items()
    )


def get_prefetchable_reverse_relations(model):
    """
    Get the reverse one-to-many relations that are advertised as prefetchable for
    the given model, as ``(field_name, related_model)`` tuples.

    Only the opted-in relations in ``_PREFETCHABLE_REVERSE_RELATIONS`` are returned,
    and the Locations relations only while the Locations feature is enabled: with it
    off, findings and products carry Endpoints instead and the relation is always empty.

    Args:
        model (django.db.models.Model): the model class to inspect

    Returns:
        list[tuple[str, django.db.models.Model]]: the prefetchable reverse relations

    """
    if not locations_enabled():
        return []

    fields = []
    for field_name in _PREFETCHABLE_REVERSE_RELATIONS.get(model, ()):
        descriptor = getattr(model, field_name, None)
        if _is_one_to_many_relation(descriptor):
            # The model that declares the ForeignKey, e.g. LocationFindingReference
            fields.append((field_name, descriptor.field.model))
    return fields


def get_prefetchable_fields(serializer):
    """
    Get the fields that are prefetchable according to the serializer description.
    Method mainly used by for automatic schema generation.

    Args:
        serializer (Serializer): [description]

    """

    def _is_field_prefetchable(field):
        return _is_one_to_one_relation(field) or _is_many_to_many_relation(
            field,
        )

    meta = getattr(serializer, "Meta", None)
    if meta is None:
        return []

    model = getattr(meta, "model", None)
    if model is None:
        return []

    fields = []
    for field_name in dir(model):
        field = getattr(model, field_name)
        if _is_field_prefetchable(field):
            # ManyToMany relationship can be reverse
            if hasattr(field, "reverse") and field.reverse:
                fields.append((field_name, field.field.model))
            else:
                fields.append((field_name, field.field.related_model))

    fields.extend(get_prefetchable_reverse_relations(model))

    return fields
