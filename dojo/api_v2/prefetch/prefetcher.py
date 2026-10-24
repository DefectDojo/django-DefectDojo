import inspect
import sys

from django.db.models import prefetch_related_objects
from django.db.models.fields import related
from rest_framework.serializers import ModelSerializer

from dojo.api_v2.prefetch import (
    registrations as _registrations,  # noqa: F401 -- side-effect import populates the RBAC registry
)
from dojo.api_v2.prefetch import utils
from dojo.api_v2.prefetch.authorized_querysets import get_authorized_queryset
from dojo.location.api.serializers import (
    LocationFindingReferenceSerializer,
    LocationProductReferenceSerializer,
    LocationSerializer,
)
from dojo.location.feature import locations_enabled
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Endpoint, FileUpload, Finding, Notes

# Related objects that a prefetched model's serializer reads, so they are fetched in the same query
_PREFETCH_SELECT_RELATED = {
    LocationFindingReference: ("location",),
    LocationProductReference: ("location",),
    Notes: ("author", "editor", "note_type"),
}
# Relations a prefetched model's serializer reads, batched over every object the page prefetches
_PREFETCH_PREFETCH_RELATED = {
    Endpoint: ("endpoint_params", "findings", "tags"),
    Notes: ("history__current_editor", "history__note_type"),
}

# Reduce the scope of search for serializers.
SERIALIZER_DEFS_MODULE = "dojo.api_v2.serializers"

preferred_serializers = {
    FileUpload: "FileSerializer",
}


class _Prefetcher:
    @staticmethod
    def _build_serializers():
        """
        Returns a map model -> serializer where model is a django model and serializer is the corresponding
        serializer used to serialize the model

        Returns:
            dict[model, serializer]: map of model to their serializer

        """

        def _is_model_serializer(obj):
            return inspect.isclass(obj) and issubclass(obj, ModelSerializer)

        serializers = {}
        # We process all the serializers found in the module SERIALIZER_DEFS_MODULE. We restrict the scope to avoid
        # processing all the classes in the symbol table
        available_serializers = inspect.getmembers(
            sys.modules[SERIALIZER_DEFS_MODULE],
            _is_model_serializer,
        )

        for _, serializer in available_serializers:
            model = serializer.Meta.model
            if model in preferred_serializers:
                if serializer.__name__ == preferred_serializers[model]:
                    serializers[model] = serializer
            else:
                serializers[model] = serializer
        # We add object->None to have a more uniform processing later on
        serializers[object] = None

        return serializers

    def __init__(self, request=None):
        self._serializers = _Prefetcher._build_serializers()
        self._prefetch_data = {}
        self._request = request

    def _find_serializer(self, field_type):
        """
        Find the best suited serializer for the given type.

        Args:
            field_type (django.db.models.fields): the field type for which we need to find a serializer

        Returns:
            rest_framework.serializers.ModelSerializer: The serializer if one has been found or None

        """
        # Check overrides first
        if serializer := self.serializer_overrides(field_type):
            return serializer

        # If the type is represented in the map then return the serializer
        if field_type in self._serializers:
            return self._serializers[field_type]

        # Otherwise we get the direct parent class and we recursively call the method
        # Note that this process will always terminate has we have a decreasing measure
        # with a lower bound taking the form of the object class which is referenced
        # in our serializers.
        parent_class = field_type.__mro__[1]
        return self._find_serializer(parent_class)

    def get_field_value_override(self, model_instance, field_name):
        """
        Allows us to override the default field value lookup functionality, e.g. for when we are migrating to new models
        while keeping the old names for API compatibility.

        :param model_instance: the model instance
        :param field_name: the name of the field we're getting a value for
        :return: a tuple of (the value of the field, whether the field is 'many'), or None if no override exists
        """
        if locations_enabled():
            if isinstance(model_instance, Finding) and field_name == "endpoints":
                return model_instance.locations, True
        return None

    def get_field_value(self, model_instance, field_name):
        """
        Returns the value of the given field from the model instance and whether the serializer used should treat the
        value as many.

        :param model_instance: the model instance
        :param field_name: the name of the field we're getting a value for
        :return: a tuple of (the value of the field, whether the field is 'many')
        """
        # Check overrides first
        if field_data := self.get_field_value_override(model_instance, field_name):
            return field_data

        # Get the concrete field type
        field_meta = getattr(type(model_instance), field_name, None)
        # Check if the field represents a to-many relationship as we need to instantiate the serializer accordingly.
        # Both many-to-many fields and the reverse side of a ForeignKey (one-to-many) resolve to a RelatedManager,
        # so both must be treated as 'many' -- otherwise the single-object path dereferences ``.pk`` on the manager.
        many = utils._is_many_to_many_relation(field_meta)
        if utils._is_one_to_many_relation(field_meta):
            # A reverse relation can be unbounded (``Test.finding_set``), so only the opted-in ones are served.
            if not utils.is_prefetchable_reverse_relation(type(model_instance), field_name):
                return None, False
            many = True
        # Get the field from the instance
        return getattr(model_instance, field_name, None), many

    def serializer_overrides(self, field_type):
        """
        Overrides for model serializers, e.g. for serializers not found in SERIALIZER_DEFS_MODULE

        :param field_type: the model field type
        :return: a serializer for the given model field type, or None if no override exists
        """
        return {
            Location: LocationSerializer,
            LocationFindingReference: LocationFindingReferenceSerializer,
            LocationProductReference: LocationProductReferenceSerializer,
        }.get(field_type)

    def get_prefetch_lookup(self, model_instance, field_name):
        """
        The ``prefetch_related`` lookup that loads ``field_name`` on ``model_instance``, mirroring
        ``get_field_value_override`` (under V3 a finding's ``endpoints`` are its ``locations``).
        """
        if locations_enabled() and isinstance(model_instance, Finding) and field_name == "endpoints":
            return "locations"
        return field_name

    def _prefetch(self, entry, fields_to_fetch):
        """
        Apply prefetching for the given field on the given entry

        Args:
            entry (ModelInstance): Instance of a model as returned by a django queryset
            field_to_fetch (list[string]): fields to prefetch

        """
        self.prefetch_entries([entry], fields_to_fetch)

    def prefetch_entries(self, entries, fields_to_fetch):
        """
        Apply prefetching for the given fields on a whole page of entries.

        Authorization and serialization run once per page rather than once per entry: the related
        ids of every entry are authorized with one query, and each distinct related object is
        serialized once. Doing this per entry cost an ``exists()`` and a full serialization of the
        same object on every row of a list response.

        Args:
            entries (list[ModelInstance]): Instances of a model as returned by a django queryset
            fields_to_fetch (list[string]): fields to prefetch

        """
        entries = list(entries)
        if not entries:
            return
        user = getattr(self._request, "user", None) if self._request else None
        for field_to_fetch in fields_to_fetch:
            self._prefetch_field(entries, field_to_fetch, user)

    def _load_relation(self, entries, field_to_fetch):
        """
        Load the relation behind ``field_to_fetch`` for every entry in one query, so reading it per entry
        does not query once per row. A relation the queryset already loaded is left as it is.
        """
        lookup = self.get_prefetch_lookup(entries[0], field_to_fetch)
        descriptor = getattr(type(entries[0]), lookup, None)
        if not isinstance(descriptor, (related.ForwardManyToOneDescriptor, related.ReverseManyToOneDescriptor)):
            return
        # Same allowlist as get_field_value: an unbounded reverse relation is never loaded
        if utils._is_one_to_many_relation(descriptor) and not utils.is_prefetchable_reverse_relation(type(entries[0]), lookup):
            return
        prefetch_related_objects(entries, lookup)

    def _related_values(self, entries, field_to_fetch):
        """The non-null related value of each entry, as ``(field_value, many)`` pairs in entry order."""
        if len(entries) > 1:
            self._load_relation(entries, field_to_fetch)
        values = []
        for entry in entries:
            field_value, many = self.get_field_value(entry, field_to_fetch)
            if field_value is not None:
                values.append((field_value, many))
        return values

    def _prefetch_field(self, entries, field_to_fetch, user):
        groups = {}
        for field_value, many in self._related_values(entries, field_to_fetch):
            # Get the model related to the field
            model_type = getattr(field_value, "model", type(field_value))
            groups.setdefault((model_type, many), []).append(field_value)

        for (model_type, many), field_values in groups.items():
            extra_serializer = self._find_serializer(model_type)
            if extra_serializer is None:
                continue

            # Authorization gate: only serialize objects from the requester's
            # authorized queryset for this model. Deny-by-default -- models
            # with no registered policy are omitted from the prefetch payload.
            authorized_qs = get_authorized_queryset(model_type, user)
            if authorized_qs is None:
                continue

            # Match the legacy contract: the field key always appears in the
            # prefetch payload (possibly empty) once we have a policy. Tests
            # and clients can rely on the key being present whenever the
            # primary field is non-null on the entry.
            self._prefetch_data.setdefault(field_to_fetch, {})

            # Serializers that read through a FK (``location.location_value``) would otherwise query once per row
            if select_related := _PREFETCH_SELECT_RELATED.get(model_type):
                authorized_qs = authorized_qs.select_related(*select_related)
            if prefetch_related := _PREFETCH_PREFETCH_RELATED.get(model_type):
                authorized_qs = authorized_qs.prefetch_related(*prefetch_related)

            serializer_kwargs = {"many": many}
            if self._request is not None:
                # Add in the request for the serializers to use if they want
                serializer_kwargs["context"] = {"request": self._request}

            if many:
                self._prefetch_many(field_to_fetch, field_values, authorized_qs, extra_serializer, serializer_kwargs)
            else:
                self._prefetch_single(field_to_fetch, field_values, authorized_qs, extra_serializer, serializer_kwargs)

    def _prefetch_many(self, field_to_fetch, field_values, authorized_qs, extra_serializer, serializer_kwargs):
        related_ids_per_entry = []
        for field_value in field_values:
            related_qs = field_value.all() if hasattr(field_value, "all") else field_value
            if getattr(related_qs, "_result_cache", None) is not None:
                related_ids_per_entry.append([obj.pk for obj in related_qs])
            else:
                related_ids_per_entry.append(list(related_qs.values_list("pk", flat=True)))
        all_ids = {pk for related_ids in related_ids_per_entry for pk in related_ids}
        if not all_ids:
            return
        # Serialize the objects the user has permission to, each once, in the authorized queryset's order
        authorized = list(authorized_qs.filter(pk__in=all_ids))
        if not authorized:
            return
        field_data = extra_serializer(**serializer_kwargs).to_representation(authorized)
        # Keyed by the serialized id: a list serializer that filters (VisibleNotesSerializer) may return fewer rows
        # than it was given, and an object it dropped is then left out of the payload rather than mismatched
        data_by_pk = {data["id"]: data for data in field_data}
        position = {obj.pk: index for index, obj in enumerate(authorized)}
        # Insert entry by entry, so the payload lists ids in the order a per-entry walk would
        for related_ids in related_ids_per_entry:
            for pk in sorted((pk for pk in set(related_ids) if pk in data_by_pk), key=position.__getitem__):
                data = data_by_pk[pk]
                self._prefetch_data[field_to_fetch][data["id"]] = data

    def _prefetch_single(self, field_to_fetch, field_values, authorized_qs, extra_serializer, serializer_kwargs):
        # Only a single related item per entry; keep the ones in the set of authorized objects
        authorized_ids = set(authorized_qs.filter(pk__in={value.pk for value in field_values}).values_list("pk", flat=True))
        serialized = set()
        for field_value in field_values:
            if field_value.pk not in authorized_ids or field_value.pk in serialized:
                continue
            serialized.add(field_value.pk)
            # Serialize the entry's own instance, which carries whatever the queryset prefetched on it
            data = extra_serializer(**serializer_kwargs).to_representation(field_value)
            self._prefetch_data[field_to_fetch][data["id"]] = data

    @property
    def prefetched_data(self):
        return self._prefetch_data
