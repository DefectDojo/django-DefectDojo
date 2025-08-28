from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework.exceptions import ValidationError
from rest_framework.serializers import (
    ModelSerializer,
    Serializer,
)

if TYPE_CHECKING:
    from collections import OrderedDict

    from django.db.models import Model

    from dojo.base_models.base import T


class SnubSerializer(Serializer):
    pass


class BaseModelSerializer(ModelSerializer):

    """Base serializer for all models."""

    def get_request_method(self) -> str:
        """Return the method of the request."""
        return self.context.get("request").method

    def remove_internal_fields(self, fields: dict) -> None:
        """Remove a list of internally defined fields that should never be exposed to the user."""
        # Fetch the list of fields from the serializer
        internal_fields = getattr(self, "internal_fields", [])
        # Remove them from the field dict
        for field in internal_fields:
            fields.pop(field, None)

    def get_fields(self) -> OrderedDict:
        """Exclude all internal fields by default."""
        fields = super().get_fields()
        # Remove the internal fields
        self.remove_internal_fields(fields)

        return fields

    def process_nested_serializer(
        self,
        serializer_class: type[BaseModelSerializer],
        object_data: dict | None,
        instance: Model | None,
    ) -> T | None:
        """Process nested serializers in a generic way."""
        # Short circuit if given incorrect data
        if object_data is None or object_data == {}:
            return None
        # Check the method is an expected value
        method = self.get_request_method()
        if method not in {"POST", "PATCH", "PUT"}:
            msg = "The `method` method must be one of `POST`, `PATCH`, or `PUT`..."
            raise ValidationError(msg)
        # Check the method has what it needs
        if instance is None and method in {"PATCH", "PUT"}:
            msg = "When using the `PUT` or `PATCH` method, you must also supply the instance to update..."
            raise ValidationError(msg)
        # Initialize the serializer class
        unsaved_object = serializer_class(data=object_data, partial=(method == "PATCH"))
        # Validate the object with the serializer class
        if not unsaved_object.is_valid():
            raise ValidationError(unsaved_object.errors)
        # Determine the args to pass based on the method to call
        object_instance = None
        if method == "POST":
            object_instance = unsaved_object.create(validated_data=unsaved_object.validated_data)
        elif method in {"PATCH", "PUT"}:
            object_instance = unsaved_object.update(
                instance=instance,
                validated_data=unsaved_object.validated_data,
            )

        return object_instance
