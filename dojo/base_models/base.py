import contextlib
import logging
from typing import TypeVar

from django.conf import settings
from django.db.models import DateTimeField, Manager, Model, QuerySet
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

# Type variable for the model
T = TypeVar("T", bound="BaseModelWithoutTimeMeta")


class BaseQuerySet(QuerySet):

    """Base Queryset to add chainable queries."""

    def order_by_id(self, *field_names: str):
        return super().order_by("id")


class BaseManager(Manager):

    """Base manager to manipulate all objects with."""

    QUERY_SET_CLASS = BaseQuerySet

    def get_queryset(self) -> QuerySet[T]:
        return self.QUERY_SET_CLASS(self.model, using=self._db).order_by_id()


class BaseModelWithoutTimeMeta(Model):

    """Base model class that all models will extend."""

    objects = BaseManager()

    class Meta:

        """Meta class for the base model."""

        abstract = True

    def save(self, *args: list, skip_validation: bool = not settings.V3_FEATURE_LOCATIONS, **kwargs: dict) -> None:
        """
        Override save method to call the `full_clean()` validation function each save.

        The `full_clean` function is also called here to perform validation on the model in
        various places. Here is the name, and a brief description for each function:
        - Validate the model fields - `clean_fields()`
        - Validate the model as a whole - `clean()`
        - Validate the field uniqueness - `validate_unique()`
        All three steps are performed when you call a model's full_clean() method in the order above
        """
        # Run the pre save logic, if enabled
        self.pre_save_logic()
        # Call the validations
        if not skip_validation:
            try:
                self.full_clean()
            except Exception:
                self.print_all_fields()
                raise
        # Run the post save logic, if enabled
        self.post_save_logic()
        # Call the base save method to save the model to the database
        super().save(*args, **kwargs)

    def pre_save_logic(self) -> None:
        """Allow for some pre save operations by other classes."""

    def post_save_logic(self) -> None:
        """Allow for some post save operations by other classes."""

    def print_all_fields(self) -> None:
        """Query all fields, and then print them in an easy to read fashion."""
        with contextlib.suppress(ValueError):
            fields = [f.name for f in self._meta.get_fields()]
            logger.debug(f"\n\n-- {self._meta.object_name} --")
            for field in fields:
                logger.debug(f"\t {field}: {getattr(self, field, 'Unable to access')}")


class BaseModel(BaseModelWithoutTimeMeta):

    """Base model class that all models will extend, but with created/updated timestamps."""

    created = DateTimeField(
        verbose_name=_("Created"),
        auto_now_add=True,
        null=True,  # This will never happen, but it fits what the current model defines
        help_text=_("Time that the object was initially created, and saved to the database"),
    )
    updated = DateTimeField(
        verbose_name=_("Updated"),
        auto_now=True,
        null=True,  # This will never happen, but it fits what the current model defines
        help_text=_("Time that the object was most recently saved to the database"),
    )

    class Meta:

        """Meta class for the base model."""

        abstract = True
