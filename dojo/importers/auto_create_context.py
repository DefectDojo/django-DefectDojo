import logging
from datetime import datetime, timedelta
from typing import Any

from crum import get_current_user
from django.db import transaction
from django.http.request import QueryDict
from django.utils import timezone

from dojo.models import (
    Engagement,
    Product,
    Product_Member,
    Product_Type,
    Product_Type_Member,
    Role,
    Test,
)
from dojo.utils import get_last_object_or_none, get_object_or_none

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class AutoCreateContextManager:

    """
    Management of safely fetching and creating resources used in the import
    and reimport processes. Resources managed by this class are:
    - Product Types
    - Products
    - Engagements
    - Tests
    """

    """
    ===================================
    ----------- Validators ------------
    ===================================
    """
    def process_object_fields(
        self,
        key: str,
        label: str,
        object_type: Any,
        data: dict,
        **kwargs: dict,
    ) -> None:
        """
        Process the object fields such as product, engagement, and
        test such that passing the whole object, or just the ID
        will suffice
        """
        if object_id := data.get(key):
            # Convert to just the ID if the whole object as passed
            if isinstance(object_id, object_type):
                object_id = object_id.id
            # Convert to a string if needed
            if isinstance(object_id, list) and len(object_id) > 0:
                object_id = object_id[0]
            # Ensure the ID is an integer, not a string
            elif isinstance(object_id, str) and not object_id.isdigit():
                msg = f"{key} must be an integer"
                raise ValueError(msg)
            # Update the "test" entry in the dict with the ID
            data[label] = object_id

    def process_object_name(
        self,
        key: str,
        data: dict,
        **kwargs: dict,
    ) -> None:
        """
        Process the object names by ensuring that the inputs
        are a string and not a list of strings
        """
        if object_name := data.get(key):
            # Convert to a string if needed
            if isinstance(object_name, list) and len(object_name) > 0:
                data[key] = object_name[0]

    def process_import_meta_data_from_dict(
        self,
        data: dict,
        **kwargs: dict,
    ) -> None:
        """
        Ensure that the inputs supplied for test and engagement can be
        derive into am integer ID. This can happen if a full Test or
        Engagement is supplied, or if the input is an integer ID to
        start with
        """
        # Validate the test artifact
        self.process_object_fields("test", "test_id", Test, data)
        # Validate the engagement artifact
        self.process_object_fields("engagement", "engagement_id", Engagement, data)
        # Validate the product artifact
        self.process_object_fields("product", "product_id", Product, data)
        # Validate the product_type_name
        self.process_object_name("product_type_name", data)
        # Validate the product_name
        self.process_object_name("product_name", data)
        # Validate the engagement_name
        self.process_object_name("engagement_name", data)
        # Validate the test_title
        self.process_object_name("test_title", data)

    """
    ===================================
    ------------ Fetchers -------------
    ===================================
    """
    def get_target_product_type_if_exists(
        self,
        product_type_name: str | None = None,
        **kwargs: dict,
    ) -> Product_Type | None:
        """
        Query for a product type that matches the name `product_type_name`.

        If a match is not found, return None
        """
        # Look for an existing object
        if product_type_name:
            return get_object_or_none(Product_Type, name=product_type_name)
        return None

    def get_target_product_if_exists(
        self,
        product_name: str | None = None,
        product_type_name: str | None = None,
        **kwargs: dict,
    ) -> Product | None:
        """
        Query for a product that matches the name `product_name`. Some
        extra verification is also administered to ensure the
        `product_type_name` matches the one on the fetched product

        If a match is not found, return None
        """
        # Look for an existing object
        if product_name and (product := get_object_or_none(Product, name=product_name)):
            # product type name must match if provided
            if product_type_name and product.prod_type.name != product_type_name:
                msg = (
                    "The fetched product has a conflict with the supplied product type name: "
                    f"existing product type name - {product.prod_type.name} vs "
                    f"supplied product type name - {product_type_name}"
                )
                raise ValueError(msg)
            # Return the product
            return product
        return None

    def get_target_product_by_id_if_exists(
        self,
        product_id: int = 0,
        **kwargs: dict,
    ) -> Product | None:
        """
        Query for a product matching by ID

        If a match is not found, return None
        """
        return get_object_or_none(Product, pk=product_id)

    def get_target_engagement_if_exists(
        self,
        engagement_id: int = 0,
        engagement_name: str | None = None,
        product: Product = None,
        **kwargs: dict,
    ) -> Engagement | None:
        """
        Query for an engagement matching by ID. If a match is not found,
        and a product is supplied, return the last engagement created on
        the product by name

        If a match is not found, and a product is not supplied, return None
        """
        if engagement := get_object_or_none(Engagement, pk=engagement_id):
            logger.debug("Using existing engagement by id: %s", engagement_id)
            return engagement
        # if there's no product, then for sure there's no engagement either
        if product is None:
            return None
        # engagement name is not unique unfortunately
        return get_last_object_or_none(Engagement, product=product, name=engagement_name)

    def get_target_test_if_exists(
        self,
        test_id: int = 0,
        test_title: str | None = None,
        scan_type: str | None = None,
        engagement: Engagement = None,
        **kwargs: dict,
    ) -> Test | None:
        """
        Retrieves the target test to reimport. This can be as simple as looking up the test via the `test_id` parameter.
        If there is no `test_id` provided, we lookup the latest test inside the provided engagement that satisfies
        the provided scan_type and test_title.
        """
        if test := get_object_or_none(Test, pk=test_id):
            logger.debug("Using existing Test by id: %s", test_id)
            return test
        # If the engagement is not supplied, we cannot do anything
        if not engagement:
            return None
        # Check for a custom test title
        if test_title:
            return get_last_object_or_none(Test, engagement=engagement, title=test_title, scan_type=scan_type)
        # Otherwise use the last test by scan type
        return get_last_object_or_none(Test, engagement=engagement, scan_type=scan_type)

    """
    ===================================
    ------------ Creators -------------
    ===================================
    """
    def get_or_create_product_type(
        self,
        product_type_name: str | None = None,
        **kwargs: dict,
    ) -> Product_Type:
        """
        Fetches a product type by name if one already exists. If not,
        a new product type will be created with the current user being
        added as product type member
        """
        # Look for an existing object
        if product_type := self.get_target_product_type_if_exists(product_type_name=product_type_name):
            return product_type
        with transaction.atomic():
            product_type, created = Product_Type.objects.select_for_update().get_or_create(name=product_type_name)
            if created:
                Product_Type_Member.objects.create(
                    user=get_current_user(),
                    product_type=product_type,
                    role=Role.objects.get(is_owner=True),
                )
            return product_type

    def get_or_create_product(
        self,
        product_name: str | None = None,
        product_type_name: str | None = None,
        *,
        auto_create_context: bool = False,
        **kwargs: dict,
    ) -> Product:
        """
        Fetches a product by name if it exists. When `auto_create_context` is
        enabled the product will be created with the current user being added
        as product member
        """
        # try to find the product (within the provided product_type)
        if product := self.get_target_product_if_exists(product_name, product_type_name):
            return product
        # not found .... create it
        if not auto_create_context:
            msg = "auto_create_context not True, unable to create non-existing product"
            raise ValueError(msg)
        # Look for a product type first
        product_type = self.get_or_create_product_type(product_type_name=product_type_name)
        # Create the product
        with transaction.atomic():
            product, created = Product.objects.select_for_update().get_or_create(name=product_name, prod_type=product_type, description=product_name)
            if created:
                Product_Member.objects.create(
                    user=get_current_user(),
                    product=product,
                    role=Role.objects.get(is_owner=True),
                )

        return product

    def get_or_create_engagement(
        self,
        engagement_id: int = 0,
        engagement_name: str | None = None,
        product_name: str | None = None,
        product_type_name: str | None = None,
        *,
        auto_create_context: bool = False,
        deduplication_on_engagement: bool = False,
        source_code_management_uri: str | None = None,
        target_end: datetime | None = None,
        **kwargs: dict,
    ) -> Engagement:
        """Fetches an engagement by name or ID if one already exists."""
        # try to find the engagement (and product)
        product = self.get_target_product_if_exists(
            product_name=product_name,
            product_type_name=product_type_name,
        )
        engagement = self.get_target_engagement_if_exists(
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            product=product,
        )
        # If we have an engagement, we cna just return it
        if engagement:
            return engagement
        # not found .... create it
        if not auto_create_context:
            msg = "auto_create_context not True, unable to create non-existing engagement"
            raise ValueError(msg)
        # Get a product first
        product = self.get_or_create_product(
            product_name=product_name,
            product_type_name=product_type_name,
            auto_create_context=auto_create_context,
        )
        # Get the target start date in order
        target_start = timezone.now().date()
        if (target_end is None) or (target_start > target_end):
            target_end = (timezone.now() + timedelta(days=365)).date()
        # Create the engagement
        with transaction.atomic():
            return Engagement.objects.select_for_update().create(
                engagement_type="CI/CD",
                name=engagement_name,
                product=product,
                lead=get_current_user(),
                target_start=target_start,
                target_end=target_end,
                status="In Progress",
                deduplication_on_engagement=deduplication_on_engagement,
                source_code_management_uri=source_code_management_uri,
            )

    """
    ===================================
    ------------ Utilities ------------
    ===================================
    """
    def convert_querydict_to_dict(
        self,
        query_dict_data: QueryDict,
    ) -> dict:
        """
        Creates a copy of a query dict, and then converts it
        to a dict
        """
        # First copy the query dict
        copy = {}
        # Iterate ovr the dict and extract the elements based
        # on whether they are a single item, or a list
        for key, value in query_dict_data.items():
            if value:
                # Accommodate lists
                if isinstance(value, list):
                    copy[key] = value if len(value) > 1 else value[0]
                else:
                    copy[key] = value
        # Convert to a regular dict
        return copy
