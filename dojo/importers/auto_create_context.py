import logging
from datetime import datetime, timedelta
from typing import Any

from django.db import transaction
from django.http.request import QueryDict
from django.utils import timezone

from dojo.importers.test_type_names import accepted_test_type_names
from dojo.models import (
    Engagement,
    Product,
    Product_Type,
    Test,
)
from dojo.tools.factory import get_parser
from dojo.utils import get_current_user, get_last_object_or_none, get_object_or_none

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

    One request resolves the same target in the permission check, the view and the
    serializer. ``for_request`` hands all three the same manager, which remembers the
    rows it found so each lookup runs once per request. A miss is never remembered:
    the creators look again before they create, as they always have.
    """

    _REQUEST_ATTRIBUTE = "_dojo_auto_create_context_manager"

    def __init__(self) -> None:
        self._found: dict[tuple, Any] = {}
        # (report file, the test type names it accepts): the permission check and the serializer
        # resolve the same upload, so the report is read for its tool once per request.
        self._report_test_types: list[tuple[Any, frozenset[str] | None]] = []

    @classmethod
    def for_request(cls, request) -> "AutoCreateContextManager":
        """The manager shared by everything that handles ``request`` (a new one without a request)."""
        if request is None:
            return cls()
        manager = getattr(request, cls._REQUEST_ATTRIBUTE, None)
        if manager is None:
            manager = cls()
            setattr(request, cls._REQUEST_ATTRIBUTE, manager)
        return manager

    def _remembered(self, key: tuple, lookup):
        """``lookup()``, run once per ``key`` while it finds something."""
        if (found := self._found.get(key)) is not None:
            return found
        if (found := lookup()) is not None:
            self._found[key] = found
        return found

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
            return self._remembered(
                ("product_type", product_type_name),
                lambda: get_object_or_none(Product_Type, name=product_type_name),
            )
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
        if product_name and (product := self._remembered(
            ("product", product_name),
            lambda: get_object_or_none(Product.objects.select_related("prod_type"), name=product_name),
        )):
            # product type name must match if provided
            if product_type_name and product.prod_type.name != product_type_name:
                msg = (
                    "The fetched product has a conflict with the supplied product type name: "
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
        if engagement_id and (engagement := self._remembered(
            ("engagement", engagement_id),
            lambda: get_object_or_none(Engagement.objects.select_related("product__prod_type"), pk=engagement_id),
        )):
            logger.debug("Using existing engagement by id: %s", engagement_id)
            if product is not None and engagement.product_id != product.id:
                msg = "The provided identifiers are inconsistent — the engagement does not belong to the specified product."
                raise ValueError(msg)
            return engagement
        # if there's no product, then for sure there's no engagement either
        if product is None:
            return None
        # engagement name is not unique unfortunately
        return self._remembered(
            ("engagement", product.pk, engagement_name),
            lambda: get_last_object_or_none(Engagement.objects.select_related("product__prod_type"), product=product, name=engagement_name),
        )

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
        the provided scan_type and test_title. When the report is passed (``scan``, or ``file`` as the
        API request names it) and its parser names the test type from the report, a title lookup only
        matches a test of that report's tool (``report_test_type_names``).
        """
        if test_id and (test := self._remembered(
            ("test", test_id),
            lambda: get_object_or_none(Test.objects.select_related("engagement__product__prod_type"), pk=test_id),
        )):
            logger.debug("Using existing Test by id: %s", test_id)
            if engagement is not None and test.engagement_id != engagement.id:
                msg = "The provided identifiers are inconsistent — the test does not belong to the specified engagement."
                raise ValueError(msg)
            return test
        # If the engagement is not supplied, we cannot do anything
        if not engagement:
            return None
        # Check for a custom test title
        if test_title:
            tests = Test.objects.select_related("engagement__product__prod_type").filter(engagement=engagement, title=test_title, scan_type=scan_type)
            # One scan type can carry reports from several tools (GitLab SAST, SARIF, Generic), each
            # imported into a test of its own tool's type. Narrow to the report's tool, or a second
            # tool sharing the title would reimport into the first tool's test.
            if (
                (scan := kwargs.get("scan") or kwargs.get("file")) is not None
                and tests.exists()
                and (test_type_names := self.report_test_type_names(scan_type, scan)) is not None
            ):
                return self._remembered(
                    ("test", engagement.pk, scan_type, test_title, test_type_names),
                    lambda: get_last_object_or_none(tests, test_type__name__in=test_type_names),
                )
            return self._remembered(
                ("test", engagement.pk, scan_type, test_title),
                lambda: get_last_object_or_none(tests),
            )
        # Otherwise use the last test by scan type
        return self._remembered(
            ("test", engagement.pk, scan_type),
            lambda: get_last_object_or_none(Test.objects.select_related("engagement__product__prod_type"), engagement=engagement, scan_type=scan_type),
        )

    def report_test_type_names(self, scan_type: str | None, scan: Any) -> frozenset[str] | None:
        """
        The Test_Type names a test may carry to take a reimport of ``scan``, or None when any test may.

        Only a parser that names the test type from the report (``get_tests``) has a tool to match;
        a report that describes no test, or that the parser cannot read, is left to the importer,
        which reports the error. The file is rewound, so the importer reads it from the start.
        """
        for seen, names in self._report_test_types:
            if seen is scan:
                return names
        names = self._read_report_test_type_names(scan_type, scan)
        self._report_test_types.append((scan, names))
        return names

    @staticmethod
    def _read_report_test_type_names(scan_type: str | None, scan: Any) -> frozenset[str] | None:
        try:
            parser = get_parser(scan_type)
        except ValueError:
            return None
        if not hasattr(parser, "get_tests"):
            return None
        try:
            tests = parser.get_tests(scan_type, scan)
        except Exception:  # any parser error is the importer's to report, with its own handling
            logger.debug("Could not read the test type of a %s report before resolving its test", scan_type, exc_info=True)
            return None
        finally:
            scan.seek(0)
        if not tests:
            return None
        return frozenset(accepted_test_type_names(tests[0].type, scan_type))

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
        a new product type will be created. RBAC ownership of the new row
        is bootstrapped by Pro's post_save signal on Product_Type.
        """
        # Look for an existing object
        if product_type := self.get_target_product_type_if_exists(product_type_name=product_type_name):
            return product_type
        with transaction.atomic():
            product_type, _created = Product_Type.objects.select_for_update().get_or_create(name=product_type_name)
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
        enabled the product will be created. RBAC ownership of the new row is
        bootstrapped by Pro's post_save signal on Product.
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
            # Only `name` is a lookup: it is the column that is actually unique. `prod_type`
            # and `description` were lookup kwargs historically, so a row a concurrent request
            # had just committed did not match here, making this attempt a CREATE that then
            # lost to the unique index -- and get_or_create's recovery get() reuses the same
            # lookup, so it missed that row too and re-raised. Callers reach this line only
            # when the name looked free, so the symptom was an IntegrityError whenever two
            # imports raced through that gap.
            product, _created = Product.objects.select_for_update().get_or_create(
                name=product_name,
                defaults={
                    "prod_type": product_type,
                    "description": product_name,
                },
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
            # Lock the parent product row to serialize engagement creation per product
            locked_product = Product.objects.select_for_update().get(pk=product.pk)
            # Re-check for an existing engagement now that we hold the lock
            existing = get_last_object_or_none(Engagement, product=locked_product, name=engagement_name)
            if existing:
                return existing
            return Engagement.objects.create(
                engagement_type="CI/CD",
                name=engagement_name,
                product=locked_product,
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
        # Trim names the way the serializers' CharFields do, so a permission check
        # resolves the same objects the import later uses
        for key in ("product_type_name", "product_name", "engagement_name", "test_title"):
            if isinstance(copy.get(key), str):
                copy[key] = copy[key].strip()
        # Convert to a regular dict
        return copy
