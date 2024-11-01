import logging
from datetime import datetime
from functools import wraps
from pprint import pformat as pp
from typing import Any, Callable, List, Optional

from django.contrib.auth.models import User
from django.db.models import Model
from django.utils import timezone
from django.utils.functional import SimpleLazyObject

from dojo.models import (
    Development_Environment,
    Dojo_User,
    Endpoint,
    Engagement,
    Finding,
    Product_API_Scan_Configuration,
    Test,
    Test_Import,
)
from dojo.utils import get_current_user, is_finding_groups_enabled

logger = logging.getLogger(__name__)


class ImporterOptions:

    """
    Converts the supplied kwargs into a class for global mutability
    as well as making it more clear which fields are used in each
    function.
    """

    def __init__(
        self,
        *args: list,
        **kwargs: dict,
    ):
        self.load_base_options(*args, **kwargs)
        self.load_additional_options(*args, **kwargs)
        self.field_names = list(self.__dict__.keys())

    def load_base_options(
        self,
        *args: list,
        **kwargs: dict,
    ):
        self.active: bool = self.validate_active(*args, **kwargs)
        self.api_scan_configuration: Product_API_Scan_Configuration | None = self.validate_api_scan_configuration(*args, **kwargs)
        self.apply_tags_to_endpoints: bool = self.validate_apply_tags_to_endpoints(*args, **kwargs)
        self.apply_tags_to_findings: bool = self.validate_apply_tags_to_findings(*args, **kwargs)
        self.branch_tag: str = self.validate_branch_tag(*args, **kwargs)
        self.build_id: str = self.validate_build_id(*args, **kwargs)
        self.close_old_findings_toggle: bool = self.validate_close_old_findings(*args, **kwargs)
        self.close_old_findings_product_scope: bool = self.validate_close_old_findings_product_scope(*args, **kwargs)
        self.do_not_reactivate: bool = self.validate_do_not_reactivate(*args, **kwargs)
        self.commit_hash: str = self.validate_commit_hash(*args, **kwargs)
        self.create_finding_groups_for_all_findings: bool = self.validate_create_finding_groups_for_all_findings(*args, **kwargs)
        self.endpoints_to_add: List[Endpoint] | None = self.validate_endpoints_to_add(*args, **kwargs)
        self.engagement: Engagement | None = self.validate_engagement(*args, **kwargs)
        self.environment: Development_Environment | None = self.validate_environment(*args, **kwargs)
        self.group_by: str = self.validate_group_by(*args, **kwargs)
        self.import_type: str = self.validate_import_type(*args, **kwargs)
        self.lead: Dojo_User | None = self.validate_lead(*args, **kwargs)
        self.minimum_severity: str = self.validate_minimum_severity(*args, **kwargs)
        self.parsed_findings: List[Finding] | None = self.validate_parsed_findings(*args, **kwargs)
        self.push_to_jira: bool = self.validate_push_to_jira(*args, **kwargs)
        self.scan_date: datetime = self.validate_scan_date(*args, **kwargs)
        self.scan_type: str = self.validate_scan_type(*args, **kwargs)
        self.service: str = self.validate_service(*args, **kwargs)
        self.tags: List[str] = self.validate_tags(*args, **kwargs)
        self.test: Test | None = self.validate_test(*args, **kwargs)
        self.user: Dojo_User | None = self.validate_user(*args, **kwargs)
        self.test_title: str = self.validate_test_title(*args, **kwargs)
        self.verified: bool = self.validate_verified(*args, **kwargs)
        self.version: str = self.validate_version(*args, **kwargs)

    def load_additional_options(
        self,
        *args: list,
        **kwargs: dict,
    ):
        """
        An added hook for loading additional options
        to be used by children classes for the BaseImporter
        """

    def log_translation(
        self,
        header_message: Optional[str] = None,
    ):
        if header_message is not None:
            logger.debug(header_message)
        for field in self.field_names:
            logger.debug(f"{field}: {getattr(self, field)}")

    def _compress_decorator(function):
        @wraps(function)
        def inner_compress_function(*args, **kwargs):
            args[0].compress_options()
            return function(*args, **kwargs)
        return inner_compress_function

    def _decompress_decorator(function):
        @wraps(function)
        def inner_decompress_function(*args, **kwargs):
            args[0].decompress_options()
            return function(*args, **kwargs)
        return inner_decompress_function

    def compress_options(self):
        compressed_fields = {}
        for field in self.field_names:
            value = getattr(self, field)
            # Get everything that is not a model
            if isinstance(value, Model):
                # Grab the ID of the model
                compressed_fields[field] = (type(value), value.id)
            # Accommodate lists of fields
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], Model):
                id_list = [item.id for item in value]
                item_type = type(value[0])
                class_name = None
                # Get the actual class if available
                if len(id_list) > 0:
                    id_type = type(id_list[0])
                    # Only define the class name if we are able to make a query on the object in decompression
                    if isinstance(id_type, int):
                        class_name = item_type if item_type is None else id_type
                # Ensure we are not setting a class name as None
                if class_name is type(None) or class_name is None:
                    compressed_fields[field] = value
                # Add the list to the dict
                else:
                    compressed_fields[field] = (class_name, id_list)
                # Check if we are working with a list of models
            # If the type is None (for unsaved objects) we do not need to do anything special
            else:
                # Must be a primitive
                compressed_fields[field] = value
        self.set_dict_fields(compressed_fields)
        # self.log_translation(header_message="Compressed Options:")

    def decompress_options(self):
        decompressed_fields = {}
        for field in self.field_names:
            value = getattr(self, field)
            # Get everything that is not a model
            if isinstance(value, tuple):
                class_name, model_value = value
                # Accommodate for model lists
                if isinstance(model_value, list):
                    if class_name is type(None):
                        model_list = model_value
                    else:
                        model_list = list(class_name.objects.filter(id__in=model_value))
                    decompressed_fields[field] = model_list
                elif isinstance(model_value, int):
                    # Check for SimpleLazyObject that will be user objects
                    if class_name is SimpleLazyObject:
                        decompressed_fields[field] = Dojo_User.objects.get(id=model_value)
                    else:
                        decompressed_fields[field] = class_name.objects.get(id=model_value)
                else:
                    msg = f"Unexpected compressed value: {field} - {value}"
                    raise TypeError(msg)
            else:
                # Must be a primitive
                decompressed_fields[field] = value
        self.set_dict_fields(decompressed_fields)
        # self.log_translation(header_message="Decompressed Options:")

    def set_dict_fields(
        self,
        fields: dict,
    ):
        for field_name, value in fields.items():
            setattr(self, field_name, value)

    def validate(
        self,
        field_name: str,
        expected_types: List[Callable] = [],
        *,
        required: bool = False,
        default: Any = None,
        **kwargs: dict,
    ) -> Any | None:
        """
        Safely gets the value of a model object from the kwargs
        and ensures it is the correct type before returning it
        """
        # Get the value from the kwargs
        value = kwargs.get(field_name, None)
        # Make sure we have something if we need it
        if required is True:
            if value is None:
                msg = (
                    f"{field_name} is required when using an importer class\n"
                    f"Here are all the options submitted:\n{pp(kwargs)}"
                )
                raise ValueError(msg)
        # Check for the type constraint if supplied
        if len(expected_types) > 0 and value is not None:
            value_type = type(value)
            if value_type not in expected_types:
                msg = (
                    f"{field_name} of type {value_type} is not one of {expected_types}\n"
                    f"Here are all the options submitted:\n{pp(kwargs)}"
                )
                raise ValueError(msg)
        # Final check to return a default in the event the value was not found
        if default is not None and value is None:
            value = default

        return value

    def validate_active(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "active",
            expected_types=[bool],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_api_scan_configuration(
        self,
        *args: list,
        **kwargs: dict,
    ) -> Product_API_Scan_Configuration | None:
        return self.validate(
            "api_scan_configuration",
            expected_types=[Product_API_Scan_Configuration],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_apply_tags_to_endpoints(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "apply_tags_to_endpoints",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_apply_tags_to_findings(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "apply_tags_to_findings",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_branch_tag(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "branch_tag",
            expected_types=[str],
            required=False,
            default="",
            **kwargs,
        )

    def validate_build_id(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "build_id",
            expected_types=[str],
            required=False,
            default="",
            **kwargs,
        )

    def validate_close_old_findings(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "close_old_findings",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_close_old_findings_product_scope(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "close_old_findings_product_scope",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_do_not_reactivate(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "do_not_reactivate",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_commit_hash(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "commit_hash",
            expected_types=[str],
            required=False,
            default="",
            **kwargs,
        )

    def validate_create_finding_groups_for_all_findings(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "create_finding_groups_for_all_findings",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_endpoints_to_add(
        self,
        *args: list,
        **kwargs: dict,
    ) -> list | None:
        return self.validate(
            "endpoints_to_add",
            expected_types=[list],
            required=False,
            default=[],
            **kwargs,
        )

    def validate_engagement(
        self,
        *args: list,
        **kwargs: dict,
    ) -> Engagement | None:
        return self.validate(
            "engagement",
            expected_types=[Engagement],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_environment(
        self,
        *args: list,
        **kwargs: dict,
    ) -> Development_Environment | None:
        return self.validate(
            "environment",
            expected_types=[Development_Environment],
            required=True,
            default=None,
            **kwargs,
        )

    def validate_group_by(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        self.findings_groups_enabled: bool = is_finding_groups_enabled()
        return self.validate(
            "group_by",
            expected_types=[str],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_import_type(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "import_type",
            expected_types=[str],
            required=False,
            default=Test_Import.IMPORT_TYPE,
            **kwargs,
        )

    def validate_lead(
        self,
        *args: list,
        **kwargs: dict,
    ) -> Dojo_User | None:
        return self.validate(
            "lead",
            expected_types=[User, Dojo_User, SimpleLazyObject],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_minimum_severity(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "minimum_severity",
            expected_types=[str],
            required=False,
            default="Info",
            **kwargs,
        )

    def validate_parsed_findings(
        self,
        *args: list,
        **kwargs: dict,
    ) -> list | None:
        return self.validate(
            "parsed_findings",
            expected_types=[list],
            required=False,
            default=[],
            **kwargs,
        )

    def validate_push_to_jira(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "push_to_jira",
            expected_types=[bool],
            required=False,
            default=False,
            **kwargs,
        )

    def validate_scan_date(
        self,
        *args: list,
        **kwargs: dict,
    ) -> datetime:
        self.now = timezone.now()
        value = self.validate(
            "scan_date",
            expected_types=[datetime],
            required=False,
            default=self.now,
            **kwargs,
        )
        # Set an additional flag to indicate an override was made
        self.scan_date_override = (self.now != value)
        # Set the timezones appropriately
        if value is not None and not value.tzinfo:
            value = timezone.make_aware(value)

        return value

    def validate_scan_type(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "scan_type",
            expected_types=[str],
            required=True,
            default=None,
            **kwargs,
        )

    def validate_service(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "service",
            expected_types=[str],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_tags(
        self,
        *args: list,
        **kwargs: dict,
    ) -> list:
        return self.validate(
            "tags",
            expected_types=[list],
            required=False,
            default=[],
            **kwargs,
        )

    def validate_test(
        self,
        *args: list,
        **kwargs: dict,
    ) -> Test | None:
        return self.validate(
            "test",
            expected_types=[Test],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_test_title(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "test_title",
            expected_types=[str],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_user(
        self,
        *args: list,
        **kwargs: dict,
    ) -> Dojo_User | None:
        return self.validate(
            "user",
            expected_types=[User, Dojo_User, SimpleLazyObject],
            required=False,
            default=get_current_user(),
            **kwargs,
        )

    def validate_verified(
        self,
        *args: list,
        **kwargs: dict,
    ) -> bool:
        return self.validate(
            "verified",
            expected_types=[bool],
            required=False,
            default=None,
            **kwargs,
        )

    def validate_version(
        self,
        *args: list,
        **kwargs: dict,
    ) -> str:
        return self.validate(
            "version",
            expected_types=[str],
            required=False,
            default="",
            **kwargs,
        )
