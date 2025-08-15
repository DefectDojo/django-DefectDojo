"""
This module provides a centralized location for application copy.

Class _K defines the keys used to refer to the copy in application code/templates. The labels dictionaries define
translatable copy entries for each of these keys. As the creation of this whole thing was to facilitate the migration of
Dojo terminology, two dictionaries are provided, one each for v2 and v3 terminology. Translators can provide translated
text for both versions of terminology as desired.

New copy can be added by doing the following:
    * Add a new attribute to _K
    * Add entries for the new attribute to the version dictionaries
    * Use it:
        * In templates, a `label` context processor has been added, so you can just use labels.ATTRIBUTE_NAME
        * In views/Python code, first import get_labels() and set it to a variable (e.g., labels = get_labels()). Then
            you can simply use labels.ATTRIBUTE_NAME

Some conventions used:
    Each copy attribute name starts with a noun representing the overarching model/object type the label is for.
    Attribute suffixes are as follows:
        _LABEL -> short label, used for UI/API fields
        _MESSAGE -> a longer message displayed as a toast or displayed on the page
        _HELP -> helptext (for help_text kwargs/popover content)
"""
import logging

from django.utils.functional import lazy
from django.utils.translation import gettext_lazy as _

from dojo.v3_migration import v3_migration_enabled

logger = logging.getLogger(__name__)


class _K:

    """Directory of text copy used throughout the app."""

    ORG_LABEL = "org.label"
    ORG_PLURAL_LABEL = "org.plural_label"
    ORG_ALL_LABEL = "org.all_label"
    ORG_WITH_NAME_LABEL = "org.with_name_label"
    ORG_NONE_FOUND_MESSAGE = "org.none_found_label"
    ORG_REPORT_LABEL = "org.report_label"
    ORG_REPORT_TITLE = "org.report_title"
    ORG_REPORT_WITH_NAME_TITLE = "org.report_with_name_title"
    ORG_METRICS_LABEL = "org.metrics.label"
    ORG_METRICS_COUNTS_LABEL = "org.metrics.counts_label"
    ORG_METRICS_BY_FINDINGS_LABEL = "org.metrics_by_findings_label"
    ORG_METRICS_BY_ENDPOINTS_LABEL = "org.metrics_by_endpoints_label"
    ORG_METRICS_TYPE_COUNTS_ERROR_MESSAGE = "org.metrics_type_counts_error_message"
    ORG_OPTIONS_LABEL = "org.options_label"
    ORG_NOTIFICATION_WITH_NAME_CREATED_MESSAGE = "org.notification_with_name_created_message"
    ORG_CRITICAL_PRODUCT_LABEL = "org.critical_product_label"
    ORG_KEY_PRODUCT_LABEL = "org.key_product_label"
    ORG_FILTERS_LABEL = "org.filters.label"
    ORG_FILTERS_LABEL_HELP = "org.filters.label_help"
    ORG_FILTERS_NAME_LABEL = "org.filters.name_label"
    ORG_FILTERS_NAME_HELP = "org.filters.name_help"
    ORG_FILTERS_NAME_EXACT_LABEL = "org.filters.name_exact_label"
    ORG_FILTERS_NAME_CONTAINS_LABEL = "org.filters.name_contains_label"
    ORG_FILTERS_NAME_CONTAINS_HELP = "org.filters.name_contains_help"
    ORG_FILTERS_TAGS_LABEL = "org.filters.tags_label"
    ORG_USERS_LABEL = "org.users.label"
    ORG_USERS_NO_ACCESS_MESSAGE = "org.users.no_access_message"
    ORG_USERS_ADD_ORGANIZATIONS_LABEL = "org.users.add_organizations_label"
    ORG_USERS_DELETE_LABEL = "org.users.delete_label"
    ORG_USERS_DELETE_SUCCESS_MESSAGE = "org.users.delete_success_message"
    ORG_USERS_ADD_LABEL = "org.users.add_label"
    ORG_USERS_ADD_SUCCESS_MESSAGE = "org.users.add_success_message"
    ORG_USERS_UPDATE_LABEL = "org.users.update_label"
    ORG_USERS_UPDATE_SUCCESS_MESSAGE = "org.users.update_success_message"
    ORG_USERS_MINIMUM_NUMBER_WITH_NAME_MESSAGE = "org.users.minimum_number_with_name_message"
    ORG_GROUPS_LABEL = "org.groups.label"
    ORG_GROUPS_NO_ACCESS_MESSAGE = "org.groups.no_access_message"
    ORG_GROUPS_ADD_ORGANIZATIONS_LABEL = "org.groups.add_organizations_label"
    ORG_GROUPS_NUM_ORGANIZATIONS_LABEL = "org.groups.num_organizations_label"
    ORG_GROUPS_ADD_LABEL = "org.groups.add_label"
    ORG_GROUPS_ADD_SUCCESS_MESSAGE = "org.groups.add_success_message"
    ORG_GROUPS_UPDATE_LABEL = "org.groups.update_label"
    ORG_GROUPS_UPDATE_SUCCESS_MESSAGE = "org.groups.update_success_message"
    ORG_GROUPS_DELETE_LABEL = "org.groups.delete_label"
    ORG_GROUPS_DELETE_SUCCESS_MESSAGE = "org.groups.delete_success_message"
    ORG_CREATE_LABEL = "org.create.label"
    ORG_CREATE_SUCCESS_MESSAGE = "org.create.success_message"
    ORG_READ_LABEL = "org.read.label"
    ORG_READ_LIST_LABEL = "org.read.list_label"
    ORG_UPDATE_LABEL = "org.update.label"
    ORG_UPDATE_WITH_NAME_LABEL = "org.update.with_name_label"
    ORG_UPDATE_SUCCESS_MESSAGE = "org.update.success_message"
    ORG_DELETE_LABEL = "org.delete.label"
    ORG_DELETE_WITH_NAME_LABEL = "org.delete.with_name_label"
    ORG_DELETE_CONFIRM_MESSAGE = "org.delete.confirm_message"
    ORG_DELETE_SUCCESS_MESSAGE = "org.delete.success_message"
    ORG_DELETE_SUCCESS_ASYNC_MESSAGE = "org.delete.success_async_message"
    ORG_DELETE_WITH_NAME_SUCCESS_MESSAGE = "org.delete.with_name_success_message"
    ORG_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE = "org.delete.with_name_with_user_success_message"

    ASSET_LABEL = "asset.label"
    ASSET_PLURAL_LABEL = "asset.plural_label"
    ASSET_ALL_LABEL = "asset.all_label"
    ASSET_WITH_NAME_LABEL = "asset.with_name_label"
    ASSET_NONE_FOUND_MESSAGE = "asset.none_found_label"
    ASSET_MANAGER_LABEL = "asset.manager_label"
    ASSET_GLOBAL_ROLE_HELP = "asset.global_role_help"
    ASSET_NOTIFICATIONS_HELP = "asset.notifications_help"
    ASSET_OPTIONS_LABEL = "asset.options_label"
    ASSET_OPTIONS_MENU_LABEL = "asset.options_menu_label"
    ASSET_COUNT_LABEL = "asset.count_label"
    ASSET_ENGAGEMENTS_BY_LABEL = "asset.engagements_by_label"
    ASSET_LIFECYCLE_LABEL = "asset.lifecycle_label"
    ASSET_TAG_LABEL = "asset.tag_label"
    ASSET_METRICS_TAG_COUNTS_LABEL = "asset.metrics.tag_counts_label"
    ASSET_METRICS_TAG_COUNTS_ERROR_MESSAGE = "asset.metrics.tag_counts_error_message"
    ASSET_METRICS_CRITICAL_LABEL = "asset.metrics.critical_label"
    ASSET_METRICS_NO_CRITICAL_ERROR_MESSAGE = "asset.metrics.no_critical_error_message"
    ASSET_METRICS_TOP_TEN_BY_SEVERITY_LABEL = "asset.metrics.top_by_severity_label"
    ASSET_NOTIFICATION_WITH_NAME_CREATED_MESSAGE = "asset.notification_with_name_created_message"
    ASSET_REPORT_LABEL = "asset.report_label"
    ASSET_REPORT_TITLE = "asset.report_title"
    ASSET_REPORT_WITH_NAME_TITLE = "asset.report_with_name_title"
    ASSET_TRACKED_FILES_ADD_LABEL = "asset.tracked_files.add_label"
    ASSET_TRACKED_FILES_ADD_SUCCESS_MESSAGE = "asset.tracked_files.add_success_message"
    ASSET_TRACKED_FILES_ID_MISMATCH_ERROR_MESSAGE = "asset.tracked_files.id_mismatch_error_message"
    ASSET_FINDINGS_CLOSE_LABEL = "asset.findings_close_label"
    ASSET_FINDINGS_CLOSE_HELP = "asset.findings_close_help"
    ASSET_TAG_INHERITANCE_ENABLE_LABEL = "asset.tag_inheritance_enable_label"
    ASSET_TAG_INHERITANCE_ENABLE_HELP = "asset.tag_inheritance_enable_help"
    ASSET_ENDPOINT_HELP = "asset.endpoint_help"
    ASSET_CREATE_LABEL = "asset.create.label"
    ASSET_CREATE_SUCCESS_MESSAGE = "asset.create.success_message"
    ASSET_READ_LIST_LABEL = "asset.read.list_label"
    ASSET_UPDATE_LABEL = "asset.update.label"
    ASSET_UPDATE_SUCCESS_MESSAGE = "asset.update.success_message"
    ASSET_UPDATE_SLA_CHANGED_MESSAGE = "asset.update.sla_changed_message"
    ASSET_DELETE_LABEL = "asset.delete.label"
    ASSET_DELETE_WITH_NAME_LABEL = "asset.delete.with_name_label"
    ASSET_DELETE_CONFIRM_MESSAGE = "asset.delete.confirm_message"
    ASSET_DELETE_SUCCESS_MESSAGE = "asset.delete.success_message"
    ASSET_DELETE_SUCCESS_ASYNC_MESSAGE = "asset.delete.success_async_message"
    ASSET_DELETE_WITH_NAME_SUCCESS_MESSAGE = "asset.delete.with_name_success_message"
    ASSET_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE = "asset.delete.with_name_with_user_success_message"
    ASSET_FILTERS_LABEL = "asset.filters.label"
    ASSET_FILTERS_NAME_LABEL = "asset.filters.name_label"
    ASSET_FILTERS_NAME_HELP = "asset.filters.name_help"
    ASSET_FILTERS_NAME_EXACT_LABEL = "asset.filters.name_exact_label"
    ASSET_FILTERS_NAME_CONTAINS_LABEL = "asset.filters.name_contains_label"
    ASSET_FILTERS_NAME_CONTAINS_HELP = "asset.filters.name_contains_help"
    ASSET_FILTERS_TAGS_LABEL = "asset.filters.tags_label"
    ASSET_FILTERS_TAGS_HELP = "asset.filters.tags_help"
    ASSET_FILTERS_NOT_TAGS_HELP = "asset.filters.not_tags_help"
    ASSET_FILTERS_ASSETS_WITHOUT_TAGS_LABEL = "asset.filters.assets_without_tags_label"
    ASSET_FILTERS_ASSETS_WITHOUT_TAGS_HELP = "asset.filters.assets_without_tags_help"
    ASSET_FILTERS_TAGS_FILTER_HELP = "asset.filters.tags_filter_help"
    ASSET_FILTERS_CSV_TAGS_OR_HELP = "asset.filters.csv_tags_or_help"
    ASSET_FILTERS_CSV_TAGS_AND_HELP = "asset.filters.csv_tags_and_help"
    ASSET_FILTERS_CSV_TAGS_NOT_HELP = "asset.filters.csv_tags_not_help"
    ASSET_FILTERS_CSV_LIFECYCLES_LABEL = "asset.filters.csv_lifecycles_label"
    ASSET_FILTERS_TAGS_ASSET_LABEL = "asset.filters.tags_asset_label"
    ASSET_FILTERS_TAG_ASSET_LABEL = "asset.filters.tag_asset_label"
    ASSET_FILTERS_TAG_ASSET_HELP = "asset.filters.tag_asset_help"
    ASSET_FILTERS_NOT_TAGS_ASSET_LABEL = "asset.filters.not_tags_asset_label"
    ASSET_FILTERS_WITHOUT_TAGS_LABEL = "asset.filters.without_tags_label"
    ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL = "asset.filters.tag_asset_contains_label"
    ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP = "asset.filters.tag_asset_contains_help"
    ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL = "asset.filters.tag_not_contain_label"
    ASSET_FILTERS_TAG_NOT_CONTAIN_HELP = "asset.filters.tag_not_contain_help"
    ASSET_FILTERS_TAG_NOT_LABEL = "asset.filters.tag_not_label"
    ASSET_FILTERS_TAG_NOT_HELP = "asset.filters.tag_not_help"
    ASSET_USERS_ACCESS_LABEL = "asset.users.access_label"
    ASSET_USERS_NO_ACCESS_MESSAGE = "asset.users.no_access_message"
    ASSET_USERS_ADD_LABEL = "asset.users.add_label"
    ASSET_USERS_USERS_ADD_LABEL = "asset.users.users_add_label"
    ASSET_USERS_MEMBER_LABEL = "asset.users.member_label"
    ASSET_USERS_MEMBER_ADD_LABEL = "asset.users.member_add_label"
    ASSET_USERS_MEMBER_ADD_SUCCESS_MESSAGE = "asset.users.member_add_success_message"
    ASSET_USERS_MEMBER_UPDATE_LABEL = "asset.users.member_update_label"
    ASSET_USERS_MEMBER_UPDATE_SUCCESS_MESSAGE = "asset.users.member_update_success_message"
    ASSET_USERS_MEMBER_DELETE_LABEL = "asset.users.member_delete_label"
    ASSET_USERS_MEMBER_DELETE_SUCCESS_MESSAGE = "asset.users.member_delete_success_message"
    ASSET_GROUPS_ACCESS_LABEL = "asset.groups.access_label"
    ASSET_GROUPS_NO_ACCESS_MESSAGE = "asset.groups.no_access_message"
    ASSET_GROUPS_MEMBER_LABEL = "asset.groups.member_label"
    ASSET_GROUPS_ADD_LABEL = "asset.groups.add_label"
    ASSET_GROUPS_ADD_SUCCESS_MESSAGE = "asset.groups.add_success_message"
    ASSET_GROUPS_UPDATE_LABEL = "asset.groups.update_label"
    ASSET_GROUPS_UPDATE_SUCCESS_MESSAGE = "asset.groups.update_success_message"
    ASSET_GROUPS_DELETE_LABEL = "asset.groups.delete_label"
    ASSET_GROUPS_DELETE_SUCCESS_MESSAGE = "asset.groups.delete_success_message"
    ASSET_GROUPS_ADD_ASSETS_LABEL = "asset.groups.add_assets_label"
    ASSET_GROUPS_NUM_ASSETS_LABEL = "asset.groups.num_assets_label"

    SETTINGS_TRACKED_FILES_ENABLE_LABEL = "settings.tracked_files.enable_label"
    SETTINGS_TRACKED_FILES_ENABLE_HELP = "settings.tracked_files.enable_help"
    SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL = "settings.asset_grading.enforce_verified_label"
    SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP = "settings.asset_grading.enforce_verified_help"
    SETTINGS_ASSET_GRADING_ENABLE_LABEL = "settings.asset_grading.enable_label"
    SETTINGS_ASSET_GRADING_ENABLE_HELP = "settings.asset_grading.enable_help"
    SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL = "settings.asset_tag_inheritance.enable_label"
    SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP = "settings.asset_tag_inheritance.enable_help"


# V2 labels: uses "Product" and "Product Type."
V2_LABELS = {
    _K.ORG_LABEL: _("Product Type"),
    _K.ORG_PLURAL_LABEL: _("Product Types"),
    _K.ORG_ALL_LABEL: _("All Product Types"),
    _K.ORG_WITH_NAME_LABEL: _("Product Type '%(name)s'"),
    _K.ORG_NONE_FOUND_MESSAGE: _("No Product Types found"),
    _K.ORG_REPORT_LABEL: _("Product Type Report"),
    _K.ORG_REPORT_TITLE: _("Product Type Report"),
    _K.ORG_REPORT_WITH_NAME_TITLE: _("Product Type Report: %(name)s"),
    _K.ORG_METRICS_LABEL: _("Product Type Metrics"),
    _K.ORG_METRICS_COUNTS_LABEL: _("Product Type Counts"),
    _K.ORG_METRICS_BY_FINDINGS_LABEL: _("Product Type Metrics by Findings"),
    _K.ORG_METRICS_BY_ENDPOINTS_LABEL: _("Product Type Metrics by Affected Endpoints"),
    _K.ORG_METRICS_TYPE_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Product Type."),
    _K.ORG_OPTIONS_LABEL: _("Product Type Options"),
    _K.ORG_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Product Type %(name)s has been created successfully."),
    _K.ORG_CRITICAL_PRODUCT_LABEL: _("Critical Product"),
    _K.ORG_KEY_PRODUCT_LABEL: _("Key Product"),
    _K.ORG_FILTERS_LABEL: _("Product Type"),
    _K.ORG_FILTERS_LABEL_HELP: _("Search for Product Type names that are an exact match"),
    _K.ORG_FILTERS_NAME_LABEL: _("Product Type Name"),
    _K.ORG_FILTERS_NAME_HELP: _("Search for Product Type names that are an exact match"),
    _K.ORG_FILTERS_NAME_EXACT_LABEL: _("Exact Product Type Name"),
    _K.ORG_FILTERS_NAME_CONTAINS_LABEL: _("Product Type Name Contains"),
    _K.ORG_FILTERS_NAME_CONTAINS_HELP: _("Search for Product Type names that contain a given pattern"),
    _K.ORG_FILTERS_TAGS_LABEL: _("Tags (Product Type)"),
    _K.ORG_USERS_LABEL: _("Product Types this User can access"),
    _K.ORG_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Product Types."),
    _K.ORG_USERS_ADD_ORGANIZATIONS_LABEL: _("Add Product Types"),
    _K.ORG_USERS_DELETE_LABEL: _("Delete Product Type Member"),
    _K.ORG_USERS_DELETE_SUCCESS_MESSAGE: _("Product Type member deleted successfully."),
    _K.ORG_USERS_ADD_LABEL: _("Add Product Type Member"),
    _K.ORG_USERS_ADD_SUCCESS_MESSAGE: _("Product Type members added successfully."),
    _K.ORG_USERS_UPDATE_LABEL: _("Edit Product Type Member"),
    _K.ORG_USERS_UPDATE_SUCCESS_MESSAGE: _("Product Type member updated successfully."),
    _K.ORG_USERS_MINIMUM_NUMBER_WITH_NAME_MESSAGE: _("There must be at least one owner for Product Type %(name)s."),
    _K.ORG_GROUPS_LABEL: _("Product Types this Group can access"),
    _K.ORG_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Product Types."),
    _K.ORG_GROUPS_ADD_ORGANIZATIONS_LABEL: _("Add Product Types"),
    _K.ORG_GROUPS_NUM_ORGANIZATIONS_LABEL: _("Number of Product Types"),
    _K.ORG_GROUPS_ADD_LABEL: _("Add Product Type Group"),
    _K.ORG_GROUPS_ADD_SUCCESS_MESSAGE: _("Product Type groups added successfully."),
    _K.ORG_GROUPS_UPDATE_LABEL: _("Edit Product Type Group"),
    _K.ORG_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Product Type group updated successfully."),
    _K.ORG_GROUPS_DELETE_LABEL: _("Delete Product Type Group"),
    _K.ORG_GROUPS_DELETE_SUCCESS_MESSAGE: _("Product Type group deleted successfully."),
    _K.ORG_CREATE_LABEL: _("Add Product Type"),
    _K.ORG_CREATE_SUCCESS_MESSAGE: _("Product Type added successfully."),
    _K.ORG_READ_LABEL: _("View Product Type"),
    _K.ORG_READ_LIST_LABEL: _("List Product Types"),
    _K.ORG_UPDATE_LABEL: _("Edit Product Type"),
    _K.ORG_UPDATE_WITH_NAME_LABEL: _("Edit Product Type %(name)s"),
    _K.ORG_UPDATE_SUCCESS_MESSAGE: _("Product Type updated successfully."),
    _K.ORG_DELETE_LABEL: _("Delete Product Type"),
    _K.ORG_DELETE_WITH_NAME_LABEL: _("Delete Product Type %(name)s"),
    _K.ORG_DELETE_CONFIRM_MESSAGE: _(
        "Deleting this Product Type will remove any related objects associated with it. These relationships are listed below:"),
    _K.ORG_DELETE_SUCCESS_MESSAGE: _("Product Type and relationships removed."),
    _K.ORG_DELETE_SUCCESS_ASYNC_MESSAGE: _("Product Type and relationships will be removed in the background."),
    _K.ORG_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The product type "%(name)s" was deleted'),
    _K.ORG_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The product type "%(name)s" was deleted by %(user)s'),
    _K.ASSET_LABEL: _("Product"),
    _K.ASSET_PLURAL_LABEL: _("Products"),
    _K.ASSET_ALL_LABEL: _("All Products"),
    _K.ASSET_WITH_NAME_LABEL: _("Product '%(name)s'"),
    _K.ASSET_NONE_FOUND_MESSAGE: _("No Products found."),
    _K.ASSET_MANAGER_LABEL: _("Product Manager"),
    _K.ASSET_GLOBAL_ROLE_HELP: _("The global role will be applied to all Product Types and Products."),
    _K.ASSET_NOTIFICATIONS_HELP: _("These are your personal settings for this Product."),
    _K.ASSET_OPTIONS_LABEL: _("Product Options"),
    _K.ASSET_OPTIONS_MENU_LABEL: _("Product Options Menu"),
    _K.ASSET_COUNT_LABEL: _("Product Count"),
    _K.ASSET_ENGAGEMENTS_BY_LABEL: _("Engagements by Product"),
    _K.ASSET_LIFECYCLE_LABEL: _("Product Lifecycle"),
    _K.ASSET_TAG_LABEL: _("Product Tag"),
    _K.ASSET_METRICS_TAG_COUNTS_LABEL: _("Product Tag Counts"),
    _K.ASSET_METRICS_TAG_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Product Tag."),
    _K.ASSET_METRICS_CRITICAL_LABEL: _("Critical Product Metrics"),
    _K.ASSET_METRICS_NO_CRITICAL_ERROR_MESSAGE: _("No Critical Products registered"),
    _K.ASSET_METRICS_TOP_TEN_BY_SEVERITY_LABEL: _("Top 10 Products by bug severity"),
    _K.ASSET_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Product %(name)s has been created successfully."),
    _K.ASSET_REPORT_LABEL: _("Product Report"),
    _K.ASSET_REPORT_TITLE: _("Product Report"),
    _K.ASSET_REPORT_WITH_NAME_TITLE: _("Product Report: %(name)s"),
    _K.ASSET_TRACKED_FILES_ADD_LABEL: _("Add Tracked Files to a Product"),
    _K.ASSET_TRACKED_FILES_ADD_SUCCESS_MESSAGE: _("Added Tracked File to a Product"),
    _K.ASSET_TRACKED_FILES_ID_MISMATCH_ERROR_MESSAGE: _(
        "Product %(asset_id)s does not match Product of Object %(object_asset_id)s"),
    _K.ASSET_FINDINGS_CLOSE_LABEL: _("Close old findings within this Product"),
    _K.ASSET_FINDINGS_CLOSE_HELP: _("Old findings no longer present in the new report get closed as mitigated when importing. If service has been set, only the findings for this service will be closed. This affects findings within the same product."),
    _K.ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Product Tag Inheritance"),
    _K.ASSET_TAG_INHERITANCE_ENABLE_HELP: _(
        "Enables Product tag inheritance. Any tags added on an Product will automatically be added to all Engagements, Tests, and Findings."),
    _K.ASSET_ENDPOINT_HELP: _("The Product this Endpoint should be associated with."),
    _K.ASSET_CREATE_LABEL: _("Add Product"),
    _K.ASSET_CREATE_SUCCESS_MESSAGE: _("Product added successfully."),
    _K.ASSET_READ_LIST_LABEL: _("Product List"),
    _K.ASSET_UPDATE_LABEL: _("Edit Product"),
    _K.ASSET_UPDATE_SUCCESS_MESSAGE: _("Product updated successfully."),
    _K.ASSET_UPDATE_SLA_CHANGED_MESSAGE: _(
        "All SLA expiration dates for Findings within this Product will be recalculated asynchronously for the newly assigned SLA configuration."),
    _K.ASSET_DELETE_LABEL: _("Delete Product"),
    _K.ASSET_DELETE_WITH_NAME_LABEL: _("Delete Product %(name)s"),
    _K.ASSET_DELETE_CONFIRM_MESSAGE: _(
        "Deleting this Product will remove any related objects associated with it. These relationships are listed below: "),
    _K.ASSET_DELETE_SUCCESS_MESSAGE: _("Product and relationships removed."),
    _K.ASSET_DELETE_SUCCESS_ASYNC_MESSAGE: _("Product and relationships will be removed in the background."),
    _K.ASSET_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The product "%(name)s" was deleted'),
    _K.ASSET_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The product "%(name)s" was deleted by %(user)s'),
    _K.ASSET_FILTERS_LABEL: _("Product"),
    _K.ASSET_FILTERS_NAME_LABEL: _("Product Name"),
    _K.ASSET_FILTERS_NAME_HELP: _("Search for Product names that are an exact match"),
    _K.ASSET_FILTERS_NAME_EXACT_LABEL: _("Exact Product Name"),
    _K.ASSET_FILTERS_NAME_CONTAINS_LABEL: _("Product Name Contains"),
    _K.ASSET_FILTERS_NAME_CONTAINS_HELP: _("Search for Product names that contain a given pattern"),
    _K.ASSET_FILTERS_TAGS_LABEL: _("Tags (Product)"),
    _K.ASSET_FILTERS_TAGS_HELP: _("Filter for Products with the given tags"),
    _K.ASSET_FILTERS_NOT_TAGS_HELP: _("Filter for Products that do not have the given tags"),
    _K.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_LABEL: _("Products without tags"),
    _K.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_HELP: _(
        "Search for tags on an Product that contain a given pattern, and exclude them"),
    _K.ASSET_FILTERS_TAGS_FILTER_HELP: _("Filter Products by the selected tags"),
    _K.ASSET_FILTERS_CSV_TAGS_OR_HELP: _(
        "Comma separated list of exact tags present on Product (uses OR for multiple values)"),
    _K.ASSET_FILTERS_CSV_TAGS_AND_HELP: _(
        "Comma separated list of exact tags to match with an AND expression present on Product"),
    _K.ASSET_FILTERS_CSV_TAGS_NOT_HELP: _("Comma separated list of exact tags not present on Product"),
    _K.ASSET_FILTERS_CSV_LIFECYCLES_LABEL: _("Comma separated list of exact Product lifecycles"),
    _K.ASSET_FILTERS_TAGS_ASSET_LABEL: _("Product Tags"),
    _K.ASSET_FILTERS_TAG_ASSET_LABEL: _("Product Tag"),
    _K.ASSET_FILTERS_TAG_ASSET_HELP: _("Search for tags on an Product that are an exact match"),
    _K.ASSET_FILTERS_NOT_TAGS_ASSET_LABEL: _("Not Product Tags"),
    _K.ASSET_FILTERS_WITHOUT_TAGS_LABEL: _("Product without tags"),
    _K.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL: _("Product Tag Contains"),
    _K.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP: _("Search for tags on an Product that contain a given pattern"),
    _K.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL: _("Product Tag Does Not Contain"),
    _K.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP: _(
        "Search for tags on an Product that contain a given pattern, and exclude them"),
    _K.ASSET_FILTERS_TAG_NOT_LABEL: _("Not Product Tag"),
    _K.ASSET_FILTERS_TAG_NOT_HELP: _("Search for tags on an Product that are an exact match, and exclude them"),
    _K.ASSET_USERS_ACCESS_LABEL: _("Products this User can access"),
    _K.ASSET_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Products."),
    _K.ASSET_USERS_ADD_LABEL: _("Add Products"),
    _K.ASSET_USERS_USERS_ADD_LABEL: _("Add Users"),
    _K.ASSET_USERS_MEMBER_LABEL: _("Product Member"),
    _K.ASSET_USERS_MEMBER_ADD_LABEL: _("Add Product Member"),
    _K.ASSET_USERS_MEMBER_ADD_SUCCESS_MESSAGE: _("Product members added successfully."),
    _K.ASSET_USERS_MEMBER_UPDATE_LABEL: _("Edit Product Member"),
    _K.ASSET_USERS_MEMBER_UPDATE_SUCCESS_MESSAGE: _("Product member updated successfully."),
    _K.ASSET_USERS_MEMBER_DELETE_LABEL: _("Delete Product Member"),
    _K.ASSET_USERS_MEMBER_DELETE_SUCCESS_MESSAGE: _("Product member deleted successfully."),
    _K.ASSET_GROUPS_ACCESS_LABEL: _("Products this Group can access"),
    _K.ASSET_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Products."),
    _K.ASSET_GROUPS_MEMBER_LABEL: _("Product Group"),
    _K.ASSET_GROUPS_ADD_LABEL: _("Add Product Group"),
    _K.ASSET_GROUPS_ADD_SUCCESS_MESSAGE: _("Product Groups added successfully."),
    _K.ASSET_GROUPS_UPDATE_LABEL: _("Edit Product Group"),
    _K.ASSET_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Product Group updated successfully."),
    _K.ASSET_GROUPS_DELETE_LABEL: _("Delete Product Group"),
    _K.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE: _("Product Group deleted successfully."),
    _K.ASSET_GROUPS_ADD_ASSETS_LABEL: _("Add Products"),
    _K.ASSET_GROUPS_NUM_ASSETS_LABEL: _("Number of Products"),
    _K.SETTINGS_TRACKED_FILES_ENABLE_LABEL: _("Enable Product Tracking Files"),
    _K.SETTINGS_TRACKED_FILES_ENABLE_HELP: _("With this setting turned off, the product tracking files will be disabled in the user interface."),
    _K.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL: _("Enforce Verified Status - Product Grading"),
    _K.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP: _("When enabled, findings must have a verified status to be considered as part of a product's grading."),
    _K.SETTINGS_ASSET_GRADING_ENABLE_LABEL: _("Enable Product Grading"),
    _K.SETTINGS_ASSET_GRADING_ENABLE_HELP: _("Displays a grade letter next to a product to show the overall health."),
    _K.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Product Tag Inheritance"),
    _K.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP: _("Enables product tag inheritance globally for all products. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings"),
}


# V3 labels: uses "Asset" and "Organization."
V3_LABELS = {
    _K.ORG_LABEL: _("Organization"),
    _K.ORG_PLURAL_LABEL: _("Organizations"),
    _K.ORG_ALL_LABEL: _("All Organizations"),
    _K.ORG_WITH_NAME_LABEL: _("Organization '%(name)s'"),
    _K.ORG_NONE_FOUND_MESSAGE: _("No Organizations found"),
    _K.ORG_REPORT_LABEL: _("Organization Report"),
    _K.ORG_REPORT_TITLE: _("Organization Report"),
    _K.ORG_REPORT_WITH_NAME_TITLE: _("Organization Report: %(name)s"),
    _K.ORG_METRICS_LABEL: _("Organization Metrics"),
    _K.ORG_METRICS_COUNTS_LABEL: _("Organization Counts"),
    _K.ORG_METRICS_BY_FINDINGS_LABEL: _("Organization Metrics by Findings"),
    _K.ORG_METRICS_BY_ENDPOINTS_LABEL: _("Organization Metrics by Affected Endpoints"),
    _K.ORG_METRICS_TYPE_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Organization."),
    _K.ORG_OPTIONS_LABEL: _("Organization Options"),
    _K.ORG_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Organization %(name)s has been created successfully."),
    _K.ORG_CRITICAL_PRODUCT_LABEL: _("Critical Asset"),
    _K.ORG_KEY_PRODUCT_LABEL: _("Key Asset"),
    _K.ORG_FILTERS_LABEL: _("Organization"),
    _K.ORG_FILTERS_LABEL_HELP: _("Search for Organization names that are an exact match"),
    _K.ORG_FILTERS_NAME_LABEL: _("Organization Name"),
    _K.ORG_FILTERS_NAME_HELP: _("Search for Organization names that are an exact match"),
    _K.ORG_FILTERS_NAME_EXACT_LABEL: _("Exact Organization Name"),
    _K.ORG_FILTERS_NAME_CONTAINS_LABEL: _("Organization Name Contains"),
    _K.ORG_FILTERS_NAME_CONTAINS_HELP: _("Search for Organization names that contain a given pattern"),
    _K.ORG_FILTERS_TAGS_LABEL: _("Tags (Organization)"),
    _K.ORG_USERS_LABEL: _("Organizations this User can access"),
    _K.ORG_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Organizations."),
    _K.ORG_USERS_ADD_ORGANIZATIONS_LABEL: _("Add Organizations"),
    _K.ORG_USERS_DELETE_LABEL: _("Delete Organization Member"),
    _K.ORG_USERS_DELETE_SUCCESS_MESSAGE: _("Organization member deleted successfully."),
    _K.ORG_USERS_ADD_LABEL: _("Add Organization Member"),
    _K.ORG_USERS_ADD_SUCCESS_MESSAGE: _("Organization members added successfully."),
    _K.ORG_USERS_UPDATE_LABEL: _("Edit Organization Member"),
    _K.ORG_USERS_UPDATE_SUCCESS_MESSAGE: _("Organization member updated successfully."),
    _K.ORG_USERS_MINIMUM_NUMBER_WITH_NAME_MESSAGE: _("There must be at least one owner for Organization %(name)s."),
    _K.ORG_GROUPS_LABEL: _("Organizations this Group can access"),
    _K.ORG_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Organizations."),
    _K.ORG_GROUPS_ADD_ORGANIZATIONS_LABEL: _("Add Organizations"),
    _K.ORG_GROUPS_NUM_ORGANIZATIONS_LABEL: _("Number of Organizations"),
    _K.ORG_GROUPS_ADD_LABEL: _("Add Organization Group"),
    _K.ORG_GROUPS_ADD_SUCCESS_MESSAGE: _("Organization groups added successfully."),
    _K.ORG_GROUPS_UPDATE_LABEL: _("Edit Organization Group"),
    _K.ORG_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Organization group updated successfully."),
    _K.ORG_GROUPS_DELETE_LABEL: _("Delete Organization Group"),
    _K.ORG_GROUPS_DELETE_SUCCESS_MESSAGE: _("Organization group deleted successfully."),
    _K.ORG_CREATE_LABEL: _("Add Organization"),
    _K.ORG_CREATE_SUCCESS_MESSAGE: _("Organization added successfully."),
    _K.ORG_READ_LABEL: _("View Organization"),
    _K.ORG_READ_LIST_LABEL: _("List Organizations"),
    _K.ORG_UPDATE_LABEL: _("Edit Organization"),
    _K.ORG_UPDATE_WITH_NAME_LABEL: _("Edit Organization %(name)s"),
    _K.ORG_UPDATE_SUCCESS_MESSAGE: _("Organization updated successfully."),
    _K.ORG_DELETE_LABEL: _("Delete Organization"),
    _K.ORG_DELETE_WITH_NAME_LABEL: _("Delete Organization %(name)s"),
    _K.ORG_DELETE_CONFIRM_MESSAGE: _("Deleting this Organization will remove any related objects associated with it. These relationships are listed below:"),
    _K.ORG_DELETE_SUCCESS_MESSAGE: _("Organization and relationships removed."),
    _K.ORG_DELETE_SUCCESS_ASYNC_MESSAGE: _("Organization and relationships will be removed in the background."),
    _K.ORG_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The Organization "%(name)s" was deleted'),
    _K.ORG_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The Organization "%(name)s" was deleted by %(user)s'),
    _K.ASSET_LABEL: _("Asset"),
    _K.ASSET_PLURAL_LABEL: _("Assets"),
    _K.ASSET_ALL_LABEL: _("All Assets"),
    _K.ASSET_WITH_NAME_LABEL: _("Asset '%(name)s'"),
    _K.ASSET_NONE_FOUND_MESSAGE: _("No Assets found."),
    _K.ASSET_MANAGER_LABEL: _("Asset Manager"),
    _K.ASSET_GLOBAL_ROLE_HELP: _("The global role will be applied to all Organizations and Assets."),
    _K.ASSET_NOTIFICATIONS_HELP: _("These are your personal settings for this Asset."),
    _K.ASSET_OPTIONS_LABEL: _("Asset Options"),
    _K.ASSET_OPTIONS_MENU_LABEL: _("Asset Options Menu"),
    _K.ASSET_COUNT_LABEL: _("Asset Count"),
    _K.ASSET_ENGAGEMENTS_BY_LABEL: _("Engagements by Asset"),
    _K.ASSET_LIFECYCLE_LABEL: _("Asset Lifecycle"),
    _K.ASSET_TAG_LABEL: _("Asset Tag"),
    _K.ASSET_METRICS_TAG_COUNTS_LABEL: _("Asset Tag Counts"),
    _K.ASSET_METRICS_TAG_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Asset Tag."),
    _K.ASSET_METRICS_CRITICAL_LABEL: _("Critical Asset Metrics"),
    _K.ASSET_METRICS_NO_CRITICAL_ERROR_MESSAGE: _("No Critical Assets registered"),
    _K.ASSET_METRICS_TOP_TEN_BY_SEVERITY_LABEL: _("Top 10 Assets by bug severity"),
    _K.ASSET_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Asset %(name)s has been created successfully."),
    _K.ASSET_REPORT_LABEL: _("Asset Report"),
    _K.ASSET_REPORT_TITLE: _("Asset Report"),
    _K.ASSET_REPORT_WITH_NAME_TITLE: _("Asset Report: %(name)s"),
    _K.ASSET_TRACKED_FILES_ADD_LABEL: _("Add Tracked Files to an Asset"),
    _K.ASSET_TRACKED_FILES_ADD_SUCCESS_MESSAGE: _("Added Tracked File to an Asset"),
    _K.ASSET_TRACKED_FILES_ID_MISMATCH_ERROR_MESSAGE: _(
        "Asset %(asset_id)s does not match Asset of Object %(object_asset_id)s"),
    _K.ASSET_FINDINGS_CLOSE_LABEL: _("Close old findings within this Asset"),
    _K.ASSET_FINDINGS_CLOSE_HELP: _("Old findings no longer present in the new report get closed as mitigated when importing. If service has been set, only the findings for this service will be closed. This affects findings within the same Asset."),
    _K.ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Asset Tag Inheritance"),
    _K.ASSET_TAG_INHERITANCE_ENABLE_HELP: _("Enables Asset tag inheritance. Any tags added on an Asset will automatically be added to all Engagements, Tests, and Findings."),
    _K.ASSET_ENDPOINT_HELP: _("The Asset this Endpoint should be associated with."),
    _K.ASSET_CREATE_LABEL: _("Add Asset"),
    _K.ASSET_CREATE_SUCCESS_MESSAGE: _("Asset added successfully."),
    _K.ASSET_READ_LIST_LABEL: _("Asset List"),
    _K.ASSET_UPDATE_LABEL: _("Edit Asset"),
    _K.ASSET_UPDATE_SUCCESS_MESSAGE: _("Asset updated successfully."),
    _K.ASSET_UPDATE_SLA_CHANGED_MESSAGE: _("All SLA expiration dates for Findings within this Asset will be recalculated asynchronously for the newly assigned SLA configuration."),
    _K.ASSET_DELETE_LABEL: _("Delete Asset"),
    _K.ASSET_DELETE_WITH_NAME_LABEL: _("Delete Asset %(name)s"),
    _K.ASSET_DELETE_CONFIRM_MESSAGE: _(
        "Deleting this Asset will remove any related objects associated with it. These relationships are listed below: "),
    _K.ASSET_DELETE_SUCCESS_MESSAGE: _("Asset and relationships removed."),
    _K.ASSET_DELETE_SUCCESS_ASYNC_MESSAGE: _("Asset and relationships will be removed in the background."),
    _K.ASSET_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The Asset "%(name)s" was deleted'),
    _K.ASSET_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The Asset "%(name)s" was deleted by %(user)s'),
    _K.ASSET_FILTERS_LABEL: _("Asset"),
    _K.ASSET_FILTERS_NAME_LABEL: _("Asset Name"),
    _K.ASSET_FILTERS_NAME_HELP: _("Search for Asset names that are an exact match"),
    _K.ASSET_FILTERS_NAME_EXACT_LABEL: _("Exact Asset Name"),
    _K.ASSET_FILTERS_NAME_CONTAINS_LABEL: _("Asset Name Contains"),
    _K.ASSET_FILTERS_NAME_CONTAINS_HELP: _("Search for Asset names that contain a given pattern"),
    _K.ASSET_FILTERS_TAGS_LABEL: _("Tags (Asset)"),
    _K.ASSET_FILTERS_TAGS_HELP: _("Filter for Assets with the given tags"),
    _K.ASSET_FILTERS_NOT_TAGS_HELP: _("Filter for Assets that do not have the given tags"),
    _K.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_LABEL: _("Assets without tags"),
    _K.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_HELP: _("Search for tags on an Asset that contain a given pattern, and exclude them"),
    _K.ASSET_FILTERS_TAGS_FILTER_HELP: _("Filter Assets by the selected tags"),
    _K.ASSET_FILTERS_CSV_TAGS_OR_HELP: _("Comma separated list of exact tags present on Asset (uses OR for multiple values)"),
    _K.ASSET_FILTERS_CSV_TAGS_AND_HELP: _("Comma separated list of exact tags to match with an AND expression present on Asset"),
    _K.ASSET_FILTERS_CSV_TAGS_NOT_HELP: _("Comma separated list of exact tags not present on Asset"),
    _K.ASSET_FILTERS_CSV_LIFECYCLES_LABEL: _("Comma separated list of exact Asset lifecycles"),
    _K.ASSET_FILTERS_TAGS_ASSET_LABEL: _("Asset Tags"),
    _K.ASSET_FILTERS_TAG_ASSET_LABEL: _("Asset Tag"),
    _K.ASSET_FILTERS_TAG_ASSET_HELP: _("Search for tags on an Asset that are an exact match"),
    _K.ASSET_FILTERS_NOT_TAGS_ASSET_LABEL: _("Not Asset Tags"),
    _K.ASSET_FILTERS_WITHOUT_TAGS_LABEL: _("Asset without tags"),
    _K.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL: _("Asset Tag Contains"),
    _K.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP: _("Search for tags on an Asset that contain a given pattern"),
    _K.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL: _("Asset Tag Does Not Contain"),
    _K.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP: _("Search for tags on an Asset that contain a given pattern, and exclude them"),
    _K.ASSET_FILTERS_TAG_NOT_LABEL: _("Not Asset Tag"),
    _K.ASSET_FILTERS_TAG_NOT_HELP: _("Search for tags on an Asset that are an exact match, and exclude them"),
    _K.ASSET_USERS_ACCESS_LABEL: _("Assets this User can access"),
    _K.ASSET_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Assets."),
    _K.ASSET_USERS_ADD_LABEL: _("Add Assets"),
    _K.ASSET_USERS_USERS_ADD_LABEL: _("Add Users"),
    _K.ASSET_USERS_MEMBER_LABEL: _("Asset Member"),
    _K.ASSET_USERS_MEMBER_ADD_LABEL: _("Add Asset Member"),
    _K.ASSET_USERS_MEMBER_ADD_SUCCESS_MESSAGE: _("Asset members added successfully."),
    _K.ASSET_USERS_MEMBER_UPDATE_LABEL: _("Edit Asset Member"),
    _K.ASSET_USERS_MEMBER_UPDATE_SUCCESS_MESSAGE: _("Asset member updated successfully."),
    _K.ASSET_USERS_MEMBER_DELETE_LABEL: _("Delete Asset Member"),
    _K.ASSET_USERS_MEMBER_DELETE_SUCCESS_MESSAGE: _("Asset member deleted successfully."),
    _K.ASSET_GROUPS_ACCESS_LABEL: _("Assets this Group can access"),
    _K.ASSET_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Assets."),
    _K.ASSET_GROUPS_MEMBER_LABEL: _("Asset Group"),
    _K.ASSET_GROUPS_ADD_LABEL: _("Add Asset Group"),
    _K.ASSET_GROUPS_ADD_SUCCESS_MESSAGE: _("Asset groups added successfully."),
    _K.ASSET_GROUPS_UPDATE_LABEL: _("Edit Asset Group"),
    _K.ASSET_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Asset group updated successfully."),
    _K.ASSET_GROUPS_DELETE_LABEL: _("Delete Asset Group"),
    _K.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE: _("Asset group deleted successfully."),
    _K.ASSET_GROUPS_ADD_ASSETS_LABEL: _("Add Assets"),
    _K.ASSET_GROUPS_NUM_ASSETS_LABEL: _("Number of Assets"),
    _K.SETTINGS_TRACKED_FILES_ENABLE_LABEL: _("Enable Tracked Asset Files"),
    _K.SETTINGS_TRACKED_FILES_ENABLE_HELP: _("With this setting turned off, tracked Asset files will be disabled in the user interface."),
    _K.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL: _("Enforce Verified Status - Asset Grading"),
    _K.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP: _("When enabled, findings must have a verified status to be considered as part of an Asset's grading."),
    _K.SETTINGS_ASSET_GRADING_ENABLE_LABEL: _("Enable Asset Grading"),
    _K.SETTINGS_ASSET_GRADING_ENABLE_HELP: _("Displays a grade letter next to an Asset to show the overall health."),
    _K.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Asset Tag Inheritance"),
    _K.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP: _("Enables Asset tag inheritance globally for all Assets. Any tags added on an Asset will automatically be added to all Engagements, Tests, and Findings."),
}


class LabelsProxy(_K):

    """
    Proxy class for text copy. The purpose of this is to allow easy access to the copy from within templates, and to
    allow for IDE code completion. This inherits from K so IDEs can statically determine what attributes ("labels") are
    available. After initialization, all attributes defined on K are set to the value of the appropriate text.
    """

    def _get_label_entries(self):
        """Returns a dict of all "label" entries from this class."""
        cl = self.__class__
        return {
            name: getattr(cl, name) for name in dir(cl) if not name.startswith("_")}

    def __init__(self, labels: dict[str, str]):
        """
        The initializer takes a dict set of labels and sets the corresponding attribute defined in K to the value
        specified in the dict (e.g., self.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE is set to
        labels[K.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE]).

        As a side benefit, this will explode if any label defined in K is not present in the given dict: a runtime check
        that a labels dict must be complete.
        """
        for _l, _v in self._get_label_entries().items():
            try:
                setattr(self, _l, labels[_v])
            except KeyError:
                error_message = f"Supplied copy dictionary does not provide entry for {_l}"
                logger.error(error_message)
                raise ValueError(error_message)


class DynamicLabelsProxy(_K):
    v2_labels_proxy = LabelsProxy(V2_LABELS)
    v3_labels_proxy = LabelsProxy(V3_LABELS)

    @classmethod
    def lookup(cls, name):
        if v3_migration_enabled():
            logger.info("Using V3 labels")
            return getattr(cls.v3_labels_proxy, name)
        logger.info("Using V2 labels")
        return getattr(cls.v2_labels_proxy, name)

    def __getattribute__(self, name):
        return DynamicLabelsProxy.lookup(name)


class LazyDynamicLabelsProxy(DynamicLabelsProxy):
    def __getattribute__(self, name):
        return lazy(lambda: DynamicLabelsProxy.__getattribute__(self, name), str)


def get_labels() -> DynamicLabelsProxy:
    """Method for getting a DynamicLabelsProxy initialized with the correct set of labels."""
    return DynamicLabelsProxy()


def get_lazy_labels():
    """Returns a LazyDynamicLabelsProxy initialized with the correct set of labels."""
    return LazyDynamicLabelsProxy()
