from django.conf import settings
from django.utils.translation import gettext_lazy as _


class OrganizationLabelsKeys:

    """Directory of text copy used by the Organization model."""

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


# TODO: remove the else: branch once v3 migration is complete
if settings.ENABLE_V3_ORGANIZATION_ASSET_RELABEL:
    labels = {
        OrganizationLabelsKeys.ORG_LABEL: _("Organization"),
        OrganizationLabelsKeys.ORG_PLURAL_LABEL: _("Organizations"),
        OrganizationLabelsKeys.ORG_ALL_LABEL: _("All Organizations"),
        OrganizationLabelsKeys.ORG_WITH_NAME_LABEL: _("Organization '%(name)s'"),
        OrganizationLabelsKeys.ORG_NONE_FOUND_MESSAGE: _("No Organizations found"),
        OrganizationLabelsKeys.ORG_REPORT_LABEL: _("Organization Report"),
        OrganizationLabelsKeys.ORG_REPORT_TITLE: _("Organization Report"),
        OrganizationLabelsKeys.ORG_REPORT_WITH_NAME_TITLE: _("Organization Report: %(name)s"),
        OrganizationLabelsKeys.ORG_METRICS_LABEL: _("Organization Metrics"),
        OrganizationLabelsKeys.ORG_METRICS_COUNTS_LABEL: _("Organization Counts"),
        OrganizationLabelsKeys.ORG_METRICS_BY_FINDINGS_LABEL: _("Organization Metrics by Findings"),
        OrganizationLabelsKeys.ORG_METRICS_BY_ENDPOINTS_LABEL: _("Organization Metrics by Affected Endpoints"),
        OrganizationLabelsKeys.ORG_METRICS_TYPE_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Organization."),
        OrganizationLabelsKeys.ORG_OPTIONS_LABEL: _("Organization Options"),
        OrganizationLabelsKeys.ORG_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Organization %(name)s has been created successfully."),
        OrganizationLabelsKeys.ORG_CRITICAL_PRODUCT_LABEL: _("Critical Asset"),
        OrganizationLabelsKeys.ORG_KEY_PRODUCT_LABEL: _("Key Asset"),
        OrganizationLabelsKeys.ORG_FILTERS_LABEL: _("Organization"),
        OrganizationLabelsKeys.ORG_FILTERS_LABEL_HELP: _("Search for Organization names that are an exact match"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_LABEL: _("Organization Name"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_HELP: _("Search for Organization names that are an exact match"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_EXACT_LABEL: _("Exact Organization Name"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_CONTAINS_LABEL: _("Organization Name Contains"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_CONTAINS_HELP: _("Search for Organization names that contain a given pattern"),
        OrganizationLabelsKeys.ORG_FILTERS_TAGS_LABEL: _("Tags (Organization)"),
        OrganizationLabelsKeys.ORG_USERS_LABEL: _("Organizations this User can access"),
        OrganizationLabelsKeys.ORG_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Organizations."),
        OrganizationLabelsKeys.ORG_USERS_ADD_ORGANIZATIONS_LABEL: _("Add Organizations"),
        OrganizationLabelsKeys.ORG_USERS_DELETE_LABEL: _("Delete Organization Member"),
        OrganizationLabelsKeys.ORG_USERS_DELETE_SUCCESS_MESSAGE: _("Organization member deleted successfully."),
        OrganizationLabelsKeys.ORG_USERS_ADD_LABEL: _("Add Organization Member"),
        OrganizationLabelsKeys.ORG_USERS_ADD_SUCCESS_MESSAGE: _("Organization members added successfully."),
        OrganizationLabelsKeys.ORG_USERS_UPDATE_LABEL: _("Edit Organization Member"),
        OrganizationLabelsKeys.ORG_USERS_UPDATE_SUCCESS_MESSAGE: _("Organization member updated successfully."),
        OrganizationLabelsKeys.ORG_USERS_MINIMUM_NUMBER_WITH_NAME_MESSAGE: _("There must be at least one owner for Organization %(name)s."),
        OrganizationLabelsKeys.ORG_GROUPS_LABEL: _("Organizations this Group can access"),
        OrganizationLabelsKeys.ORG_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Organizations."),
        OrganizationLabelsKeys.ORG_GROUPS_ADD_ORGANIZATIONS_LABEL: _("Add Organizations"),
        OrganizationLabelsKeys.ORG_GROUPS_NUM_ORGANIZATIONS_LABEL: _("Number of Organizations"),
        OrganizationLabelsKeys.ORG_GROUPS_ADD_LABEL: _("Add Organization Group"),
        OrganizationLabelsKeys.ORG_GROUPS_ADD_SUCCESS_MESSAGE: _("Organization groups added successfully."),
        OrganizationLabelsKeys.ORG_GROUPS_UPDATE_LABEL: _("Edit Organization Group"),
        OrganizationLabelsKeys.ORG_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Organization group updated successfully."),
        OrganizationLabelsKeys.ORG_GROUPS_DELETE_LABEL: _("Delete Organization Group"),
        OrganizationLabelsKeys.ORG_GROUPS_DELETE_SUCCESS_MESSAGE: _("Organization group deleted successfully."),
        OrganizationLabelsKeys.ORG_CREATE_LABEL: _("Add Organization"),
        OrganizationLabelsKeys.ORG_CREATE_SUCCESS_MESSAGE: _("Organization added successfully."),
        OrganizationLabelsKeys.ORG_READ_LABEL: _("View Organization"),
        OrganizationLabelsKeys.ORG_READ_LIST_LABEL: _("List Organizations"),
        OrganizationLabelsKeys.ORG_UPDATE_LABEL: _("Edit Organization"),
        OrganizationLabelsKeys.ORG_UPDATE_WITH_NAME_LABEL: _("Edit Organization %(name)s"),
        OrganizationLabelsKeys.ORG_UPDATE_SUCCESS_MESSAGE: _("Organization updated successfully."),
        OrganizationLabelsKeys.ORG_DELETE_LABEL: _("Delete Organization"),
        OrganizationLabelsKeys.ORG_DELETE_WITH_NAME_LABEL: _("Delete Organization %(name)s"),
        OrganizationLabelsKeys.ORG_DELETE_CONFIRM_MESSAGE: _(
            "Deleting this Organization will remove any related objects associated with it. These relationships are listed below:"),
        OrganizationLabelsKeys.ORG_DELETE_SUCCESS_MESSAGE: _("Organization and relationships removed."),
        OrganizationLabelsKeys.ORG_DELETE_SUCCESS_ASYNC_MESSAGE: _("Organization and relationships will be removed in the background."),
        OrganizationLabelsKeys.ORG_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The Organization "%(name)s" was deleted'),
        OrganizationLabelsKeys.ORG_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The Organization "%(name)s" was deleted by %(user)s'),
    }
else:
    labels = {
        OrganizationLabelsKeys.ORG_LABEL: _("Product Type"),
        OrganizationLabelsKeys.ORG_PLURAL_LABEL: _("Product Types"),
        OrganizationLabelsKeys.ORG_ALL_LABEL: _("All Product Types"),
        OrganizationLabelsKeys.ORG_WITH_NAME_LABEL: _("Product Type '%(name)s'"),
        OrganizationLabelsKeys.ORG_NONE_FOUND_MESSAGE: _("No Product Types found"),
        OrganizationLabelsKeys.ORG_REPORT_LABEL: _("Product Type Report"),
        OrganizationLabelsKeys.ORG_REPORT_TITLE: _("Product Type Report"),
        OrganizationLabelsKeys.ORG_REPORT_WITH_NAME_TITLE: _("Product Type Report: %(name)s"),
        OrganizationLabelsKeys.ORG_METRICS_LABEL: _("Product Type Metrics"),
        OrganizationLabelsKeys.ORG_METRICS_COUNTS_LABEL: _("Product Type Counts"),
        OrganizationLabelsKeys.ORG_METRICS_BY_FINDINGS_LABEL: _("Product Type Metrics by Findings"),
        OrganizationLabelsKeys.ORG_METRICS_BY_ENDPOINTS_LABEL: _("Product Type Metrics by Affected Endpoints"),
        OrganizationLabelsKeys.ORG_METRICS_TYPE_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Product Type."),
        OrganizationLabelsKeys.ORG_OPTIONS_LABEL: _("Product Type Options"),
        OrganizationLabelsKeys.ORG_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Product Type %(name)s has been created successfully."),
        OrganizationLabelsKeys.ORG_CRITICAL_PRODUCT_LABEL: _("Critical Product"),
        OrganizationLabelsKeys.ORG_KEY_PRODUCT_LABEL: _("Key Product"),
        OrganizationLabelsKeys.ORG_FILTERS_LABEL: _("Product Type"),
        OrganizationLabelsKeys.ORG_FILTERS_LABEL_HELP: _("Search for Product Type names that are an exact match"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_LABEL: _("Product Type Name"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_HELP: _("Search for Product Type names that are an exact match"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_EXACT_LABEL: _("Exact Product Type Name"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_CONTAINS_LABEL: _("Product Type Name Contains"),
        OrganizationLabelsKeys.ORG_FILTERS_NAME_CONTAINS_HELP: _("Search for Product Type names that contain a given pattern"),
        OrganizationLabelsKeys.ORG_FILTERS_TAGS_LABEL: _("Tags (Product Type)"),
        OrganizationLabelsKeys.ORG_USERS_LABEL: _("Product Types this User can access"),
        OrganizationLabelsKeys.ORG_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Product Types."),
        OrganizationLabelsKeys.ORG_USERS_ADD_ORGANIZATIONS_LABEL: _("Add Product Types"),
        OrganizationLabelsKeys.ORG_USERS_DELETE_LABEL: _("Delete Product Type Member"),
        OrganizationLabelsKeys.ORG_USERS_DELETE_SUCCESS_MESSAGE: _("Product Type member deleted successfully."),
        OrganizationLabelsKeys.ORG_USERS_ADD_LABEL: _("Add Product Type Member"),
        OrganizationLabelsKeys.ORG_USERS_ADD_SUCCESS_MESSAGE: _("Product Type members added successfully."),
        OrganizationLabelsKeys.ORG_USERS_UPDATE_LABEL: _("Edit Product Type Member"),
        OrganizationLabelsKeys.ORG_USERS_UPDATE_SUCCESS_MESSAGE: _("Product Type member updated successfully."),
        OrganizationLabelsKeys.ORG_USERS_MINIMUM_NUMBER_WITH_NAME_MESSAGE: _("There must be at least one owner for Product Type %(name)s."),
        OrganizationLabelsKeys.ORG_GROUPS_LABEL: _("Product Types this Group can access"),
        OrganizationLabelsKeys.ORG_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Product Types."),
        OrganizationLabelsKeys.ORG_GROUPS_ADD_ORGANIZATIONS_LABEL: _("Add Product Types"),
        OrganizationLabelsKeys.ORG_GROUPS_NUM_ORGANIZATIONS_LABEL: _("Number of Product Types"),
        OrganizationLabelsKeys.ORG_GROUPS_ADD_LABEL: _("Add Product Type Group"),
        OrganizationLabelsKeys.ORG_GROUPS_ADD_SUCCESS_MESSAGE: _("Product Type groups added successfully."),
        OrganizationLabelsKeys.ORG_GROUPS_UPDATE_LABEL: _("Edit Product Type Group"),
        OrganizationLabelsKeys.ORG_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Product Type group updated successfully."),
        OrganizationLabelsKeys.ORG_GROUPS_DELETE_LABEL: _("Delete Product Type Group"),
        OrganizationLabelsKeys.ORG_GROUPS_DELETE_SUCCESS_MESSAGE: _("Product Type group deleted successfully."),
        OrganizationLabelsKeys.ORG_CREATE_LABEL: _("Add Product Type"),
        OrganizationLabelsKeys.ORG_CREATE_SUCCESS_MESSAGE: _("Product Type added successfully."),
        OrganizationLabelsKeys.ORG_READ_LABEL: _("View Product Type"),
        OrganizationLabelsKeys.ORG_READ_LIST_LABEL: _("List Product Types"),
        OrganizationLabelsKeys.ORG_UPDATE_LABEL: _("Edit Product Type"),
        OrganizationLabelsKeys.ORG_UPDATE_WITH_NAME_LABEL: _("Edit Product Type %(name)s"),
        OrganizationLabelsKeys.ORG_UPDATE_SUCCESS_MESSAGE: _("Product Type updated successfully."),
        OrganizationLabelsKeys.ORG_DELETE_LABEL: _("Delete Product Type"),
        OrganizationLabelsKeys.ORG_DELETE_WITH_NAME_LABEL: _("Delete Product Type %(name)s"),
        OrganizationLabelsKeys.ORG_DELETE_CONFIRM_MESSAGE: _(
            "Deleting this Product Type will remove any related objects associated with it. These relationships are listed below:"),
        OrganizationLabelsKeys.ORG_DELETE_SUCCESS_MESSAGE: _("Product Type and relationships removed."),
        OrganizationLabelsKeys.ORG_DELETE_SUCCESS_ASYNC_MESSAGE: _("Product Type and relationships will be removed in the background."),
        OrganizationLabelsKeys.ORG_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The product type "%(name)s" was deleted'),
        OrganizationLabelsKeys.ORG_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The product type "%(name)s" was deleted by %(user)s'),
    }
