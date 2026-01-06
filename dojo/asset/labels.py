from django.conf import settings
from django.utils.translation import gettext_lazy as _


class AssetLabelsKeys:

    """Directory of text copy used by the Asset model."""

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
    ASSET_FILTERS_TAGS_FILTER_LABEL = "asset.filters.tags_filter_label"
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


# TODO: remove the else: branch once v3 migration is complete
if settings.ENABLE_V3_ORGANIZATION_ASSET_RELABEL:
    labels = {
        AssetLabelsKeys.ASSET_LABEL: _("Asset"),
        AssetLabelsKeys.ASSET_PLURAL_LABEL: _("Assets"),
        AssetLabelsKeys.ASSET_ALL_LABEL: _("All Assets"),
        AssetLabelsKeys.ASSET_WITH_NAME_LABEL: _("Asset '%(name)s'"),
        AssetLabelsKeys.ASSET_NONE_FOUND_MESSAGE: _("No Assets found."),
        AssetLabelsKeys.ASSET_MANAGER_LABEL: _("Asset Manager"),
        AssetLabelsKeys.ASSET_GLOBAL_ROLE_HELP: _("The global role will be applied to all Organizations and Assets."),
        AssetLabelsKeys.ASSET_NOTIFICATIONS_HELP: _("These are your personal settings for this Asset."),
        AssetLabelsKeys.ASSET_OPTIONS_LABEL: _("Asset Options"),
        AssetLabelsKeys.ASSET_OPTIONS_MENU_LABEL: _("Asset Options Menu"),
        AssetLabelsKeys.ASSET_COUNT_LABEL: _("Asset Count"),
        AssetLabelsKeys.ASSET_ENGAGEMENTS_BY_LABEL: _("Engagements by Asset"),
        AssetLabelsKeys.ASSET_LIFECYCLE_LABEL: _("Asset Lifecycle"),
        AssetLabelsKeys.ASSET_TAG_LABEL: _("Asset Tag"),
        AssetLabelsKeys.ASSET_METRICS_TAG_COUNTS_LABEL: _("Asset Tag Counts"),
        AssetLabelsKeys.ASSET_METRICS_TAG_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Asset Tag."),
        AssetLabelsKeys.ASSET_METRICS_CRITICAL_LABEL: _("Critical Asset Metrics"),
        AssetLabelsKeys.ASSET_METRICS_NO_CRITICAL_ERROR_MESSAGE: _("No Critical Assets registered"),
        AssetLabelsKeys.ASSET_METRICS_TOP_TEN_BY_SEVERITY_LABEL: _("Top 10 Assets by bug severity"),
        AssetLabelsKeys.ASSET_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Asset %(name)s has been created successfully."),
        AssetLabelsKeys.ASSET_REPORT_LABEL: _("Asset Report"),
        AssetLabelsKeys.ASSET_REPORT_TITLE: _("Asset Report"),
        AssetLabelsKeys.ASSET_REPORT_WITH_NAME_TITLE: _("Asset Report: %(name)s"),
        AssetLabelsKeys.ASSET_TRACKED_FILES_ADD_LABEL: _("Add Tracked Files to an Asset"),
        AssetLabelsKeys.ASSET_TRACKED_FILES_ADD_SUCCESS_MESSAGE: _("Added Tracked File to an Asset"),
        AssetLabelsKeys.ASSET_TRACKED_FILES_ID_MISMATCH_ERROR_MESSAGE: _(
            "Asset %(asset_id)s does not match Asset of Object %(object_asset_id)s"),
        AssetLabelsKeys.ASSET_FINDINGS_CLOSE_LABEL: _("Close old findings within this Asset"),
        AssetLabelsKeys.ASSET_FINDINGS_CLOSE_HELP: _(
            "Old findings no longer present in the new report get closed as mitigated when importing. If service has been set, only the findings for this service will be closed; if no service is set, only findings without a service will be closed. This affects findings within the same Asset."),
        AssetLabelsKeys.ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Asset Tag Inheritance"),
        AssetLabelsKeys.ASSET_TAG_INHERITANCE_ENABLE_HELP: _(
            "Enables Asset tag inheritance. Any tags added on an Asset will automatically be added to all Engagements, Tests, and Findings."),
        AssetLabelsKeys.ASSET_ENDPOINT_HELP: _("The Asset this Endpoint should be associated with."),
        AssetLabelsKeys.ASSET_CREATE_LABEL: _("Add Asset"),
        AssetLabelsKeys.ASSET_CREATE_SUCCESS_MESSAGE: _("Asset added successfully."),
        AssetLabelsKeys.ASSET_READ_LIST_LABEL: _("Asset List"),
        AssetLabelsKeys.ASSET_UPDATE_LABEL: _("Edit Asset"),
        AssetLabelsKeys.ASSET_UPDATE_SUCCESS_MESSAGE: _("Asset updated successfully."),
        AssetLabelsKeys.ASSET_UPDATE_SLA_CHANGED_MESSAGE: _(
            "All SLA expiration dates for Findings within this Asset will be recalculated asynchronously for the newly assigned SLA configuration."),
        AssetLabelsKeys.ASSET_DELETE_LABEL: _("Delete Asset"),
        AssetLabelsKeys.ASSET_DELETE_WITH_NAME_LABEL: _("Delete Asset %(name)s"),
        AssetLabelsKeys.ASSET_DELETE_CONFIRM_MESSAGE: _(
            "Deleting this Asset will remove any related objects associated with it. These relationships are listed below: "),
        AssetLabelsKeys.ASSET_DELETE_SUCCESS_MESSAGE: _("Asset and relationships removed."),
        AssetLabelsKeys.ASSET_DELETE_SUCCESS_ASYNC_MESSAGE: _("Asset and relationships will be removed in the background."),
        AssetLabelsKeys.ASSET_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The Asset "%(name)s" was deleted'),
        AssetLabelsKeys.ASSET_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The Asset "%(name)s" was deleted by %(user)s'),
        AssetLabelsKeys.ASSET_FILTERS_LABEL: _("Asset"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_LABEL: _("Asset Name"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_HELP: _("Search for Asset names that are an exact match"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_EXACT_LABEL: _("Exact Asset Name"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_CONTAINS_LABEL: _("Asset Name Contains"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_CONTAINS_HELP: _("Search for Asset names that contain a given pattern"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_LABEL: _("Tags (Asset)"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_HELP: _("Filter for Assets with the given tags"),
        AssetLabelsKeys.ASSET_FILTERS_NOT_TAGS_HELP: _("Filter for Assets that do not have the given tags"),
        AssetLabelsKeys.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_LABEL: _("Assets without tags"),
        AssetLabelsKeys.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_HELP: _(
            "Search for tags on an Asset that contain a given pattern, and exclude them"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_FILTER_LABEL: _("Asset with tags"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_FILTER_HELP: _("Filter Assets by the selected tags"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_TAGS_OR_HELP: _(
            "Comma separated list of exact tags present on Asset (uses OR for multiple values)"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_TAGS_AND_HELP: _(
            "Comma separated list of exact tags to match with an AND expression present on Asset"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_TAGS_NOT_HELP: _("Comma separated list of exact tags not present on Asset"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_LIFECYCLES_LABEL: _("Comma separated list of exact Asset lifecycles"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_ASSET_LABEL: _("Asset Tags"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_LABEL: _("Asset Tag"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_HELP: _("Search for tags on an Asset that are an exact match"),
        AssetLabelsKeys.ASSET_FILTERS_NOT_TAGS_ASSET_LABEL: _("Not Asset Tags"),
        AssetLabelsKeys.ASSET_FILTERS_WITHOUT_TAGS_LABEL: _("Asset without tags"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL: _("Asset Tag Contains"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP: _("Search for tags on an Asset that contain a given pattern"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL: _("Asset Tag Does Not Contain"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP: _(
            "Search for tags on an Asset that contain a given pattern, and exclude them"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_LABEL: _("Not Asset Tag"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_HELP: _("Search for tags on an Asset that are an exact match, and exclude them"),
        AssetLabelsKeys.ASSET_USERS_ACCESS_LABEL: _("Assets this User can access"),
        AssetLabelsKeys.ASSET_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Assets."),
        AssetLabelsKeys.ASSET_USERS_ADD_LABEL: _("Add Assets"),
        AssetLabelsKeys.ASSET_USERS_USERS_ADD_LABEL: _("Add Users"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_LABEL: _("Asset Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_ADD_LABEL: _("Add Asset Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_ADD_SUCCESS_MESSAGE: _("Asset members added successfully."),
        AssetLabelsKeys.ASSET_USERS_MEMBER_UPDATE_LABEL: _("Edit Asset Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_UPDATE_SUCCESS_MESSAGE: _("Asset member updated successfully."),
        AssetLabelsKeys.ASSET_USERS_MEMBER_DELETE_LABEL: _("Delete Asset Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_DELETE_SUCCESS_MESSAGE: _("Asset member deleted successfully."),
        AssetLabelsKeys.ASSET_GROUPS_ACCESS_LABEL: _("Assets this Group can access"),
        AssetLabelsKeys.ASSET_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Assets."),
        AssetLabelsKeys.ASSET_GROUPS_MEMBER_LABEL: _("Asset Group"),
        AssetLabelsKeys.ASSET_GROUPS_ADD_LABEL: _("Add Asset Group"),
        AssetLabelsKeys.ASSET_GROUPS_ADD_SUCCESS_MESSAGE: _("Asset groups added successfully."),
        AssetLabelsKeys.ASSET_GROUPS_UPDATE_LABEL: _("Edit Asset Group"),
        AssetLabelsKeys.ASSET_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Asset group updated successfully."),
        AssetLabelsKeys.ASSET_GROUPS_DELETE_LABEL: _("Delete Asset Group"),
        AssetLabelsKeys.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE: _("Asset group deleted successfully."),
        AssetLabelsKeys.ASSET_GROUPS_ADD_ASSETS_LABEL: _("Add Assets"),
        AssetLabelsKeys.ASSET_GROUPS_NUM_ASSETS_LABEL: _("Number of Assets"),
    }
else:
    labels = {
        AssetLabelsKeys.ASSET_LABEL: _("Product"),
        AssetLabelsKeys.ASSET_PLURAL_LABEL: _("Products"),
        AssetLabelsKeys.ASSET_ALL_LABEL: _("All Products"),
        AssetLabelsKeys.ASSET_WITH_NAME_LABEL: _("Product '%(name)s'"),
        AssetLabelsKeys.ASSET_NONE_FOUND_MESSAGE: _("No Products found."),
        AssetLabelsKeys.ASSET_MANAGER_LABEL: _("Product Manager"),
        AssetLabelsKeys.ASSET_GLOBAL_ROLE_HELP: _("The global role will be applied to all Product Types and Products."),
        AssetLabelsKeys.ASSET_NOTIFICATIONS_HELP: _("These are your personal settings for this Product."),
        AssetLabelsKeys.ASSET_OPTIONS_LABEL: _("Product Options"),
        AssetLabelsKeys.ASSET_OPTIONS_MENU_LABEL: _("Product Options Menu"),
        AssetLabelsKeys.ASSET_COUNT_LABEL: _("Product Count"),
        AssetLabelsKeys.ASSET_ENGAGEMENTS_BY_LABEL: _("Engagements by Product"),
        AssetLabelsKeys.ASSET_LIFECYCLE_LABEL: _("Product Lifecycle"),
        AssetLabelsKeys.ASSET_TAG_LABEL: _("Product Tag"),
        AssetLabelsKeys.ASSET_METRICS_TAG_COUNTS_LABEL: _("Product Tag Counts"),
        AssetLabelsKeys.ASSET_METRICS_TAG_COUNTS_ERROR_MESSAGE: _("Please choose month and year and the Product Tag."),
        AssetLabelsKeys.ASSET_METRICS_CRITICAL_LABEL: _("Critical Product Metrics"),
        AssetLabelsKeys.ASSET_METRICS_NO_CRITICAL_ERROR_MESSAGE: _("No Critical Products registered"),
        AssetLabelsKeys.ASSET_METRICS_TOP_TEN_BY_SEVERITY_LABEL: _("Top 10 Products by bug severity"),
        AssetLabelsKeys.ASSET_NOTIFICATION_WITH_NAME_CREATED_MESSAGE: _("Product %(name)s has been created successfully."),
        AssetLabelsKeys.ASSET_REPORT_LABEL: _("Product Report"),
        AssetLabelsKeys.ASSET_REPORT_TITLE: _("Product Report"),
        AssetLabelsKeys.ASSET_REPORT_WITH_NAME_TITLE: _("Product Report: %(name)s"),
        AssetLabelsKeys.ASSET_TRACKED_FILES_ADD_LABEL: _("Add Tracked Files to a Product"),
        AssetLabelsKeys.ASSET_TRACKED_FILES_ADD_SUCCESS_MESSAGE: _("Added Tracked File to a Product"),
        AssetLabelsKeys.ASSET_TRACKED_FILES_ID_MISMATCH_ERROR_MESSAGE: _(
            "Product %(asset_id)s does not match Product of Object %(object_asset_id)s"),
        AssetLabelsKeys.ASSET_FINDINGS_CLOSE_LABEL: _("Close old findings within this Product"),
        AssetLabelsKeys.ASSET_FINDINGS_CLOSE_HELP: _(
            "Old findings no longer present in the new report get closed as mitigated when importing. If service has been set, only the findings for this service will be closed; if no service is set, only findings without a service will be closed. This affects findings within the same product."),
        AssetLabelsKeys.ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Product Tag Inheritance"),
        AssetLabelsKeys.ASSET_TAG_INHERITANCE_ENABLE_HELP: _(
            "Enables Product tag inheritance. Any tags added on an Product will automatically be added to all Engagements, Tests, and Findings."),
        AssetLabelsKeys.ASSET_ENDPOINT_HELP: _("The Product this Endpoint should be associated with."),
        AssetLabelsKeys.ASSET_CREATE_LABEL: _("Add Product"),
        AssetLabelsKeys.ASSET_CREATE_SUCCESS_MESSAGE: _("Product added successfully."),
        AssetLabelsKeys.ASSET_READ_LIST_LABEL: _("Product List"),
        AssetLabelsKeys.ASSET_UPDATE_LABEL: _("Edit Product"),
        AssetLabelsKeys.ASSET_UPDATE_SUCCESS_MESSAGE: _("Product updated successfully."),
        AssetLabelsKeys.ASSET_UPDATE_SLA_CHANGED_MESSAGE: _(
            "All SLA expiration dates for Findings within this Product will be recalculated asynchronously for the newly assigned SLA configuration."),
        AssetLabelsKeys.ASSET_DELETE_LABEL: _("Delete Product"),
        AssetLabelsKeys.ASSET_DELETE_WITH_NAME_LABEL: _("Delete Product %(name)s"),
        AssetLabelsKeys.ASSET_DELETE_CONFIRM_MESSAGE: _(
            "Deleting this Product will remove any related objects associated with it. These relationships are listed below: "),
        AssetLabelsKeys.ASSET_DELETE_SUCCESS_MESSAGE: _("Product and relationships removed."),
        AssetLabelsKeys.ASSET_DELETE_SUCCESS_ASYNC_MESSAGE: _("Product and relationships will be removed in the background."),
        AssetLabelsKeys.ASSET_DELETE_WITH_NAME_SUCCESS_MESSAGE: _('The product "%(name)s" was deleted'),
        AssetLabelsKeys.ASSET_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE: _('The product "%(name)s" was deleted by %(user)s'),
        AssetLabelsKeys.ASSET_FILTERS_LABEL: _("Product"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_LABEL: _("Product Name"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_HELP: _("Search for Product names that are an exact match"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_EXACT_LABEL: _("Exact Product Name"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_CONTAINS_LABEL: _("Product Name Contains"),
        AssetLabelsKeys.ASSET_FILTERS_NAME_CONTAINS_HELP: _("Search for Product names that contain a given pattern"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_LABEL: _("Tags (Product)"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_HELP: _("Filter for Products with the given tags"),
        AssetLabelsKeys.ASSET_FILTERS_NOT_TAGS_HELP: _("Filter for Products that do not have the given tags"),
        AssetLabelsKeys.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_LABEL: _("Products without tags"),
        AssetLabelsKeys.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_HELP: _(
            "Search for tags on an Product that contain a given pattern, and exclude them"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_FILTER_LABEL: _("Product with tags"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_FILTER_HELP: _("Filter Products by the selected tags"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_TAGS_OR_HELP: _(
            "Comma separated list of exact tags present on Product (uses OR for multiple values)"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_TAGS_AND_HELP: _(
            "Comma separated list of exact tags to match with an AND expression present on Product"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_TAGS_NOT_HELP: _("Comma separated list of exact tags not present on Product"),
        AssetLabelsKeys.ASSET_FILTERS_CSV_LIFECYCLES_LABEL: _("Comma separated list of exact Product lifecycles"),
        AssetLabelsKeys.ASSET_FILTERS_TAGS_ASSET_LABEL: _("Product Tags"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_LABEL: _("Product Tag"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_HELP: _("Search for tags on an Product that are an exact match"),
        AssetLabelsKeys.ASSET_FILTERS_NOT_TAGS_ASSET_LABEL: _("Not Product Tags"),
        AssetLabelsKeys.ASSET_FILTERS_WITHOUT_TAGS_LABEL: _("Product without tags"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL: _("Product Tag Contains"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP: _("Search for tags on an Product that contain a given pattern"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL: _("Product Tag Does Not Contain"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP: _(
            "Search for tags on an Product that contain a given pattern, and exclude them"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_LABEL: _("Not Product Tag"),
        AssetLabelsKeys.ASSET_FILTERS_TAG_NOT_HELP: _("Search for tags on an Product that are an exact match, and exclude them"),
        AssetLabelsKeys.ASSET_USERS_ACCESS_LABEL: _("Products this User can access"),
        AssetLabelsKeys.ASSET_USERS_NO_ACCESS_MESSAGE: _("This User is not assigned to any Products."),
        AssetLabelsKeys.ASSET_USERS_ADD_LABEL: _("Add Products"),
        AssetLabelsKeys.ASSET_USERS_USERS_ADD_LABEL: _("Add Users"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_LABEL: _("Product Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_ADD_LABEL: _("Add Product Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_ADD_SUCCESS_MESSAGE: _("Product members added successfully."),
        AssetLabelsKeys.ASSET_USERS_MEMBER_UPDATE_LABEL: _("Edit Product Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_UPDATE_SUCCESS_MESSAGE: _("Product member updated successfully."),
        AssetLabelsKeys.ASSET_USERS_MEMBER_DELETE_LABEL: _("Delete Product Member"),
        AssetLabelsKeys.ASSET_USERS_MEMBER_DELETE_SUCCESS_MESSAGE: _("Product member deleted successfully."),
        AssetLabelsKeys.ASSET_GROUPS_ACCESS_LABEL: _("Products this Group can access"),
        AssetLabelsKeys.ASSET_GROUPS_NO_ACCESS_MESSAGE: _("This Group cannot access any Products."),
        AssetLabelsKeys.ASSET_GROUPS_MEMBER_LABEL: _("Product Group"),
        AssetLabelsKeys.ASSET_GROUPS_ADD_LABEL: _("Add Product Group"),
        AssetLabelsKeys.ASSET_GROUPS_ADD_SUCCESS_MESSAGE: _("Product groups added successfully."),
        AssetLabelsKeys.ASSET_GROUPS_UPDATE_LABEL: _("Edit Product Group"),
        AssetLabelsKeys.ASSET_GROUPS_UPDATE_SUCCESS_MESSAGE: _("Product group updated successfully."),
        AssetLabelsKeys.ASSET_GROUPS_DELETE_LABEL: _("Delete Product Group"),
        AssetLabelsKeys.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE: _("Product group deleted successfully."),
        AssetLabelsKeys.ASSET_GROUPS_ADD_ASSETS_LABEL: _("Add Products"),
        AssetLabelsKeys.ASSET_GROUPS_NUM_ASSETS_LABEL: _("Number of Products"),
    }
