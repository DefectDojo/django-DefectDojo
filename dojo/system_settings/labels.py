from django.conf import settings
from django.utils.translation import gettext_lazy as _


class SystemSettingsLabelsKeys:

    """Directory of text copy used by the System_Settings model."""

    SETTINGS_TRACKED_FILES_ENABLE_LABEL = "settings.tracked_files.enable_label"
    SETTINGS_TRACKED_FILES_ENABLE_HELP = "settings.tracked_files.enable_help"
    SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL = "settings.asset_grading.enforce_verified_label"
    SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP = "settings.asset_grading.enforce_verified_help"
    SETTINGS_ASSET_GRADING_ENABLE_LABEL = "settings.asset_grading.enable_label"
    SETTINGS_ASSET_GRADING_ENABLE_HELP = "settings.asset_grading.enable_help"
    SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL = "settings.asset_tag_inheritance.enable_label"
    SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP = "settings.asset_tag_inheritance.enable_help"


# TODO: remove the else: branch once v3 migration is complete
if settings.ENABLE_V3_ORGANIZATION_ASSET_RELABEL:
    labels = {
        SystemSettingsLabelsKeys.SETTINGS_TRACKED_FILES_ENABLE_LABEL: _("Enable Tracked Asset Files"),
        SystemSettingsLabelsKeys.SETTINGS_TRACKED_FILES_ENABLE_HELP: _("With this setting turned off, tracked Asset files will be disabled in the user interface."),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL: _("Enforce Verified Status - Asset Grading"),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP: _("When enabled, findings must have a verified status to be considered as part of an Asset's grading."),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENABLE_LABEL: _("Enable Asset Grading"),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENABLE_HELP: _("Displays a grade letter next to an Asset to show the overall health."),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Asset Tag Inheritance"),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP: _("Enables Asset tag inheritance globally for all Assets. Any tags added on an Asset will automatically be added to all Engagements, Tests, and Findings."),
    }
else:
    labels = {
        SystemSettingsLabelsKeys.SETTINGS_TRACKED_FILES_ENABLE_LABEL: _("Enable Product Tracking Files"),
        SystemSettingsLabelsKeys.SETTINGS_TRACKED_FILES_ENABLE_HELP: _("With this setting turned off, the product tracking files will be disabled in the user interface."),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_LABEL: _("Enforce Verified Status - Product Grading"),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENFORCE_VERIFIED_HELP: _("When enabled, findings must have a verified status to be considered as part of a product's grading."),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENABLE_LABEL: _("Enable Product Grading"),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_GRADING_ENABLE_HELP: _("Displays a grade letter next to a product to show the overall health."),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_LABEL: _("Enable Product Tag Inheritance"),
        SystemSettingsLabelsKeys.SETTINGS_ASSET_TAG_INHERITANCE_ENABLE_HELP: _("Enables product tag inheritance globally for all products. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings"),
    }
