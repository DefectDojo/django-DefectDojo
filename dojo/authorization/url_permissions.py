from django.conf import settings

from dojo.location.models import Location
from dojo.models import (
    App_Analysis,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Test,
)

# ---------------------------------------------------------------------------
# URL_PERMISSIONS: maps Django URL names to authorization checks.
#
# Each key is a URL name (from urls.py).
# Each value is a list of check tuples. ALL checks in the list must pass.
#
# Check tuple formats:
#   ("object",  ModelClass, "view", "kwarg_name")
#   ("global",  "view")
#   ("config",  "permission.string")
# ---------------------------------------------------------------------------

URL_PERMISSIONS = {
    # -----------------------------------------------------------------------
    # Product Type (dojo/product_type/views.py  ->  dojo/organization/urls.py)
    # -----------------------------------------------------------------------
    "add_product_type": [("global", "add")],
    "view_product_type": [("object", Product_Type, "view", "ptid")],
    "edit_product_type": [("object", Product_Type, "edit", "ptid")],
    "delete_product_type": [("object", Product_Type, "delete", "ptid")],

    # -----------------------------------------------------------------------
    # Product (dojo/product/views.py  ->  dojo/asset/urls.py)
    # -----------------------------------------------------------------------
    "view_product": [("object", Product, "view", "pid")],
    "view_product_components": [("object", Product, "view", "pid")],
    "view_product_metrics": [("object", Product, "view", "pid")],
    "async_burndown_metrics": [("object", Product, "view", "pid")],
    "view_engagements": [("object", Product, "view", "pid")],
    "edit_product": [("object", Product, "edit", "pid")],
    "delete_product": [("object", Product, "delete", "pid")],
    "new_eng_for_prod": [("object", Product, "add", "pid")],
    "new_eng_for_prod_cicd": [("object", Product, "add", "pid")],
    "new_tech_for_prod": [("object", Product, "add", "pid")],
    "edit_technology": [("object", App_Analysis, "edit", "tid")],
    "delete_technology": [("object", App_Analysis, "delete", "tid")],
    "add_meta_data": [("object", Product, "edit", "pid")],
    "edit_meta_data": [("object", Product, "edit", "pid")],
    "edit_notifications": [("object", Product, "view", "pid")],
    "engagement_presets": [("object", Product, "view", "pid")],
    "edit_engagement_presets": [("object", Product, "edit", "pid")],
    "add_engagement_presets": [("object", Product, "edit", "pid")],
    "delete_engagement_presets": [("object", Product, "edit", "pid")],
    "add_api_scan_configuration": [("object", Product, "add", "pid")],
    "view_api_scan_configurations": [("object", Product, "view", "pid")],
    "edit_api_scan_configuration": [("object", Product_API_Scan_Configuration, "edit", "pascid")],
    "delete_api_scan_configuration": [("object", Product_API_Scan_Configuration, "delete", "pascid")],

    # -----------------------------------------------------------------------
    # Engagement (dojo/engagement/ui/views.py  ->  dojo/engagement/ui/urls.py)
    # -----------------------------------------------------------------------
    "edit_engagement": [("object", Engagement, "edit", "eid")],
    "delete_engagement": [("object", Engagement, "delete", "eid")],
    "copy_engagement": [("object", Engagement, "edit", "eid")],
    "add_tests": [("object", Engagement, "add", "eid")],
    "close_engagement": [("object", Engagement, "edit", "eid")],
    "engagement_unlink_jira": [("object", Engagement, "edit", "eid")],
    "reopen_engagement": [("object", Engagement, "edit", "eid")],
    "complete_checklist": [("object", Engagement, "edit", "eid")],
    "add_risk_acceptance": [("object", Engagement, "edit", "eid")],
    "view_risk_acceptance": [("object", Engagement, "view", "eid")],
    "edit_risk_acceptance": [("object", Engagement, "edit", "eid")],
    "expire_risk_acceptance": [("object", Engagement, "edit", "eid")],
    "reinstate_risk_acceptance": [("object", Engagement, "edit", "eid")],
    "delete_risk_acceptance": [("object", Engagement, "edit", "eid")],
    "download_risk_acceptance": [("object", Engagement, "view", "eid")],
    "upload_threatmodel": [("object", Engagement, "edit", "eid")],
    "view_threatmodel": [("object", Engagement, "view", "eid")],
    "engagement_ics": [("object", Engagement, "view", "eid")],

    # -----------------------------------------------------------------------
    # Test (dojo/test/views.py  ->  dojo/test/urls.py)
    # -----------------------------------------------------------------------
    "edit_test": [("object", Test, "edit", "tid")],
    "delete_test": [("object", Test, "delete", "tid")],
    "copy_test": [("object", Test, "edit", "tid")],
    "test_ics": [("object", Test, "view", "tid")],
    "add_finding_from_template": [("object", Test, "add", "tid")],
    "search": [("object", Test, "view", "tid")],

    # -----------------------------------------------------------------------
    # Finding (dojo/finding/views.py  ->  dojo/finding/urls.py)
    # -----------------------------------------------------------------------
    "close_finding": [("object", Finding, "edit", "fid")],
    "verify_finding": [("object", Finding, "edit", "fid")],
    "defect_finding_review": [("object", Finding, "edit", "fid")],
    "reopen_finding": [("object", Finding, "edit", "fid")],
    "copy_finding": [("object", Finding, "edit", "fid")],
    "remediation_date": [("object", Finding, "edit", "fid")],
    "touch_finding": [("object", Finding, "edit", "fid")],
    "simple_risk_accept_finding": [("object", Finding, "edit", "fid")],
    "risk_unaccept_finding": [("object", Finding, "edit", "fid")],
    "request_finding_review": [("object", Finding, "view", "fid")],
    "clear_finding_review": [("object", Finding, "edit", "fid")],
    "mktemplate": [("global", "add")],
    "find_template_to_apply": [("object", Finding, "edit", "fid")],
    "choose_finding_template_options": [("object", Finding, "edit", "fid")],
    "apply_template_to_finding": [("object", Finding, "edit", "fid")],
    "merge_finding": [("object", Product, "edit", "pid")],
    "merge_finding_product": [("object", Product, "edit", "pid")],
    "mark_finding_duplicate": [("object", Finding, "edit", "original_id")],
    "reset_finding_duplicate_status": [("object", Finding, "edit", "duplicate_id")],
    "set_finding_as_original": [("object", Finding, "edit", "finding_id")],
    "finding_unlink_jira": [("object", Finding, "edit", "fid")],
    "finding_push_to_jira": [("object", Finding, "edit", "fid")],

    # Finding templates
    "templates": [("global", "edit")],
    "export_template": [("global", "edit")],
    "add_template": [("global", "add")],
    "edit_template": [("global", "edit")],
    "delete_template": [("global", "delete")],

    # -----------------------------------------------------------------------
    # Finding Group (dojo/finding_group/views.py  ->  dojo/finding_group/urls.py)
    # -----------------------------------------------------------------------
    "view_finding_group": [("object", Finding_Group, "view", "fgid")],
    "delete_finding_group": [("object", Finding_Group, "delete", "fgid")],
    "finding_group_push_to_jira": [("object", Finding_Group, "edit", "fgid")],
    "finding_group_unlink_jira": [("object", Finding_Group, "edit", "fgid")],

    # -----------------------------------------------------------------------
    # Endpoint (dojo/endpoint/views.py  ->  dojo/endpoint/urls.py)
    # -----------------------------------------------------------------------
    "view_endpoint": [("object", Endpoint, "view", "eid")],
    "view_endpoint_host": [("object", Endpoint, "view", "eid")],
    "edit_endpoint": [("object", Endpoint, "edit", "eid")],
    "add_endpoint": [("object", Product, "add", "pid")],
    "delete_endpoint": [("object", Endpoint, "delete", "eid")],
    "add_endpoint_meta_data": [("object", Endpoint, "edit", "eid")],
    "edit_endpoint_meta_data": [("object", Endpoint, "edit", "eid")],
    "endpoints_status_bulk": [("object", Finding, "edit", "fid")],
    "import_endpoint_meta": [("object", Product, "edit", "pid")],
    "endpoint_report": [("object", Endpoint, "view", "eid")],
    "endpoint_host_report": [("object", Endpoint, "view", "eid")],

    # -----------------------------------------------------------------------
    # URL / Location UI (dojo/url/ui/views.py  ->  dojo/url/ui/urls.py)
    #
    # When V3_FEATURE_LOCATIONS is enabled, the endpoint URL names above
    # are remapped below to the active routes' model + kwarg names.
    # -----------------------------------------------------------------------
    "add_endpoint_to_product": [("object", Product, "add", "product_id")],
    "add_endpoint_to_finding": [("object", Finding, "add", "finding_id")],

    # -----------------------------------------------------------------------
    # Reports (dojo/reports/views.py  ->  dojo/reports/urls.py)
    # -----------------------------------------------------------------------
    "product_type_report": [("object", Product_Type, "view", "ptid")],
    "product_report": [("object", Product, "view", "pid")],
    "product_endpoint_report": [("object", Product, "view", "pid")],
    "engagement_report": [("object", Engagement, "view", "eid")],
    "test_report": [("object", Test, "view", "tid")],

    # -----------------------------------------------------------------------
    # Tool Product (dojo/tool_product/views.py  ->  dojo/tool_product/urls.py)
    # -----------------------------------------------------------------------
    "new_tool_product": [("object", Product, "edit", "pid")],
    "all_tool_product": [("object", Product, "edit", "pid")],
    "edit_tool_product": [("object", Product, "edit", "pid")],
    "delete_tool_product": [("object", Product, "edit", "pid")],

    # -----------------------------------------------------------------------
    # Tool Type (dojo/tool_type/views.py  ->  dojo/tool_type/urls.py)
    # -----------------------------------------------------------------------
    "add_tool_type": [("config", "dojo.add_tool_type")],
    "edit_tool_type": [("config", "dojo.change_tool_type")],
    "tool_type": [("config", "dojo.view_tool_type")],

    # -----------------------------------------------------------------------
    # Tool Config (dojo/tool_config/views.py  ->  dojo/tool_config/urls.py)
    # -----------------------------------------------------------------------
    "add_tool_config": [("config", "dojo.add_tool_configuration")],
    "edit_tool_config": [("config", "dojo.change_tool_configuration")],
    "tool_config": [("config", "dojo.view_tool_configuration")],

    # -----------------------------------------------------------------------
    # Benchmark (dojo/benchmark/views.py  ->  dojo/benchmark/urls.py)
    # -----------------------------------------------------------------------
    "view_product_benchmark": [("object", Product, "edit", "pid")],
    "edit_benchmark": [("object", Product, "edit", "pid")],
    "delete_product_benchmark": [("object", Product, "delete", "pid")],
    "update_product_benchmark": [("object", Product, "edit", "pid")],
    "update_product_benchmark_summary": [("object", Product, "edit", "pid")],

    # -----------------------------------------------------------------------
    # Object / Tracked Files (dojo/object/views.py  ->  dojo/object/urls.py)
    # -----------------------------------------------------------------------
    "new_object": [("object", Product, "add", "pid")],
    "view_objects": [("object", Product, "view", "pid")],
    "edit_object": [("object", Product, "edit", "pid")],
    "delete_object": [("object", Product, "delete", "pid")],

    # -----------------------------------------------------------------------
    # Note Type (dojo/note_type/views.py  ->  dojo/note_type/urls.py)
    # -----------------------------------------------------------------------
    "note_type": [("config", "dojo.view_note_type")],
    "edit_note_type": [("config", "dojo.change_note_type")],
    "disable_note_type": [("config", "dojo.change_note_type")],
    "enable_note_type": [("config", "dojo.change_note_type")],
    "add_note_type": [("config", "dojo.add_note_type")],

    # -----------------------------------------------------------------------
    # SLA Config (dojo/sla_config/views.py  ->  dojo/sla_config/urls.py)
    # -----------------------------------------------------------------------
    "new_sla_config": [("config", "dojo.add_sla_configuration")],
    "edit_sla_config": [("config", "dojo.change_sla_configuration")],
    "sla_config": [("config", "dojo.view_sla_configuration")],

    # -----------------------------------------------------------------------
    # Regulations (dojo/regulations/views.py  ->  dojo/regulations/urls.py)
    # -----------------------------------------------------------------------
    "new_regulation": [("config", "dojo.add_regulation")],
    "edit_regulations": [("config", "dojo.change_regulation")],

    # -----------------------------------------------------------------------
    # Development Environment (dojo/development_environment/views.py)
    # -----------------------------------------------------------------------
    "add_dev_env": [("config", "dojo.add_development_environment")],
    "edit_dev_env": [("config", "dojo.change_development_environment")],

    # -----------------------------------------------------------------------
    # GitHub Issue Link (dojo/github_issue_link/views.py)
    # -----------------------------------------------------------------------
    "add_github": [("config", "dojo.add_github_conf")],
    "github": [("config", "dojo.view_github_conf")],
    "delete_github": [("config", "dojo.delete_github_conf")],

    # -----------------------------------------------------------------------
    # Test Type (dojo/test_type/views.py  ->  dojo/test_type/urls.py)
    # -----------------------------------------------------------------------
    "add_test_type": [("config", "dojo.add_test_type")],
    "edit_test_type": [("config", "dojo.change_test_type")],

    # -----------------------------------------------------------------------
    # Announcement (dojo/announcement/views.py)
    # -----------------------------------------------------------------------
    "configure_announcement": [("config", "dojo.change_announcement")],

    # -----------------------------------------------------------------------
    # Banner (dojo/banner/views.py)
    # -----------------------------------------------------------------------
    "configure_banner": [("config", "dojo.change_bannerconf")],

    # -----------------------------------------------------------------------
    # User (dojo/user/views.py  ->  dojo/user/urls.py)
    # -----------------------------------------------------------------------
    "users": [("config", "auth.view_user")],
    "add_user": [("config", "auth.add_user")],
    "view_user": [("config", "auth.view_user")],
    "edit_user": [("config", "auth.change_user")],
    "delete_user": [("config", "auth.delete_user")],
    "edit_user_permissions": [("config", "auth.change_permission")],

    # -----------------------------------------------------------------------
    # Survey / Questionnaire (dojo/survey/views.py  ->  dojo/survey/urls.py)
    # -----------------------------------------------------------------------
    # Engagement-scoped questionnaire views
    "delete_engagement_survey": [("object", Engagement, "edit", "eid")],
    "assign_questionnaire": [("object", Engagement, "edit", "eid")],
    "view_questionnaire": [("object", Engagement, "view", "eid")],
    "add_questionnaire": [("object", Engagement, "edit", "eid")],

    # Global questionnaire management
    "edit_questionnaire": [("config", "dojo.change_engagement_survey")],
    "delete_questionnaire": [("config", "dojo.delete_engagement_survey")],
    "create_questionnaire": [("config", "dojo.add_engagement_survey")],
    "questionnaire": [("config", "dojo.view_engagement_survey")],
    "questions": [("config", "dojo.view_question")],
    "create_question": [("config", "dojo.add_question")],
    "edit_question": [("config", "dojo.change_question")],
    "add_choices": [("config", "dojo.change_question")],
    "add_empty_questionnaire": [("config", "dojo.add_engagement_survey")],
    "view_empty_survey": [("config", "dojo.view_engagement_survey")],
    "delete_empty_questionnaire": [("config", "dojo.delete_engagement_survey")],
    "delete_general_questionnaire": [("config", "dojo.delete_engagement_survey")],
}


# When the V3 location routes are active they replace the legacy endpoint
# routes (dojo/urls.py). The new routes operate on Location rows and carry
# a "location_id" kwarg, so the URL-name -> check mapping needs to point
# at the active route's model + kwarg for the middleware to apply the
# right per-object check.
if settings.V3_FEATURE_LOCATIONS:
    URL_PERMISSIONS.update({
        "view_endpoint":           [("object", Location, "view", "location_id")],
        "view_endpoint_host":      [("object", Location, "view", "location_id")],
        "edit_endpoint":           [("object", Location, "edit", "location_id")],
        "delete_endpoint":         [("object", Location, "delete", "location_id")],
        "endpoint_report":         [("object", Location, "view", "location_id")],
        "endpoint_host_report":    [("object", Location, "view", "location_id")],
        "add_endpoint_meta_data":  [("object", Location, "edit", "location_id")],
        "edit_endpoint_meta_data": [("object", Location, "edit", "location_id")],
        # The V3 "add_endpoint" route is an alias for add_endpoint_to_product;
        # it carries product_id rather than the legacy pid.
        "add_endpoint":            [("object", Product, "add", "product_id")],
        # Remaining V3 routes that share a URL name with the legacy module
        # but carry a different kwarg.
        "import_endpoint_meta":    [("object", Product, "edit", "product_id")],
        "endpoints_status_bulk":   [("object", Finding, "edit", "finding_id")],
    })
