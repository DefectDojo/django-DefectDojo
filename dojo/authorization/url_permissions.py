from dojo.authorization.models import (
    Dojo_Group_Member,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    App_Analysis,
    Cred_Mapping,
    Dojo_Group,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Stub_Finding,
    Test,
)

# ---------------------------------------------------------------------------
# URL_PERMISSIONS: maps Django URL names to authorization checks.
#
# Each key is a URL name (from urls.py).
# Each value is a list of check tuples. ALL checks in the list must pass.
#
# Check tuple formats:
#   ("object",  ModelClass, Permissions.Perm, "kwarg_name")
#   ("global",  Permissions.Perm)
#   ("config",  "permission.string")
# ---------------------------------------------------------------------------

URL_PERMISSIONS = {
    # -----------------------------------------------------------------------
    # Product Type (dojo/product_type/views.py  ->  dojo/organization/urls.py)
    # -----------------------------------------------------------------------
    "add_product_type": [("global", Permissions.Product_Type_Add)],
    "view_product_type": [("object", Product_Type, Permissions.Product_Type_View, "ptid")],
    "edit_product_type": [("object", Product_Type, Permissions.Product_Type_Edit, "ptid")],
    "delete_product_type": [("object", Product_Type, Permissions.Product_Type_Delete, "ptid")],
    "add_product_type_member": [("object", Product_Type, Permissions.Product_Type_Manage_Members, "ptid")],
    "edit_product_type_member": [("object", Product_Type_Member, Permissions.Product_Type_Manage_Members, "memberid")],
    "delete_product_type_member": [("object", Product_Type_Member, Permissions.Product_Type_Member_Delete, "memberid")],
    "add_product_type_group": [("object", Product_Type, Permissions.Product_Type_Group_Add, "ptid")],
    "edit_product_type_group": [("object", Product_Type_Group, Permissions.Product_Type_Group_Edit, "groupid")],
    "delete_product_type_group": [("object", Product_Type_Group, Permissions.Product_Type_Group_Delete, "groupid")],

    # -----------------------------------------------------------------------
    # Product (dojo/product/views.py  ->  dojo/asset/urls.py)
    # -----------------------------------------------------------------------
    "view_product": [("object", Product, Permissions.Product_View, "pid")],
    "view_product_components": [("object", Product, Permissions.Component_View, "pid")],
    "view_product_metrics": [("object", Product, Permissions.Product_View, "pid")],
    "async_burndown_metrics": [("object", Product, Permissions.Product_View, "pid")],
    "view_engagements": [("object", Product, Permissions.Engagement_View, "pid")],
    "edit_product": [("object", Product, Permissions.Product_Edit, "pid")],
    "delete_product": [("object", Product, Permissions.Product_Delete, "pid")],
    "new_eng_for_prod": [("object", Product, Permissions.Engagement_Add, "pid")],
    "new_eng_for_prod_cicd": [("object", Product, Permissions.Engagement_Add, "pid")],
    "new_tech_for_prod": [("object", Product, Permissions.Technology_Add, "pid")],
    "edit_technology": [("object", App_Analysis, Permissions.Technology_Edit, "tid")],
    "delete_technology": [("object", App_Analysis, Permissions.Technology_Delete, "tid")],
    "add_meta_data": [("object", Product, Permissions.Product_Edit, "pid")],
    "edit_meta_data": [("object", Product, Permissions.Product_Edit, "pid")],
    "edit_notifications": [("object", Product, Permissions.Product_View, "pid")],
    "engagement_presets": [("object", Product, Permissions.Product_View, "pid")],
    "edit_engagement_presets": [("object", Product, Permissions.Product_Edit, "pid")],
    "add_engagement_presets": [("object", Product, Permissions.Product_Edit, "pid")],
    "delete_engagement_presets": [("object", Product, Permissions.Product_Edit, "pid")],
    "add_product_member": [("object", Product, Permissions.Product_Manage_Members, "pid")],
    "edit_product_member": [("object", Product_Member, Permissions.Product_Manage_Members, "memberid")],
    "delete_product_member": [("object", Product_Member, Permissions.Product_Member_Delete, "memberid")],
    "add_api_scan_configuration": [("object", Product, Permissions.Product_API_Scan_Configuration_Add, "pid")],
    "view_api_scan_configurations": [("object", Product, Permissions.Product_View, "pid")],
    "edit_api_scan_configuration": [("object", Product_API_Scan_Configuration, Permissions.Product_API_Scan_Configuration_Edit, "pascid")],
    "delete_api_scan_configuration": [("object", Product_API_Scan_Configuration, Permissions.Product_API_Scan_Configuration_Delete, "pascid")],
    "add_product_group": [("object", Product, Permissions.Product_Group_Add, "pid")],
    "edit_product_group": [("object", Product_Group, Permissions.Product_Group_Edit, "groupid")],
    "delete_product_group": [("object", Product_Group, Permissions.Product_Group_Delete, "groupid")],

    # -----------------------------------------------------------------------
    # Engagement (dojo/engagement/views.py  ->  dojo/engagement/urls.py)
    # -----------------------------------------------------------------------
    "edit_engagement": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "delete_engagement": [("object", Engagement, Permissions.Engagement_Delete, "eid")],
    "copy_engagement": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "add_tests": [("object", Engagement, Permissions.Test_Add, "eid")],
    "close_engagement": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "engagement_unlink_jira": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "reopen_engagement": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "complete_checklist": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "add_risk_acceptance": [("object", Engagement, Permissions.Risk_Acceptance, "eid")],
    "view_risk_acceptance": [("object", Engagement, Permissions.Engagement_View, "eid")],
    "edit_risk_acceptance": [("object", Engagement, Permissions.Risk_Acceptance, "eid")],
    "expire_risk_acceptance": [("object", Engagement, Permissions.Risk_Acceptance, "eid")],
    "reinstate_risk_acceptance": [("object", Engagement, Permissions.Risk_Acceptance, "eid")],
    "delete_risk_acceptance": [("object", Engagement, Permissions.Risk_Acceptance, "eid")],
    "download_risk_acceptance": [("object", Engagement, Permissions.Engagement_View, "eid")],
    "upload_threatmodel": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "view_threatmodel": [("object", Engagement, Permissions.Engagement_View, "eid")],
    "engagement_ics": [("object", Engagement, Permissions.Engagement_View, "eid")],

    # -----------------------------------------------------------------------
    # Test (dojo/test/views.py  ->  dojo/test/urls.py)
    # -----------------------------------------------------------------------
    "edit_test": [("object", Test, Permissions.Test_Edit, "tid")],
    "delete_test": [("object", Test, Permissions.Test_Delete, "tid")],
    "copy_test": [("object", Test, Permissions.Test_Edit, "tid")],
    "test_ics": [("object", Test, Permissions.Test_View, "tid")],
    "add_finding_from_template": [("object", Test, Permissions.Finding_Add, "tid")],
    "search": [("object", Test, Permissions.Test_View, "tid")],

    # -----------------------------------------------------------------------
    # Finding (dojo/finding/views.py  ->  dojo/finding/urls.py)
    # -----------------------------------------------------------------------
    "close_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "verify_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "defect_finding_review": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "reopen_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "copy_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "remediation_date": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "touch_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "simple_risk_accept_finding": [("object", Finding, Permissions.Risk_Acceptance, "fid")],
    "risk_unaccept_finding": [("object", Finding, Permissions.Risk_Acceptance, "fid")],
    "request_finding_review": [("object", Finding, Permissions.Finding_View, "fid")],
    "clear_finding_review": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "mktemplate": [("global", Permissions.Finding_Add)],
    "find_template_to_apply": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "choose_finding_template_options": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "apply_template_to_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "merge_finding": [("object", Product, Permissions.Finding_Edit, "pid")],
    "merge_finding_product": [("object", Product, Permissions.Finding_Edit, "pid")],
    "mark_finding_duplicate": [("object", Finding, Permissions.Finding_Edit, "original_id")],
    "reset_finding_duplicate_status": [("object", Finding, Permissions.Finding_Edit, "duplicate_id")],
    "set_finding_as_original": [("object", Finding, Permissions.Finding_Edit, "finding_id")],
    "finding_unlink_jira": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "finding_push_to_jira": [("object", Finding, Permissions.Finding_Edit, "fid")],

    # Finding templates
    "templates": [("global", Permissions.Finding_Edit)],
    "export_template": [("global", Permissions.Finding_Edit)],
    "add_template": [("global", Permissions.Finding_Add)],
    "edit_template": [("global", Permissions.Finding_Edit)],
    "delete_template": [("global", Permissions.Finding_Delete)],

    # Stub findings
    "add_stub_finding": [("object", Test, Permissions.Finding_Add, "tid")],
    "delete_stub_finding": [("object", Stub_Finding, Permissions.Finding_Delete, "fid")],
    "promote_to_finding": [("object", Stub_Finding, Permissions.Finding_Edit, "fid")],

    # -----------------------------------------------------------------------
    # Finding Group (dojo/finding_group/views.py  ->  dojo/finding_group/urls.py)
    # -----------------------------------------------------------------------
    "view_finding_group": [("object", Finding_Group, Permissions.Finding_Group_View, "fgid")],
    "delete_finding_group": [("object", Finding_Group, Permissions.Finding_Group_Delete, "fgid")],
    "finding_group_push_to_jira": [("object", Finding_Group, Permissions.Finding_Group_Edit, "fgid")],
    "finding_group_unlink_jira": [("object", Finding_Group, Permissions.Finding_Group_Edit, "fgid")],

    # -----------------------------------------------------------------------
    # Endpoint (dojo/endpoint/views.py  ->  dojo/endpoint/urls.py)
    # -----------------------------------------------------------------------
    "view_endpoint": [("object", Endpoint, Permissions.Location_View, "eid")],
    "view_endpoint_host": [("object", Endpoint, Permissions.Location_View, "eid")],
    "edit_endpoint": [("object", Endpoint, Permissions.Location_Edit, "eid")],
    "add_endpoint": [("object", Product, Permissions.Location_Add, "pid")],
    "delete_endpoint": [("object", Endpoint, Permissions.Location_Delete, "eid")],
    "add_endpoint_meta_data": [("object", Endpoint, Permissions.Location_Edit, "eid")],
    "edit_endpoint_meta_data": [("object", Endpoint, Permissions.Location_Edit, "eid")],
    "endpoints_status_bulk": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "import_endpoint_meta": [("object", Product, Permissions.Location_Edit, "pid")],
    "endpoint_report": [("object", Endpoint, Permissions.Location_View, "eid")],
    "endpoint_host_report": [("object", Endpoint, Permissions.Location_View, "eid")],

    # -----------------------------------------------------------------------
    # URL / Location UI (dojo/url/ui/views.py  ->  dojo/url/ui/urls.py)
    #
    # These URL names overlap with the endpoint module above. Since Django
    # uses the last-registered pattern for reverse() and the middleware reads
    # view_kwargs from the matched pattern, the kwarg names from the actually
    # matched URL are used. The endpoint entries above use "eid"; if the
    # url/ui pattern matched instead, "location_id" will be present and the
    # middleware will fall back (skip checks where the kwarg is missing).
    #
    # Unique URL names from url/ui:
    # -----------------------------------------------------------------------
    "add_endpoint_to_product": [("object", Product, Permissions.Location_Add, "product_id")],
    "add_endpoint_to_finding": [("object", Product, Permissions.Location_Add, "finding_id")],

    # -----------------------------------------------------------------------
    # Credential (dojo/cred/views.py  ->  dojo/cred/urls.py)
    # -----------------------------------------------------------------------
    "add_cred": [("config", Permissions.Credential_Add)],
    "view_cred_details": [("config", Permissions.Credential_View)],
    "edit_cred": [("config", Permissions.Credential_Edit)],
    "delete_cred": [("config", Permissions.Credential_Delete)],
    "cred": [("config", Permissions.Credential_View)],
    "all_cred_product": [("object", Product, Permissions.Product_Edit, "pid")],
    "new_cred_product": [("object", Product, Permissions.Product_Edit, "pid")],
    "view_cred_product": [
        ("object", Product, Permissions.Product_View, "pid"),
        ("object", Cred_Mapping, Permissions.Credential_View, "ttid"),
    ],
    "edit_cred_product": [
        ("object", Product, Permissions.Product_Edit, "pid"),
        ("object", Cred_Mapping, Permissions.Credential_Edit, "ttid"),
    ],
    "delete_cred_product": [
        ("object", Product, Permissions.Product_Edit, "pid"),
        ("object", Cred_Mapping, Permissions.Credential_Delete, "ttid"),
    ],
    "new_cred_product_engagement": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "view_cred_product_engagement": [
        ("object", Engagement, Permissions.Engagement_View, "eid"),
        ("object", Cred_Mapping, Permissions.Credential_View, "ttid"),
    ],
    "delete_cred_engagement": [
        ("object", Engagement, Permissions.Engagement_Edit, "eid"),
        ("object", Cred_Mapping, Permissions.Credential_Delete, "ttid"),
    ],
    "new_cred_engagement_test": [("object", Test, Permissions.Test_Edit, "tid")],
    "view_cred_engagement_test": [
        ("object", Test, Permissions.Test_View, "tid"),
        ("object", Cred_Mapping, Permissions.Credential_View, "ttid"),
    ],
    "delete_cred_test": [
        ("object", Test, Permissions.Test_Edit, "tid"),
        ("object", Cred_Mapping, Permissions.Credential_Delete, "ttid"),
    ],
    "new_cred_finding": [("object", Finding, Permissions.Finding_Edit, "fid")],
    "view_cred_finding": [
        ("object", Finding, Permissions.Finding_View, "fid"),
        ("object", Cred_Mapping, Permissions.Credential_View, "ttid"),
    ],
    "delete_cred_finding": [
        ("object", Finding, Permissions.Finding_Edit, "fid"),
        ("object", Cred_Mapping, Permissions.Credential_Delete, "ttid"),
    ],

    # -----------------------------------------------------------------------
    # Group (dojo/group/views.py  ->  dojo/group/urls.py)
    # -----------------------------------------------------------------------
    "add_group_member": [("object", Dojo_Group, Permissions.Group_Manage_Members, "gid")],
    "edit_group_member": [("object", Dojo_Group_Member, Permissions.Group_Manage_Members, "mid")],
    "delete_group_member": [("object", Dojo_Group_Member, Permissions.Group_Member_Delete, "mid")],
    "edit_group_permissions": [("config", "auth.change_permission")],

    # -----------------------------------------------------------------------
    # Reports (dojo/reports/views.py  ->  dojo/reports/urls.py)
    # -----------------------------------------------------------------------
    "product_type_report": [("object", Product_Type, Permissions.Product_Type_View, "ptid")],
    "product_report": [("object", Product, Permissions.Product_View, "pid")],
    "product_endpoint_report": [("object", Product, Permissions.Product_View, "pid")],
    "engagement_report": [("object", Engagement, Permissions.Engagement_View, "eid")],
    "test_report": [("object", Test, Permissions.Test_View, "tid")],

    # -----------------------------------------------------------------------
    # Tool Product (dojo/tool_product/views.py  ->  dojo/tool_product/urls.py)
    # -----------------------------------------------------------------------
    "new_tool_product": [("object", Product, Permissions.Product_Edit, "pid")],
    "all_tool_product": [("object", Product, Permissions.Product_Edit, "pid")],
    "edit_tool_product": [("object", Product, Permissions.Product_Edit, "pid")],
    "delete_tool_product": [("object", Product, Permissions.Product_Edit, "pid")],

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
    "view_product_benchmark": [("object", Product, Permissions.Benchmark_Edit, "pid")],
    "edit_benchmark": [("object", Product, Permissions.Benchmark_Edit, "pid")],
    "delete_product_benchmark": [("object", Product, Permissions.Benchmark_Delete, "pid")],
    "update_product_benchmark": [("object", Product, Permissions.Benchmark_Edit, "pid")],
    "update_product_benchmark_summary": [("object", Product, Permissions.Benchmark_Edit, "pid")],

    # -----------------------------------------------------------------------
    # Object / Tracked Files (dojo/object/views.py  ->  dojo/object/urls.py)
    # -----------------------------------------------------------------------
    "new_object": [("object", Product, Permissions.Product_Tracking_Files_Add, "pid")],
    "view_objects": [("object", Product, Permissions.Product_Tracking_Files_View, "pid")],
    "edit_object": [("object", Product, Permissions.Product_Tracking_Files_Edit, "pid")],
    "delete_object": [("object", Product, Permissions.Product_Tracking_Files_Delete, "pid")],

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
    # GitHub Issue Link (dojo/github/ui/views.py)
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
    "delete_engagement_survey": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "assign_questionnaire": [("object", Engagement, Permissions.Engagement_Edit, "eid")],
    "view_questionnaire": [("object", Engagement, Permissions.Engagement_View, "eid")],
    "add_questionnaire": [("object", Engagement, Permissions.Engagement_Edit, "eid")],

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
