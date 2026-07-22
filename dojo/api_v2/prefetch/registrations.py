"""
Prefetch RBAC policy registrations.

Each register() call maps a model class to a callable ``(user) -> QuerySet`` of
model instances visible to that user. Policies are chosen to mirror the
authorization enforced by the model's top-level ViewSet:

* ``superuser_only`` for models behind ``IsSuperUser``
* ``authenticated_only`` for models behind plain ``IsAuthenticated``
* ``django_view_perm`` for models behind a ``DjangoModelPermissions`` subclass
* ``dojo_view_perm`` for models behind a ``BaseDjangoModelPermission`` subclass with a GET permission map entry
* ``children_via_parent`` for models where authorization is determined by the related parent FK, not the class itself
* Delegation to the matching ``get_authorized_*`` helper for object-permission
* Custom policies where necessary (so far, only Notes)

Models that are not registered here are denied by ``_Prefetcher``; a
newly added FK from a prefetch-enabled ViewSet will silently disappear from
the response until someone explicitly sets a policy for it.
"""

from django.contrib.auth.models import User

from dojo.api_v2.prefetch.authorized_querysets import (
    authenticated_only,
    children_via_parent,
    discard_user,
    django_view_perm,
    dojo_view_perm,
    notes_policy,
    register,
    superuser_only,
)
from dojo.endpoint.queries import (
    get_authorized_endpoint_status,
    get_authorized_endpoints,
)
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.queries import (
    get_authorized_findings,
    get_authorized_vulnerability_ids,
)
from dojo.finding_group.queries import get_authorized_finding_groups
from dojo.github.models import GITHUB_Issue, GITHUB_PKey
from dojo.jira.models import JIRA_Instance, JIRA_Issue, JIRA_Project
from dojo.jira.queries import (
    get_authorized_jira_issues,
    get_authorized_jira_projects,
)
from dojo.location.models import (
    Location,
    LocationFindingReference,
    LocationProductReference,
)
from dojo.location.queries import (
    get_authorized_location_finding_reference,
    get_authorized_location_product_reference,
    get_authorized_locations,
)
from dojo.models import (
    App_Analysis,
    Benchmark_Product,
    Benchmark_Product_Summary,
    BurpRawRequestResponse,
    Check_List,
    Development_Environment,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Params,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    FileUpload,
    Finding,
    Finding_Group,
    Language_Type,
    Languages,
    Network_Locations,
    Notes,
    Objects_Product,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Regulation,
    Risk_Acceptance,
    SLA_Configuration,
    Sonarqube_Issue,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    Tool_Configuration,
    Tool_Product_History,
    Tool_Product_Settings,
    Tool_Type,
    UserContactInfo,
    Vulnerability_Id,
)
from dojo.notifications.models import Notification_Webhooks, Notifications
from dojo.product.queries import (
    get_authorized_app_analysis,
    get_authorized_dojo_meta,
    get_authorized_engagement_presets,
    get_authorized_languages,
    get_authorized_product_api_scan_configurations,
    get_authorized_products,
)
from dojo.product_type.queries import get_authorized_product_types
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_test_imports, get_authorized_tests
from dojo.tool_product.queries import get_authorized_tool_product_settings
from dojo.url.models import URL
from dojo.vulnerability_id.models import (
    FindingVulnerabilityReference,
    VulnerabilityId,
)
from dojo.vulnerability_id.queries import (
    get_authorized_finding_vulnerability_references,
    get_authorized_vulnerability_id_entities,
)

########
# Models backed by ViewSets (api_v2.views) from which we can derive the required permission check.
########


# Superusers only
for model in (
    UserContactInfo,  # UserContactInfoViewSet
    Sonarqube_Issue,  # SonarqubeIssueViewSet
    Notifications,  # NotificationsViewSet
    Notification_Webhooks,  # NotificationWebhooksViewSet
    URL,  # URLViewSet
):
    register(model, superuser_only, model)


# Models where we need to check whether the user has "view" permissions.
for model in (
    Dojo_User,  # UsersViewSet
    Tool_Configuration,  # ToolConfigurationsViewSet
    Tool_Type,  # ToolTypesViewSet
    JIRA_Instance,  # JiraInstanceViewSet
    Language_Type,  # LanguageTypeViewSet
):
    register(model, django_view_perm, model)


# Models where we need to check "view" config permissions. Basically the same as above but includes staff viewership.
for model in (
    SLA_Configuration,  # SLAConfigurationViewset (UserHasSLAPermission)
):
    register(model, dojo_view_perm, model)


# Custom policy checks.
# Currently, only Notes: prefetchable through e.g. findings endpoint, but the set of Notes a user can prefetch depends
# on extra lookup logic. Notes _are_ backed by a ViewSet (NotesViewSet), but it restricts to superusers only, which
# isn't what we really want for prefetching -- users should be able to see their own notes!
register(Notes, notes_policy)


# Authentication is all that's required. These respective ViewSets have empty/non-existent GET entries for their
# perms_map, so are generally viewable for authenticated users.
for model in (
    Test_Type,  # TestTypesViewSet
    Development_Environment,  # DevelopmentEnvironmentViewSet
    Regulation,  # RegulationsViewSet
    Network_Locations,  # NetworkLocationsViewset
):
    register(model, authenticated_only, model)


# Models where we can simply fall back to a `get_authorized_*` method to check auth
for model, helper in (
    (Endpoint, get_authorized_endpoints),  # EndPointViewSet
    (Endpoint_Status, get_authorized_endpoint_status),  # EndpointStatusViewSet
    (Engagement, get_authorized_engagements),  # EngagementViewSet
    (Finding, get_authorized_findings),  # FindingViewSet
    (Product, get_authorized_products),  # ProductViewSet
    (Product_Type, get_authorized_product_types),  # ProductTypeViewSet
    (Test, get_authorized_tests),  # TestsViewSet
    (Test_Import, get_authorized_test_imports),  # TestImportViewSet
    (Risk_Acceptance, get_authorized_risk_acceptances),  # RiskAcceptanceViewSet
    (DojoMeta, get_authorized_dojo_meta),  # DojoMetaViewSet
    (App_Analysis, get_authorized_app_analysis),  # AppAnalysisViewSet
    (Languages, get_authorized_languages),  # LanguageViewSet
    (Engagement_Presets, get_authorized_engagement_presets),  # EngagementPresetsViewset
    (
        Product_API_Scan_Configuration,
        get_authorized_product_api_scan_configurations,
    ),  # ProductAPIScanConfigurationViewSet
    (Tool_Product_Settings, get_authorized_tool_product_settings),  # ToolProductSettingsViewSet
    (JIRA_Project, get_authorized_jira_projects),  # JiraProjectViewSet
    (JIRA_Issue, get_authorized_jira_issues),  # JiraIssuesViewSet
    (Location, get_authorized_locations),  # LocationViewSet
    (LocationFindingReference, get_authorized_location_finding_reference),  # LocationFindingReferenceViewSet
    (LocationProductReference, get_authorized_location_product_reference),  # LocationProductReferenceViewSet
):
    register(model, discard_user(helper), "view")


# Models where authorization is inherited from the parent the FK points to.
for child, parent, field in (
    (BurpRawRequestResponse, Finding, "finding"),  # BurpRawRequestResponseViewSet
):
    register(child, children_via_parent, child, parent, field)


########
# Models *NOT* backed by ViewSets (api_v2.views) for authorization reference.
########


# Defaulting to superuser required. Can be loosened if necessary, just playing it safe.
for model in (
    Endpoint_Params,  # m2m from Endpoint.endpoint_params
    FileUpload,  # m2m from Finding/Test/Engagement.files
):
    register(model, superuser_only, model)


# Models where we can simply fall back to a `get_authorized_*` method to check auth
for model, helper in (
    (Finding_Group, get_authorized_finding_groups),
    (Vulnerability_Id, get_authorized_vulnerability_ids),
    (VulnerabilityId, get_authorized_vulnerability_id_entities),
    (FindingVulnerabilityReference, get_authorized_finding_vulnerability_references),
):
    register(model, discard_user(helper), "view")


# Models where authorization is inherited from the parent the FK points to.
for child, parent, field in (
    (GITHUB_Issue, Finding, "finding"),
    (Test_Import_Finding_Action, Test_Import, "test_import"),
    (Check_List, Engagement, "engagement"),
    (Benchmark_Product, Product, "product"),
    (Benchmark_Product_Summary, Product, "product"),
    (Objects_Product, Product, "product"),
    (GITHUB_PKey, Product, "product"),
    (Tool_Product_History, Tool_Product_Settings, "product"),
):
    register(child, children_via_parent, child, parent, field)


# Playing it safe: the raw User model isn't exposed via ViewSet or serializer usage, but clamp it down just in case.
register(User, django_view_perm, User)
