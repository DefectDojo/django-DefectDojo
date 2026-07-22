"""
OS authorization queryset filters.

Each filter restricts results to objects whose underlying Product /
Product_Type the user is a member of (via ``authorized_users``), with
``is_superuser`` and ``is_staff`` bypasses. RBAC carrier queries (Member,
Group, Global_Role) are not registered here — Pro registers its own
implementations at startup that consult those tables.

The dojo/authorization/queries entry-point names (e.g. ``product.get_
authorized_products``) are preserved so the per-app queries.py modules and
the API filter classes that look them up via ``get_auth_filter()`` keep
working without code changes.
"""
from crum import get_current_user
from django.db.models import Q

from dojo.authorization.query_filters import register_auth_filter
from dojo.authorization.roles_permissions import permission_to_action
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import (
    App_Analysis,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    Finding,
    Finding_Group,
    JIRA_Issue,
    JIRA_Project,
    Languages,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Import,
    Tool_Product_Settings,
    Vulnerability_Id,
)
from dojo.request_cache import cache_for_request_or_task
from dojo.vulnerability_id.models import FindingVulnerabilityReference, VulnerabilityId


def _resolve_user(user):
    return user if user is not None else get_current_user()


def _is_unrestricted(user, action):
    """
    Returns True if the user can see every object regardless of membership.
    Superuser and staff both bypass — matches pre-2020 behavior where
    is_staff was an absolute bypass for every perm_type. The ``action``
    arg is retained for callers that may want to gate StaffOnly /
    SuperuserOnly differently in the future.
    """
    if not user or getattr(user, "is_anonymous", False):
        return False
    if user.is_superuser:
        return True
    return bool(user.is_staff)


def _authorized_product_ids(user):
    """
    QuerySet of product ids the user can access via authorized_users.
    Lazy on purpose — callers that pass this into ``.filter(id__in=...)``
    let Postgres collapse it into a single subquery.
    """
    return Product.objects.filter(
        Q(authorized_users=user) | Q(prod_type__authorized_users=user),
    ).values("id")


def _authorized_product_type_ids(user):
    """
    QuerySet of product_type ids the user can access via authorized_users.
    Lazy on purpose (see ``_authorized_product_ids``).
    """
    return Product_Type.objects.filter(authorized_users=user).values("id")


@cache_for_request_or_task
def authorized_product_id_set(user_pk):
    """
    Frozen set of product ids the user can access via authorized_users
    (direct or via prod_type). Result is cached for the lifetime of the
    current request — repeated per-object permission checks (one per
    object, often dozens per request) collapse to a single SELECT.

    Returns an empty frozenset for anonymous / missing users so callers
    can do ``pid in set`` without a None check.
    """
    if not user_pk:
        return frozenset()
    return frozenset(
        Product.objects.filter(
            Q(authorized_users=user_pk) | Q(prod_type__authorized_users=user_pk),
        ).values_list("id", flat=True),
    )


@cache_for_request_or_task
def authorized_product_type_id_set(user_pk):
    """
    Frozen set of product_type ids the user is a direct member of via
    authorized_users. Cached per request (see ``authorized_product_id_set``).
    """
    if not user_pk:
        return frozenset()
    return frozenset(
        Product_Type.objects.filter(authorized_users=user_pk).values_list("id", flat=True),
    )


def _filter_by_authorized_products(queryset, product_path, permission, user=None):
    """
    Generic helper: restrict ``queryset`` to rows whose ``product_path`` FK
    points at a Product the user is authorized for. ``product_path`` is a
    Django ORM lookup like ``"product"`` or ``"engagement__product"``.
    """
    user = _resolve_user(user)
    if user is None or getattr(user, "is_anonymous", False):
        return queryset.none()
    action = permission_to_action(permission)
    if _is_unrestricted(user, action):
        return queryset
    return queryset.filter(**{f"{product_path}__id__in": _authorized_product_ids(user)})


# ---------------------------------------------------------------------------
# Product / Product_Type
# ---------------------------------------------------------------------------


def _get_authorized_products(permission, user=None):
    user = _resolve_user(user)
    if user is None or getattr(user, "is_anonymous", False):
        return Product.objects.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return Product.objects.all().order_by("name")
    return Product.objects.filter(
        Q(authorized_users=user) | Q(prod_type__authorized_users=user),
    ).distinct().order_by("name")


register_auth_filter("product.get_authorized_products", _get_authorized_products)


def _get_authorized_product_types(permission, user=None):
    user = _resolve_user(user)
    if user is None or getattr(user, "is_anonymous", False):
        return Product_Type.objects.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return Product_Type.objects.all().order_by("name")
    return Product_Type.objects.filter(authorized_users=user).order_by("name")


register_auth_filter("product_type.get_authorized_product_types", _get_authorized_product_types)


# ---------------------------------------------------------------------------
# Children of Product / Product_Type (membership inherited)
# ---------------------------------------------------------------------------


def _get_authorized_engagements(permission):
    return _filter_by_authorized_products(Engagement.objects.all(), "product", permission)


register_auth_filter("engagement.get_authorized_engagements", _get_authorized_engagements)


def _get_authorized_tests(permission, product=None):
    qs = Test.objects.all()
    if product is not None:
        qs = qs.filter(engagement__product=product)
    return _filter_by_authorized_products(qs, "engagement__product", permission)


register_auth_filter("test.get_authorized_tests", _get_authorized_tests)


def _get_authorized_test_imports(permission):
    return _filter_by_authorized_products(Test_Import.objects.all(), "test__engagement__product", permission)


register_auth_filter("test.get_authorized_test_imports", _get_authorized_test_imports)


def _get_authorized_risk_acceptances(permission):
    return _filter_by_authorized_products(Risk_Acceptance.objects.all(), "engagement__product", permission)


register_auth_filter("risk_acceptance.get_authorized_risk_acceptances", _get_authorized_risk_acceptances)


def _get_authorized_finding_groups(permission, user=None):
    return _filter_by_authorized_products(
        Finding_Group.objects.all(), "test__engagement__product", permission, user=user,
    )


register_auth_filter("finding_group.get_authorized_finding_groups", _get_authorized_finding_groups)


def _get_authorized_finding_groups_for_queryset(permission, queryset, user=None):
    return _filter_by_authorized_products(queryset, "test__engagement__product", permission, user=user)


register_auth_filter("finding_group.get_authorized_finding_groups_for_queryset", _get_authorized_finding_groups_for_queryset)


def _get_authorized_app_analysis(permission):
    return _filter_by_authorized_products(App_Analysis.objects.all(), "product", permission)


register_auth_filter("product.get_authorized_app_analysis", _get_authorized_app_analysis)


def _get_authorized_dojo_meta(permission):
    user = get_current_user()
    if user is None or getattr(user, "is_anonymous", False):
        return DojoMeta.objects.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return DojoMeta.objects.all()
    authorized_products = _authorized_product_ids(user)
    authorized_product_types = _authorized_product_type_ids(user)
    return DojoMeta.objects.filter(
        Q(product__id__in=authorized_products)
        | Q(product_type__id__in=authorized_product_types)
        | Q(finding__test__engagement__product__id__in=authorized_products)
        | Q(endpoint__product__id__in=authorized_products),
    )


register_auth_filter("product.get_authorized_dojo_meta", _get_authorized_dojo_meta)


def _get_authorized_languages(permission):
    return _filter_by_authorized_products(Languages.objects.all(), "product", permission)


register_auth_filter("product.get_authorized_languages", _get_authorized_languages)


def _get_authorized_engagement_presets(permission):
    return _filter_by_authorized_products(Engagement_Presets.objects.all(), "product", permission)


register_auth_filter("product.get_authorized_engagement_presets", _get_authorized_engagement_presets)


def _get_authorized_product_api_scan_configurations(permission):
    return _filter_by_authorized_products(
        Product_API_Scan_Configuration.objects.all(), "product", permission,
    )


register_auth_filter("product.get_authorized_product_api_scan_configurations", _get_authorized_product_api_scan_configurations)


def _get_authorized_jira_projects(permission, user=None):
    user = _resolve_user(user)
    if user is None or getattr(user, "is_anonymous", False):
        return JIRA_Project.objects.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return JIRA_Project.objects.all()
    authorized_products = _authorized_product_ids(user)
    authorized_product_types = _authorized_product_type_ids(user)
    return JIRA_Project.objects.filter(
        Q(product__id__in=authorized_products)
        | Q(product__prod_type__id__in=authorized_product_types)
        | Q(engagement__product__id__in=authorized_products),
    ).distinct()


register_auth_filter("jira_link.get_authorized_jira_projects", _get_authorized_jira_projects)


def _get_authorized_jira_issues(permission):
    user = get_current_user()
    if user is None or getattr(user, "is_anonymous", False):
        return JIRA_Issue.objects.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return JIRA_Issue.objects.all()
    authorized_products = _authorized_product_ids(user)
    return JIRA_Issue.objects.filter(
        Q(engagement__product__id__in=authorized_products)
        | Q(finding__test__engagement__product__id__in=authorized_products)
        | Q(finding_group__test__engagement__product__id__in=authorized_products),
    )


register_auth_filter("jira_link.get_authorized_jira_issues", _get_authorized_jira_issues)


def _get_authorized_tool_product_settings(permission):
    return _filter_by_authorized_products(Tool_Product_Settings.objects.all(), "product", permission)


register_auth_filter("tool_product.get_authorized_tool_product_settings", _get_authorized_tool_product_settings)


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


def _get_authorized_locations(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else Location.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    authorized_products = _authorized_product_ids(user)
    return qs.filter(products__product__id__in=authorized_products).distinct()


register_auth_filter("location.get_authorized_locations", _get_authorized_locations)


def _get_authorized_location_finding_reference(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else LocationFindingReference.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    authorized_products = _authorized_product_ids(user)
    return qs.filter(finding__test__engagement__product__id__in=authorized_products)


register_auth_filter("location.get_authorized_location_finding_reference", _get_authorized_location_finding_reference)


def _get_authorized_location_product_reference(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else LocationProductReference.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    authorized_products = _authorized_product_ids(user)
    return qs.filter(product__id__in=authorized_products)


register_auth_filter("location.get_authorized_location_product_reference", _get_authorized_location_product_reference)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _get_authorized_endpoints(permission, user=None):
    return _filter_by_authorized_products(Endpoint.objects.all(), "product", permission, user=user)


register_auth_filter("endpoint.get_authorized_endpoints", _get_authorized_endpoints)


def _get_authorized_endpoints_for_queryset(permission, queryset, user=None):
    return _filter_by_authorized_products(queryset, "product", permission, user=user)


register_auth_filter("endpoint.get_authorized_endpoints_for_queryset", _get_authorized_endpoints_for_queryset)


def _get_authorized_endpoint_status(permission, user=None):
    return _filter_by_authorized_products(
        Endpoint_Status.objects.all(), "endpoint__product", permission, user=user,
    )


register_auth_filter("endpoint.get_authorized_endpoint_status", _get_authorized_endpoint_status)


def _get_authorized_endpoint_status_for_queryset(permission, queryset, user=None):
    return _filter_by_authorized_products(queryset, "endpoint__product", permission, user=user)


register_auth_filter("endpoint.get_authorized_endpoint_status_for_queryset", _get_authorized_endpoint_status_for_queryset)


# ---------------------------------------------------------------------------
# Findings / Vulnerability_Ids
# ---------------------------------------------------------------------------


def _get_authorized_findings(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else Finding.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    return qs.filter(test__engagement__product__id__in=_authorized_product_ids(user))


register_auth_filter("finding.get_authorized_findings", _get_authorized_findings)
register_auth_filter("finding.get_authorized_findings_for_queryset", _get_authorized_findings)


def _get_authorized_vulnerability_ids(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else Vulnerability_Id.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    return qs.filter(finding__test__engagement__product__id__in=_authorized_product_ids(user))


register_auth_filter("finding.get_authorized_vulnerability_ids", _get_authorized_vulnerability_ids)
register_auth_filter("finding.get_authorized_vulnerability_ids_for_queryset", _get_authorized_vulnerability_ids)


def _get_authorized_vulnerability_id_entities(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else VulnerabilityId.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    # An entity links to findings across many products; distinct() collapses the join fan-out.
    return qs.filter(
        finding_references__finding__test__engagement__product__id__in=_authorized_product_ids(user),
    ).distinct()


def _get_authorized_finding_vulnerability_references(permission, queryset=None, user=None):
    user = _resolve_user(user)
    qs = queryset if queryset is not None else FindingVulnerabilityReference.objects.all()
    if user is None or getattr(user, "is_anonymous", False):
        return qs.none()
    if _is_unrestricted(user, permission_to_action(permission)):
        return qs
    return qs.filter(finding__test__engagement__product__id__in=_authorized_product_ids(user))


register_auth_filter("vulnerability_id.get_authorized_entities", _get_authorized_vulnerability_id_entities)
register_auth_filter("vulnerability_id.get_authorized_references", _get_authorized_finding_vulnerability_references)


# ---------------------------------------------------------------------------
# User queries
# ---------------------------------------------------------------------------


def _get_authorized_users(permission, user=None):
    user = _resolve_user(user)
    if user is None or getattr(user, "is_anonymous", False):
        return Dojo_User.objects.none()
    if _is_unrestricted(user, permission_to_action(permission)) or user.is_staff:
        return Dojo_User.objects.all().order_by("first_name", "last_name")
    # OS: collaborators — users sharing the caller's authorized products /
    # product types (via authorized_users), plus superusers. Mirrors 2.58.4,
    # which returned co-members of the caller's authorized products/types.
    return Dojo_User.objects.filter(
        Q(authorized_products__id__in=_authorized_product_ids(user))
        | Q(authorized_product_types__id__in=_authorized_product_type_ids(user))
        | Q(is_superuser=True),
    ).distinct().order_by("first_name", "last_name")


register_auth_filter("user.get_authorized_users", _get_authorized_users)


def _get_authorized_users_for_product_type(users, product_type, permission):
    if users is None:
        users = Dojo_User.objects.all()
    user = get_current_user()
    if user is None or getattr(user, "is_anonymous", False):
        return users.none()
    if _is_unrestricted(user, permission_to_action(permission)) or user.is_staff:
        return users
    if product_type is None:
        return users.none()
    # OS: users authorized on this product type via authorized_users, plus
    # superusers (2.58.4 always surfaced is_superuser users as candidates).
    return users.filter(
        Q(id__in=product_type.authorized_users.values("id"))
        | Q(is_superuser=True),
    )


register_auth_filter("user.get_authorized_users_for_product_type", _get_authorized_users_for_product_type)


def _get_authorized_users_for_product_and_product_type(users, product, permission):
    if users is None:
        users = Dojo_User.objects.all()
    user = get_current_user()
    if user is None or getattr(user, "is_anonymous", False):
        return users.none()
    if _is_unrestricted(user, permission_to_action(permission)) or user.is_staff:
        return users
    if product is None:
        return users.none()
    # OS: users authorized on this product via authorized_users (directly on
    # the product or via its product type), plus superusers (2.58.4 always
    # surfaced is_superuser users as candidates).
    return users.filter(
        Q(id__in=product.authorized_users.values("id"))
        | Q(id__in=product.prod_type.authorized_users.values("id"))
        | Q(is_superuser=True),
    )


register_auth_filter("user.get_authorized_users_for_product_and_product_type", _get_authorized_users_for_product_and_product_type)
