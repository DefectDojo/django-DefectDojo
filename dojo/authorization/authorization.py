"""
OS authorization: is_superuser / is_staff / authorized_users.

The hierarchical RBAC role system has been moved out of OS to the dojo-pro
plugin. OS-only deployments authorize an action on an object iff

  * the user is a superuser, or
  * the user is staff and the action is non-destructive (legacy treats
    every staff user as eligible for staff-only and delete actions), or
  * the user is in the relevant ``authorized_users`` ManyToMany
    (climbing the Product_Type → Product → Engagement → Test → Finding
    hierarchy until an explicit membership is found).

Per-product role granularity (Reader / Writer / Maintainer / Owner),
group-level authorization, and Member/Group/Role tables are not consulted
in this model. Deployments that need that fidelity should run the
dojo-pro plugin, which keeps the RBAC layer alive and shadows this
module's symbols at startup so the same code paths route through Pro.
"""
from django.core.exceptions import PermissionDenied
from django.db.models import Model

from dojo.authorization.models import Dojo_Group_Member, Product_Member, Product_Type_Member
from dojo.authorization.query_registrations import (
    authorized_product_id_set,
    authorized_product_type_id_set,
)
from dojo.authorization.roles_permissions import (
    Action,
    permission_to_action,
)
from dojo.location.models import AbstractLocation, Location
from dojo.models import (
    App_Analysis,
    Dojo_Group,
    Dojo_User,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Languages,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Risk_Acceptance,
    Test,
)


def user_has_configuration_permission(user: Dojo_User, permission: str):
    """
    Legacy: configuration permissions reduce to is_superuser / is_staff,
    matching the rest of the legacy auth model. ``user.has_perm`` is
    still consulted as a fallback so explicit Django permission grants
    (e.g. ``auth.add_user`` granted via Django Admin) keep working for
    non-staff users. Pro overrides this function at runtime via
    pro/apps.py:_shadow_authorization_symbols, so this OS bypass does
    not affect Pro deployments.
    """
    if not user:
        return False
    if user.is_anonymous:
        return False
    if user.is_superuser or user.is_staff:
        return True
    return user.has_perm(permission)


def user_is_superuser_or_global_owner(user: Dojo_User) -> bool:
    """
    Legacy: there is no Owner role; only the superuser flag elevates
    a user to system-wide authority.
    """
    if not user or getattr(user, "is_anonymous", False):
        return False
    return bool(user.is_superuser)


def user_has_permission(user: Dojo_User, obj: Model, permission) -> bool:
    """
    Legacy object-level authorization check.

    Resolution order:

      1. anonymous → deny
      2. superuser → allow
      3. action → mapped from Permissions / string / Action via permission_to_action
      4. SuperuserOnly action → deny (already handled superuser above)
      5. StaffOnly / Delete → require is_staff
      6. View / Edit / Add / Import → is_staff bypasses unconditionally,
         otherwise check membership in the obj.authorized_users chain
         (climbing Product_Type ← Product ← Engagement ← Test ← Finding).
         This matches the pre-Auth-V2 (pre-2020) behavior where is_staff
         was an absolute bypass on every perm_type — see
         dojo/user/helper.py at commit e7805aa14~ for the historical
         reference.

    Carrier objects don't expose authorized_users themselves; they
    delegate to their wrapped product or product type.
    """
    if not user or getattr(user, "is_anonymous", False):
        return False
    if user.is_superuser:
        return True

    action = permission_to_action(permission)

    if action == Action.SuperuserOnly:
        return False

    if action in {Action.StaffOnly, Action.Delete}:
        return bool(user.is_staff)

    return _user_authorized_for(user, obj, action)


def _user_authorized_for(user: Dojo_User, obj: Model, action: Action) -> bool:
    """
    Membership-chain check. Returns True if user has any membership that
    grants ``action`` on ``obj``.
    """
    if obj is None:
        return False

    if isinstance(obj, Product_Type):
        if user.is_staff:
            return True
        return obj.pk in authorized_product_type_id_set(user.pk)

    if isinstance(obj, Product):
        if user.is_staff:
            return True
        # authorized_product_id_set folds direct Product membership AND
        # inherited membership via prod_type into one cached lookup.
        return obj.pk in authorized_product_id_set(user.pk)

    if isinstance(obj, Engagement):
        return _user_authorized_for(user, obj.product, action)

    if isinstance(obj, Test):
        return _user_authorized_for(user, obj.engagement.product, action) if obj.engagement_id else False

    if isinstance(obj, Finding):
        return _user_authorized_for(user, obj.test.engagement.product, action)

    if isinstance(obj, Finding_Group):
        return _user_authorized_for(user, obj.test.engagement.product, action)

    if isinstance(obj, Risk_Acceptance):
        # Risk_Acceptance is reachable from Engagement via the reverse M2M
        # `engagement.risk_acceptance`. Pre-2020 followed the same path
        # (see dojo/user/helper.py at e7805aa14~).
        engagement = obj.engagement_set.first()
        if engagement is not None:
            return _user_authorized_for(user, engagement.product, action)
        return False

    if isinstance(obj, Location):
        return any(_user_authorized_for(user, ref.product, action) for ref in obj.products.all())

    if isinstance(obj, AbstractLocation):
        return _user_authorized_for(user, obj.location, action)

    if isinstance(obj, Endpoint | Languages | App_Analysis | Product_API_Scan_Configuration):
        return _user_authorized_for(user, obj.product, action)

    if isinstance(obj, Dojo_Group):
        # Groups and the role tables live in RBAC territory; under the legacy
        # OS model they are staff-only. Pro's runtime shadow re-routes these
        # calls to the RBAC implementation for Pro deployments.
        return bool(user.is_staff)

    if isinstance(obj, Dojo_Group_Member | Product_Member | Product_Type_Member):
        # Membership rows: a user can always act on a membership row that
        # references themselves (self-removal); otherwise it's staff-only.
        if obj.user_id == user.pk:
            return True
        return bool(user.is_staff)

    msg = f"No legacy authorization implemented for class {type(obj).__name__}"
    raise NoAuthorizationImplementedError(msg)


def user_has_global_permission(user: Dojo_User, permission) -> bool:
    """
    Legacy: global permissions reduce to is_superuser / is_staff.

    The one Django configuration-permission carve-out preserved from the
    pre-2020 model: ``dojo.add_product_type`` lets a non-staff user
    create product types if explicitly granted via Django auth.
    """
    if not user or getattr(user, "is_anonymous", False):
        return False
    if user.is_superuser:
        return True

    action = permission_to_action(permission)

    if permission == "add" and user_has_configuration_permission(user, "dojo.add_product_type"):
        return True

    if action == Action.SuperuserOnly:
        return False
    return bool(user.is_staff)


def user_has_configuration_permission_or_403(user: Dojo_User, permission: str) -> None:
    if not user_has_configuration_permission(user, permission):
        raise PermissionDenied


def user_has_permission_or_403(user: Dojo_User, obj: Model, permission) -> None:
    if not user_has_permission(user, obj, permission):
        raise PermissionDenied


def user_has_global_permission_or_403(user: Dojo_User, permission) -> None:
    if not user_has_global_permission(user, permission):
        raise PermissionDenied


# ---------------------------------------------------------------------------
# Inert role-based helpers.
#
# The hierarchical RBAC roles (Reader / Writer / Maintainer / Owner /
# API_Importer) live in dojo-pro now; OS-only deployments authorize via
# is_superuser / is_staff / authorized_users only. These three helpers are
# kept as stubs so transitional callers that haven't dropped the role
# lookups don't AttributeError. They always return the "no role grants
# this permission" answer; OS deployments don't consult roles anyway.
# ---------------------------------------------------------------------------


def get_roles_for_permission(permission) -> set:
    """Inert stub. Legacy OS auth does not consult roles."""
    return set()


def role_has_permission(role, permission) -> bool:
    """Inert stub. Legacy OS auth does not consult roles."""
    return False


def role_has_global_permission(role, permission) -> bool:
    """Inert stub. Legacy OS auth does not consult roles."""
    return False


class NoAuthorizationImplementedError(Exception):
    def __init__(self, message):
        self.message = message


class PermissionDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message


class RoleDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message
