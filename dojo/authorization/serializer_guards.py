from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

# Keyed by model name so this module stays import-light and free of cycles.
# Value is (Permissions attribute name, noun used in the error message).
_MANAGE_MEMBERS = {
    "Product": ("Product_Manage_Members", "product"),
    "Product_Type": ("Product_Type_Manage_Members", "product type"),
}


class AuthorizedUsersMemberGuardMixin:

    """
    Enforce the member-management permission on ``authorized_users`` writes.

    ``authorized_users`` is a writable M2M on ``Product`` and ``Product_Type``, so
    every ``ModelSerializer`` over those models picks it up unless it is explicitly
    excluded. Object access is derived from that list, which makes writing it a
    member-management operation rather than an ordinary edit: it is gated behind
    ``Product_Manage_Members`` / ``Product_Type_Manage_Members``, the same
    permissions the web UI requires (dojo.product.ui.views.add_product_authorized_users).
    The rest of these endpoints is governed by the corresponding ``_Edit`` permission.

    Mix this into *every* serializer exposing the field, including alias
    serializers over the same models, so the rule holds wherever the field is
    reachable. The permission is derived from ``Meta.model``, so there is nothing
    per-serializer to configure or forget.

    The check hangs off ``run_validation`` rather than ``validate`` on purpose: a
    subclass that defines its own ``validate`` would otherwise shadow the mixin's
    and silently drop the guard.

    No-ops when the field is absent or unchanged (replay-safe), mirroring
    dojo.authorization.api_permissions.check_update_permission.
    """

    def run_validation(self, data=serializers.empty):
        value = super().run_validation(data)
        self._validate_authorized_users_change(value)
        return value

    def _validate_authorized_users_change(self, data):
        if "authorized_users" not in data:
            return

        # Field-level validation has already resolved the payload to Dojo_User
        # instances at this point.
        from dojo.authorization.authorization import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            user_has_permission,
        )
        from dojo.authorization.roles_permissions import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            Permissions,
        )

        model_name = self.Meta.model.__name__
        if model_name not in _MANAGE_MEMBERS:
            # Fail closed: a model we have no member-management permission for
            # must not get a free pass on the membership list.
            msg = f"No member-management permission is defined for {model_name}."
            raise PermissionDenied(msg)
        permission_name, label = _MANAGE_MEMBERS[model_name]

        new_ids = sorted(user.pk for user in (data.get("authorized_users") or []))
        current_ids = (
            sorted(self.instance.authorized_users.values_list("pk", flat=True))
            if self.instance is not None
            else []
        )
        if new_ids == current_ids:
            return

        request = self.context.get("request")
        request_user = getattr(request, "user", None)
        permission = getattr(Permissions, permission_name)
        if not (request_user and user_has_permission(request_user, self.instance, permission)):
            msg = f"You do not have permission to manage authorized users for this {label}."
            raise PermissionDenied(msg)


class ToolConfigurationUseGuardMixin:

    """
    Enforce ``view_tool_configuration`` on ``tool_configuration`` writes.

    Selecting a ``tool_configuration`` lets an import run authenticated requests
    with the credential stored on it, so it is gated by the same
    ``view_tool_configuration`` permission that guards the tool-configuration
    views, not just the object permission these endpoints already check.

    Mix this into *every* serializer exposing the field, including alias
    serializers over the same model, so the rule holds wherever the field is
    reachable.

    The check hangs off ``run_validation`` rather than ``validate`` on purpose: a
    subclass that defines its own ``validate`` would otherwise shadow the mixin's
    and silently drop the guard.

    No-ops when the field is absent (replay-safe on PATCH), mirroring
    dojo.authorization.api_permissions.check_update_permission.
    """

    def run_validation(self, data=serializers.empty):
        value = super().run_validation(data)
        self._validate_tool_configuration_use(value)
        return value

    def _validate_tool_configuration_use(self, data):
        if "tool_configuration" not in data:
            return

        from dojo.tool_config.queries import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            get_authorized_tool_configurations,
        )

        # Field-level validation has already resolved the payload to a
        # Tool_Configuration instance at this point.
        tool_configuration = data.get("tool_configuration")
        if tool_configuration is None:
            return
        request = self.context.get("request")
        request_user = getattr(request, "user", None)
        if not get_authorized_tool_configurations(request_user).filter(pk=tool_configuration.pk).exists():
            msg = "You do not have permission to use this tool configuration."
            raise PermissionDenied(msg)


CONTACT_FIELDS = ("product_manager", "technical_contact", "team_manager")


class ActiveUserContactGuardMixin:

    """
    Refuse a *new* contact assignment to a deactivated account.

    An inactive account exists to keep a historical reference readable, such as
    attribution for an import run by somebody who has since left. Picking one up as
    a new contact turns that record back into a live relationship, which is what
    the web UI's dropdowns have always refused (dojo.product.ui.forms.ProductForm).
    This closes the same gap on the API.

    Mix this into *every* serializer that writes one of ``CONTACT_FIELDS``,
    including alias serializers over the same model, so the rule holds wherever the
    field is reachable.

    The check hangs off ``run_validation`` rather than ``validate`` on purpose: a
    subclass that defines its own ``validate`` would otherwise shadow the mixin's
    and silently drop the guard. It also means the Pro subclasses inherit the guard
    without a change of their own.

    No-ops when the field is absent (replay-safe on PATCH), when the value is null
    (clearing a contact is always allowed), and when the submitted user already
    holds that field on this row. That last case is what keeps an existing
    assignment intact: a full PUT, and the Vue form's PATCH, both echo every
    current value back, and rejecting the echo would delete a historical reference
    rather than protect it.
    """

    def run_validation(self, data=serializers.empty):
        value = super().run_validation(data)
        self._validate_contacts_are_active(value)
        return value

    def _validate_contacts_are_active(self, data):
        errors = {}
        for model_field in CONTACT_FIELDS:
            if model_field not in data:
                continue
            # Field-level validation has already resolved the payload to a
            # Dojo_User instance at this point.
            user = data[model_field]
            if user is None or user.is_active:
                continue
            if getattr(self.instance, f"{model_field}_id", None) == user.pk:
                continue
            # Key the error by the name the client actually sent: the assets
            # endpoint calls this field ``asset_managers`` over the same column.
            key = next(
                (name for name, field in self.fields.items() if field.source == model_field),
                model_field,
            )
            errors[key] = [
                f"{user.get_username()} is not an active user and cannot be assigned to this field.",
            ]
        if errors:
            raise serializers.ValidationError(errors)
