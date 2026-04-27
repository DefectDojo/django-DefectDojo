# Import query_registrations to trigger RBAC filter registration at startup
from dojo.authorization import query_registrations  # noqa: F401
from dojo.authorization.authorization import (  # noqa: F401
    user_has_configuration_permission,
    user_has_global_permission,
    user_has_global_permission_or_403,
    user_has_permission,
    user_has_permission_or_403,
    user_is_superuser_or_global_owner,
)
from dojo.authorization.roles_permissions import Permissions, Roles  # noqa: F401
