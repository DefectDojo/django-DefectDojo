from functools import wraps
from dojo.models import Finding
from dojo.authorization.roles_permissions import Permissions 
from dojo.authorization.authorization import user_has_global_permission
from dojo.models import Dojo_User, Test
from dojo.api_v2.api_error import ApiError


def get_exclusive_permission(user: Dojo_User):
    # TODO: IMPLEMENTAR EL QUERY A LA BASE DE DATOS
    if user.username == "developer":
        return [] 
    return [Permissions.Finding_Red_Team]

class RulePermission:
    def __init__(self, permission: Permissions):
        self.permission = permission

    def rule_finding_red_team(self, *args, **kwargs) -> bool:
        tags = kwargs["obj"].tags.all()
        if "red_team" in tags:
            return kwargs["permission"] in get_exclusive_permission(kwargs["user"])
        else:
            return True

    def apply_rule(self, *args, **kwargs) -> bool:

        rule_dict = {
            "Finding_Red_Team": self.rule_finding_red_team
        }

        rule_function = rule_dict.get(self.permission.name, None)
        if rule_function:
            return rule_function(*args, **kwargs)
        return rule_function


def user_has_permission(user: Dojo_User,
                        permission: Permissions,
                        obj) -> bool:

    engine_rule = RulePermission(permission)
    rule_response = engine_rule.apply_rule(obj=obj,
                                    permission=permission,
                                    user=user)
    if rule_response is None:
        return permission in get_exclusive_permission(user)
    return rule_response



def user_has_exclusive_permission(user: Dojo_User, 
                                   obj: object,
                                   permission: Permissions)-> bool:
    if not user:
        return False

    if user.is_anonymous:
        return False
    
    if user.is_superuser:
        return True
    
    if user_has_global_permission(user, permission):
        return True
    
    if ((isinstance(obj, Finding) or isinstance(obj, Test))
        and user_has_permission(user, permission, obj)):
        return True
    return False