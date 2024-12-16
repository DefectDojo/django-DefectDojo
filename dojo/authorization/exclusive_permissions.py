from dojo.utils import get_product
from dojo.api_v2.api_error import ApiError
from dojo.models import Finding
from dojo.authorization.roles_permissions import Permissions 
from dojo.product.queries import get_authorized_members_for_product
from dojo.authorization.authorization import user_has_global_permission
from dojo.models import Dojo_User, Test, Product, ExclusivePermission, Product_Member
import logging
logger = logging.getLogger(__name__)


def get_exclusive_permission(user: Dojo_User,
                             product: Product) -> list[Permissions]:
    products_members = Product_Member.objects.filter(product=product, user=user)
    permissions = []
    if products_members.exists():
        permissions = ExclusivePermission.objects.filter(members__in=products_members)
        try:
            permissions = [Permissions[permission.name] for permission in permissions]
        except KeyError as e:
            logger.error(f"The permit {e} has not been defined in class Permissions")

    return permissions

class RulePermission:
    def __init__(self, permission: Permissions, user: Dojo_User, obj: object):
        self.permission = permission
        self.user = user
        self.object = obj

    def rule_Product_Tag_Red_Team(self, *args, **kwargs) -> bool:
        """Rule Custom for permission

        Returns:
            bool: True if user has permission, False otherwise
        """
        tags = self.object.tags.all()
        product = get_product(self.object)
        if "red_team" in tags:
            return self.permission in get_exclusive_permission(self.user,
                                                               product)
        else:
            return True

    def apply_rule(self, *args, **kwargs) -> bool:

        rule_dict = {
            "Product_Tag_Red_Team": self.rule_Product_Tag_Red_Team
        }

        rule_function = rule_dict.get(self.permission.name, None)
        if rule_function:
            return rule_function(*args, **kwargs)
        return rule_function


def user_has_permission(user: Dojo_User,
                        permission: Permissions,
                        obj) -> bool:

    engine_rule = RulePermission(
        user=user,
        permission=permission,
        obj=obj)

    rule_response = engine_rule.apply_rule()
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
