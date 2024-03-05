import copy
import datetime
from crum import get_current_user
from dojo.risk_acceptance import risk_pending
from dojo.models import Test, Finding, Product, Engagement, Test_Type
from dojo.authorization.authorization import (
    user_has_global_permission,
    user_has_permission,
    user_has_configuration_permission,
)

def get_permissions_tranfer_finding(permission):
    user = get_current_user()
    role = risk_pending.get_role_members(user, obj_producto, obj_product_type)
    permission_result = user_has_global_permission(user, permission)
    roles = roles_permissions.get_roles_with_permissions()


def transfer_finding(finding: Finding, engagement: Engagement):
    test_type = Test_Type.objects.create(name='Transfer_finding', static_tool=True)
    test = Test.objects.create(engagement=engagement, test_type=test_type,
                                     target_start=datetime.date(2000, 2, 1), target_end=datetime.date(2000, 2, 1))
    obj_finding = Finding(test=test, title=finding.title, cve=finding.cve, severity=finding.severity, verified=finding.verified,
            description=finding.description, mitigation=finding.mitigation, impact=finding.impact,
            reporter=finding.reporter, numerical_severity=finding.numerical_severity,
            static_finding=finding.static_finding, dynamic_finding=finding.dynamic_finding
            )
    obj_finding.save()



