import logging
from dojo.api_v2.api_error import ApiError
from crum import get_current_user
from dojo.risk_acceptance import risk_pending
from dojo.models import Test, Finding, Product, Engagement, Test_Type
from dojo.authorization.authorization import user_has_global_permission

logger = logging.getLogger(__name__)

def get_permissions_tranfer_finding(permission):
    user = get_current_user()
    role = risk_pending.get_role_members(user, obj_producto, obj_product_type)
    permission_result = user_has_global_permission(user, permission)
    roles = roles_permissions.get_roles_with_permissions()


def transfer_finding(finding: Finding):
    try:
        if isinstance(finding, Finding):
            test = Test.objects.create(engagement=finding.test.engagement,
                                       test_type=finding.test_type,
                                       target_start=finding.target_start,
                                       target_end=finding.target_end)

            logger.debug(f"Created test {e}")
            obj_finding = Finding(test=test,
                                  title=finding.title,
                                  cve=finding.cve,
                                  severity=finding.severity,
                                  verified=finding.verified,
                                  description=finding.description,
                                  mitigation=finding.mitigation, impact=finding.impact,
                                  reporter=finding.reporter,
                                  numerical_severity=finding.numerical_severity,
                                  static_finding=finding.static_finding,
                                  dynamic_finding=finding.dynamic_finding)

            logger.debug(f"Creation Finding {obj_finding}")
            tf = obj_finding.save()
            logger.debug(f"Transfer Finding  Save {tf}")
            return True

    except ApiError as e:
        return ApiError(e.message)



