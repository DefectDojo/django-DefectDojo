import logging
from dojo.api_v2.api_error import ApiError
from crum import get_current_user
from dojo.risk_acceptance import risk_pending
from dojo.models import Test, Finding, Product, Engagement, Test_Type, TransferFinding
from dojo.authorization.authorization import user_has_global_permission
from dojo.notifications.helper import create_notification
from django.urls import reverse

logger = logging.getLogger(__name__)

def get_permissions_tranfer_finding(permission):
    user = get_current_user()
    role = risk_pending.get_role_members(user, obj_producto, obj_product_type)
    permission_result = user_has_global_permission(user, permission)
    roles = roles_permissions.get_roles_with_permissions()


def transfer_finding(finding: Finding, transfer_finding: TransferFinding):
    try:
        if isinstance(finding, Finding) and isinstance(transfer_finding.engagement, Engagement):
            test = Test.objects.create(engagement=finding.test.engagement,
                                       test_type=finding.test.test_type,
                                       target_start=finding.test.target_start,
                                       target_end=finding.test.target_end)

            logger.debug(f"Created test {test}")
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
            obj_finding.save()
            logger.debug(f"Transfer Finding  Save {obj_finding}")

            create_notification(
                event="transfer finding",
                title=transfer_finding.title,
                recipients=["developer"]
                    )
            logger.debug(f"Transfer Finding  creation notificaion {create_notification}")

            return True

    except ApiError as e:
        return ApiError(e.message)



