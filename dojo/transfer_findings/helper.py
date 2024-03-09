import logging
from dojo.api_v2.api_error import ApiError
from crum import get_current_user
from dojo.risk_acceptance import risk_pending
from dojo.models import Test, Finding, Product, Engagement, Test_Type, TransferFinding, TransferFindingFinding
from dojo.authorization.authorization import user_has_global_permission
from dojo.notifications.helper import create_notification
from django.urls import reverse

logger = logging.getLogger(__name__)


def get_permissions_tranfer_finding(permission):
    user = get_current_user()
    role = risk_pending.get_role_members(user, obj_producto, obj_product_type)
    permission_result = user_has_global_permission(user, permission)
    roles = roles_permissions.get_roles_with_permissions()


def transfer_finding(origin_finding: Finding, transfer_finding: TransferFinding):
    try:
        if isinstance(origin_finding, Finding) and isinstance(
            transfer_finding.destination_engagement, Engagement
        ):
            test = Test.objects.create(
                engagement=origin_finding.test.engagement,
                test_type=origin_finding.test.test_type,
                target_start=origin_finding.test.target_start,
                target_end=origin_finding.test.target_end,
            )

            logger.debug(f"Created test {test}")
            obj_finding = Finding(
                test=test,
                title=origin_finding.title,
                cve=origin_finding.cve,
                severity=origin_finding.severity,
                verified=origin_finding.verified,
                description=origin_finding.description,
                mitigation=origin_finding.mitigation,
                impact=origin_finding.impact,
                reporter=origin_finding.reporter,
                numerical_severity=origin_finding.numerical_severity,
                static_finding=origin_finding.static_finding,
                dynamic_finding=origin_finding.dynamic_finding,
            )

            logger.debug(f"Creation Finding {obj_finding}")
            obj_finding.save()
            logger.debug(f"Transfer Finding  Save {obj_finding}")

            create_notification(
                event="transfer finding",
                title=transfer_finding.title,
                recipients=["developer"],
            )
            logger.debug(
                f"Transfer Finding  creation notificaion {create_notification}"
            )

            return True

    except ApiError as e:
        return ApiError(e.message)


def send_notification_transfer_finding(transfer_findings):
    pid = transfer_findings.origin_product.id
    create_notification(
        event="transfer_finding",
        title=f"{transfer_findings.title[:30]}",
        icon="check-circle",
        color_icon="#096C11",
        recipients=[transfer_findings.owner],
        url=reverse("view_transfer_finding", args=(pid,)),
    )
