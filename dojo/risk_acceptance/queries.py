import logging
import math
from crum import get_current_user
from datetime import timedelta
from django.utils import timezone
from django.db.models import Exists, OuterRef, Q
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import (
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
    Risk_Acceptance,
    Finding,
    Product)


logger = logging.getLogger(__name__)

def get_authorized_risk_acceptances(permission):
    user = get_current_user()

    if user is None:
        return Risk_Acceptance.objects.none()

    if user.is_superuser:
        return Risk_Acceptance.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Risk_Acceptance.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("engagement__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("engagement__product_id"),
        group__users=user,
        role__in=roles)
    risk_acceptances = Risk_Acceptance.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return risk_acceptances.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))


def abuse_control_min_vulnerability_closed(product_id: int, min_percentage: int, days=None):
    """Product status based on the number of closed vulnerabilities in the last X days.

    Args:
        product_id (int): Product ID for which the query is to be performed.
        ideal_percentage (int): Percentage that must be met to pass the abuse control threshold.
        days (int, None): Number of days within which vulnerabilities were found (current date - days) = 100%.
                        If None, the total findings of the product are considered as 100%.

    Returns:
        (dict): result
    """
    message = ""
    if days:
        "Get finding for last days"
        queryset = Finding.objects.select_related('test__engagement')\
            .filter(test__engagement__product=product_id).order_by("date")

        if queryset:
            date_finding_max_old = queryset.first().date
            last_date = date_finding_max_old + timedelta(days=days)
            # obtain the finding max old whit date gte to last_date
            queryset = queryset.filter(date__gte=date_finding_max_old, date__lte=last_date)
    else:
        "Get all Finding"
        queryset = Finding.objects.select_related('test__engagement')\
            .filter(test__engagement__product=product_id)

    if queryset:
        total_finding = len(queryset)
        total_close_finding = queryset.filter(Q(active=False) & Q(mitigated__isnull=False))
        ideal_close_finding = total_finding * min_percentage
        current_percentage = ((100 * len(total_close_finding)) / total_finding) / 100
        ideal_close_finding = math.ceil(ideal_close_finding)
        
        if status := current_percentage >= min_percentage:
            message = (f"The product meets abuse control:"
                    f"The current percentage of findings closed is {round(current_percentage * 100, 1)}% and is greater than or equal to {min_percentage * 100}%")
            logger.debug(message)
        else:
            message = (f"The product does not meet the abuse control: The current percentage of findings closure is {round(current_percentage * 100, 1)}%"
                    f" and must be greater than or equal to {min_percentage * 100}%. "
                    f"At least {ideal_close_finding - len(total_close_finding)} findings need to be closed.")
            logger.debug(message)

        result = {"status": status,
                "current_percentage": current_percentage,
                "ideal_percentage": min_percentage,
                "ideal_close_finding": ideal_close_finding,
                "total_finding": total_finding,
                "total_close_finding": len(total_close_finding),
                "message": message}
    else:
        result = {"status": True, "message": ""}
    return result


def abuse_control_max_vulnerability_accepted(product_id: int, max_percentage: int):
    message = ""
    queryset = Finding.objects.select_related('test__engagement')\
        .filter(test__engagement__product=product_id)
    total_finding_active = queryset.filter(Q(Q(risk_status="Risk Accepted") | Q(active=True)) & Q(mitigated__isnull=True))
    ideal_finding_accepted = round((len(total_finding_active) * max_percentage), 1)
    total_finding_accepted = queryset.filter(risk_accepted=True, active=False, risk_status="Risk Accepted", mitigated=None)
    persentage_finding_accepted = ((100 * len(total_finding_accepted)) / len(total_finding_active)) / 100
    if status := persentage_finding_accepted <= max_percentage:
        message = (f"The product meets abuse control:"
                   f"The current percentage of findings accepted is {round((persentage_finding_accepted * 100), 1)}% and is less than or equal to {max_percentage * 100}%")
        logger.debug(message)
    else:
        message = (f"The product does not meets abuse control:"
                   f"The current percentage of findings accepted is {round((persentage_finding_accepted * 100), 1)}% and must be less than or equal to {max_percentage * 100}%"
                   f" At least {int(len(total_finding_accepted) - ideal_finding_accepted)} findings need to be closed.")
        logger.debug(message)

    result = {
        "status": status,
        "total_finding_active": len(total_finding_active),
        "total_finding_accepted": len(total_finding_accepted),
        "persentage_finding_accepted": persentage_finding_accepted,
        "message": message}
    return result
        

    

