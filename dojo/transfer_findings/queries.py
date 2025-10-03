from crum import get_current_user
from dojo.models import Product, TransferFinding, SLA_Configuration
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from dojo.authorization.authorization import user_has_global_permission, user_has_permission 
from dojo.models import Engagement, Finding
from dojo.api_v2.api_error import ApiError
import logging
logger = logging.getLogger(__name__)


def get_products_for_transfer_findings(permission, user=None, product=None):
    if user is None:
        user = get_current_user()
    
    if user.is_superuser:
        return Product.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return Product.objects.all().order_by('name')

    try:
        if product:
            if user_has_permission(user, product, permission):
                products = Product.objects.exclude(id=product.id)
            return products
        else:
            raise ApiError(detail="Current Product is None")

    except ApiError as e:
        logger.error(e)
        raise ApiError(e.message)


def get_expired_transfer_finding_to_handle():
    transfer_finding = TransferFinding.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date__date__lte=timezone.now().date())
    return transfer_finding


def get_almost_expired_transfer_finding_to_handle(heads_up_days):
    transfer_finding = TransferFinding.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date_warned__isnull=True,
            expiration_date__date__lte=timezone.now().date() + relativedelta(days=heads_up_days), expiration_date__date__gte=timezone.now().date())
    return transfer_finding


def sla_expiration_transfer_finding(sla_settings_name):
    expiration_delta_days = list(SLA_Configuration.objects.filter(name=sla_settings_name).values())
    if expiration_delta_days:
        return expiration_delta_days[0]
    raise ValueError("(TransferFinding) configuration not defined in database")


def search_finding_related(destination_engagement: Engagement, origin_finding: Finding):
    return Finding.objects.filter(test__engagement=destination_engagement,
                                  test__tags__name__in=["transferred"],
                                  title=origin_finding.title,
                                  cwe=origin_finding.cwe,
                                  vuln_id_from_tool=origin_finding.vuln_id_from_tool).first()
