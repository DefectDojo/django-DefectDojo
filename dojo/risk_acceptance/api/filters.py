from dojo.filters import DateRangeFilter, DojoFilter, OrderingFilter
from dojo.models import Risk_Acceptance


class ApiRiskAcceptanceFilter(DojoFilter):
    created = DateRangeFilter()
    updated = DateRangeFilter()

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("created", "created"),
            ("updated", "updated"),
        ),
    )

    class Meta:
        model = Risk_Acceptance
        fields = {
            "name": ["exact", "icontains"],
            "accepted_findings": ["exact"],
            "recommendation": ["exact"],
            "recommendation_details": ["exact", "icontains"],
            "decision": ["exact"],
            "decision_details": ["exact", "icontains"],
            "accepted_by": ["exact", "icontains"],
            "owner": ["exact"],
            "expiration_date": ["exact", "gt", "lt", "gte", "lte"],
            "expiration_date_warned": ["exact", "gt", "lt", "gte", "lte"],
            "expiration_date_handled": ["exact", "gt", "lt", "gte", "lte"],
            "reactivate_expired": ["exact"],
            "restart_sla_expired": ["exact"],
            "notes": ["exact"],
            "created": ["exact", "gt", "lt", "gte", "lte"],
            "updated": ["exact", "gt", "lt", "gte", "lte"],
        }
