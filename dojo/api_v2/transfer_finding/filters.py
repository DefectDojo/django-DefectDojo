from django_filters import rest_framework as filters
from dojo.models import TransferFinding

class TransferFindidingFilter(filters.FilterSet):
    accepted_by = filters.CharFilter(method="filter_accepted_by")


    def filter_accepted_by(self, queryset, name, value):
        return queryset.filter(accepted_by__username__icontains=value)


    class Meta:
        model = TransferFinding 
        fields = [
            "id",
            "destination_product_type",
            "destination_engagement",
            "destination_product",
            "origin_product_type",
            "origin_product",
            "origin_engagement",
            "owner"
        ]
