import django_filters as filter 
from dojo.engine_tools.models import FindingExclusion


class FindingExclusionFilter(filter.FilterSet):

    class Meta:
        model = FindingExclusion
        fields = ["uuid", "status"]
