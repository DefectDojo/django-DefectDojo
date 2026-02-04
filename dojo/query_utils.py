from django.db.models import Count, IntegerField, Subquery
from django.db.models.query import QuerySet


def build_count_subquery(model_qs: QuerySet, group_field: str) -> Subquery:
    """Return a Subquery that yields one aggregated count per `group_field`."""
    return Subquery(
        model_qs.values(group_field).annotate(c=Count("*")).values("c")[:1],  # one row per group_field
        output_field=IntegerField(),
    )
