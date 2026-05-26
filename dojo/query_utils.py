from django.db.models import Count, IntegerField, Subquery
from django.db.models.query import QuerySet


def build_count_subquery(model_qs: QuerySet, group_field: str) -> Subquery:
    """Return a Subquery that yields one aggregated count per `group_field`."""
    # Important: slicing (`[:1]`) on an unordered queryset makes Django add an implicit `ORDER BY <pk>`.
    # With aggregation, Django then includes that pk in the GROUP BY, which collapses counts to 1.
    # Ordering by `group_field` avoids that and keeps the GROUP BY stable.
    model_qs = model_qs.order_by()
    return Subquery(
        model_qs.values(group_field).annotate(c=Count("pk")).order_by(group_field).values("c")[:1],  # one row per group_field
        output_field=IntegerField(),
    )
