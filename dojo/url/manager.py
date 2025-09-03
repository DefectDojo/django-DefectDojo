
from dojo.base_models.base import BaseManager, BaseQuerySet


class URLQueryset(BaseQuerySet):

    """URL Queryset to add chainable queries."""


class URLManager(BaseManager):

    """URL manager to manipulate all objects with."""

    QUERY_SET_CLASS = URLQueryset
