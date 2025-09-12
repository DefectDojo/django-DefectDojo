"""
Custom pghistory models for DefectDojo.

This module contains custom proxy models for pghistory Events
to expose context fields as structured fields.

Note: Performance indexes for the pghistory_context table are managed
via Django migration 0245_add_pghistory_context_indexes.py rather than
through model Meta classes, since the context table is managed by
the pghistory library itself.
"""
import pghistory.models
from django.db import models


class DojoEvents(pghistory.models.Events):

    """
    Custom Events proxy model that exposes context fields as structured fields.

    This allows querying and displaying context data like user, url, and remote_addr
    as regular model fields instead of accessing nested JSON data.
    """

    user = pghistory.ProxyField("pgh_context__user", models.IntegerField(null=True))
    url = pghistory.ProxyField("pgh_context__url", models.TextField(null=True))
    remote_addr = pghistory.ProxyField("pgh_context__remote_addr", models.CharField(max_length=45, null=True))

    class Meta:
        proxy = True
