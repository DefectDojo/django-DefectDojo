from django.dispatch import Signal

# Sent before bulk-deleting findings via cascade_delete.
# Receivers can dispatch integrator notifications, collect metrics, etc.
# Provides: finding_qs (QuerySet of findings about to be deleted)
#
# IMPORTANT: The queryset may contain millions of rows. Receivers MUST NOT
# call list(), len(), or otherwise materialize the full queryset into memory.
# Use .filter(), .iterator(), or aggregation queries instead.
pre_bulk_delete_findings = Signal()
