from django.dispatch import Signal

# Sent before bulk-deleting findings via cascade_delete.
# Receivers can dispatch integrator notifications, collect metrics, etc.
# Provides: finding_qs (QuerySet of findings about to be deleted)
pre_bulk_delete_findings = Signal()
