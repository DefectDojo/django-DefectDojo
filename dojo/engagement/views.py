# Backward-compat shim: the view logic moved to dojo.engagement.ui.views during the
# module reorg. External consumers (e.g. dojo-pro) still import from
# dojo.engagement.views, so re-export the public names from their new location.
from dojo.engagement.ui.views import *  # noqa: F403 -- backward compat re-export
