# Backward-compat shim: the view logic moved to dojo.endpoint.ui.views during the
# module reorg. External consumers (e.g. dojo-pro) still import from
# dojo.endpoint.views, so re-export the public names from their new location.
from dojo.endpoint.ui.views import *  # noqa: F403 -- backward compat re-export
