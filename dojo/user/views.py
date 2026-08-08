# Backward-compat shim: the view logic moved to dojo.user.ui.views during the
# module reorg. External consumers (e.g. dojo-pro) still import from
# dojo.user.views, so re-export the public names from their new location.
from dojo.user.ui.views import *  # noqa: F403 -- backward compat re-export
