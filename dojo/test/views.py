# Backward-compat shim: the view logic moved to dojo.test.ui.views during the
# module reorg. External consumers (e.g. dojo-pro) still import from
# dojo.test.views, so re-export the public names from their new location.
from dojo.test.ui.views import *  # noqa: F403 -- backward compat re-export
