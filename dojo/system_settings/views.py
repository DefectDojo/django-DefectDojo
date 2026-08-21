# Backward-compat shim: the view logic moved to dojo.system_settings.ui.views during the
# module reorg. External consumers (e.g. dojo-pro) still import from
# dojo.system_settings.views, so re-export the public names from their new location.
from dojo.system_settings.ui.views import *  # noqa: F403 -- backward compat re-export
