
from split_settings.tools import include, optional

# See https://docs.defectdojo.com/en/open_source/installation/configuration/ for options
# how to tune the configuration to your needs.

include(
    "settings.dist.py",
    optional("local_settings.py"),
)
