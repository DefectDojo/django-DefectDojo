import hashlib
import sys
from pathlib import Path

from split_settings.tools import include, optional

# See https://documentation.defectdojo.com/getting_started/configuration/ for options
# how to tune the configuration to your needs.

include(
    "settings.dist.py",
    optional("local_settings.py"),
)

if not (DEBUG or ("collectstatic" in sys.argv)):  # noqa: F821 - not declared DEBUG is acceptable because we are sure it will be loaded from 'include'
    with (Path(__file__).parent / "settings.dist.py").open("rb") as file:
        real_hash = hashlib.sha256(file.read()).hexdigest()
    with (Path(__file__).parent / ".settings.dist.py.sha256sum").open("rb") as file:
        expected_hash = file.read().decode().strip()
    if real_hash != expected_hash:
        msg = "Change of 'settings.dist.py' file was detected. It is not allowed to edit this file. " \
            "Any customization of variables need to be done via environmental variables or in 'local_settings.py'. " \
            "For more information check https://documentation.defectdojo.com/getting_started/configuration/ "
        sys.exit(msg)
