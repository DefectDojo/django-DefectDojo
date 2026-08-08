"""
Registry-completeness guard for the auth-filter layer.

Every key looked up via ``get_auth_filter("...")`` must be registered via
``register_auth_filter("...")``. An unregistered key makes the per-app
wrapper fall back to its default (passthrough / None), bypassing membership
scoping, so this guards against a key being looked up but never wired up.
"""

import re
from pathlib import Path

import dojo
import dojo.authorization.query_registrations  # noqa: F401 -- ensure OS registrations run
from dojo.authorization.query_filters import get_auth_filter

from .dojo_test_case import DojoTestCase

_KEY_CALL = re.compile(r'get_auth_filter\(\s*"([^"]+)"')


def _looked_up_keys() -> set[str]:
    root = Path(dojo.__file__).resolve().parent
    keys: set[str] = set()
    for path in root.rglob("*.py"):
        keys |= set(_KEY_CALL.findall(path.read_text(encoding="utf-8")))
    return keys


class TestAuthFilterRegistryComplete(DojoTestCase):

    def test_all_looked_up_keys_are_registered(self):
        missing = sorted(key for key in _looked_up_keys() if get_auth_filter(key) is None)
        self.assertEqual(
            missing, [],
            msg=f"auth-filter keys looked up but never registered (silent fallback): {missing}",
        )
