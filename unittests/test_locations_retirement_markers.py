import importlib.util
import itertools
import re
from pathlib import Path

from django.test import SimpleTestCase

import dojo

MARKER = "# TODO: Delete this after the move to Locations"
DOJO_ROOT = Path(dojo.__file__).resolve().parent
LOCATIONS_BRANCH = re.compile(r"^\s*if locations_enabled\(\):\s*$")


class TestLocationsRetirementMarkers(SimpleTestCase):

    """The marker flags Endpoint code a later sweep deletes, so it never sits on the Locations side."""

    def test_no_marker_opens_a_locations_enabled_branch(self):
        misplaced = []
        for path in sorted(DOJO_ROOT.rglob("*.py")):
            lines = path.read_text(encoding="utf-8").splitlines()
            for number, (line, following) in enumerate(itertools.pairwise(lines), start=1):
                if LOCATIONS_BRANCH.match(line) and following.strip() == MARKER:
                    misplaced.append(f"{path.relative_to(DOJO_ROOT.parent)}:{number + 1}")
        self.assertEqual(misplaced, [], "a marker on live Locations code: move it to the Endpoint branch")


class TestEndpointViewsShim(SimpleTestCase):

    """The dojo.endpoint.views re-export had no importer and is gone; the views live in dojo.endpoint.ui.views."""

    def test_the_re_export_module_is_gone(self):
        self.assertIsNone(importlib.util.find_spec("dojo.endpoint.views"))
        self.assertIsNotNone(importlib.util.find_spec("dojo.endpoint.ui.views"))
