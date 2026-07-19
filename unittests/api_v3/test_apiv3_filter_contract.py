r"""
Filter-contract snapshot test for API v3 (D6 / §4.9, §6 OS2 / I2).

The per-object filter vocabulary (params + orderings + search fields) is a *tested artifact*: this
test renders every registered ``FilterSpec`` to ``unittests/api_v3/snapshots/filters.json`` and
fails on any drift, so a contract change can never land silently -- it must be an intentional
snapshot update.

Regenerate the snapshot deliberately with::

    DD_API_V3_UPDATE_SNAPSHOTS=1 ./run-unittest.sh --test-case \\
        unittests.api_v3.test_apiv3_filter_contract
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# Importing the built API instance forces every resource route module to import, which registers
# its FilterSpec into the kernel registry (resource -> kernel dependency direction, I5).
import dojo.api_v3.api  # noqa: F401
from dojo.api_v3.filtering import iter_filter_specs

from .base import ApiV3TestCase

SNAPSHOT = Path(__file__).parent / "snapshots" / "filters.json"


def _render() -> dict:
    return {name: spec.vocabulary() for name, spec in sorted(iter_filter_specs().items())}


class TestApiV3FilterContract(ApiV3TestCase):

    def test_filter_contract_matches_snapshot(self):
        current = _render()
        # Sanity: at least the findings vocabulary must be registered.
        self.assertIn("finding", current, "no FilterSpec registered -- did the routers import?")

        serialized = json.dumps(current, indent=2, sort_keys=True) + "\n"

        if os.environ.get("DD_API_V3_UPDATE_SNAPSHOTS") or not SNAPSHOT.exists():
            SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
            SNAPSHOT.write_text(serialized)
            if not os.environ.get("DD_API_V3_UPDATE_SNAPSHOTS"):
                # First-ever run establishes the baseline; nothing to compare against yet.
                return

        saved = json.loads(SNAPSHOT.read_text())
        self.assertEqual(
            saved,
            current,
            "contract drift -- update snapshot deliberately "
            f"(set DD_API_V3_UPDATE_SNAPSHOTS=1 to regenerate {SNAPSHOT.name}).\n"
            f"expected: {json.dumps(saved, sort_keys=True)}\n"
            f"actual:   {json.dumps(current, sort_keys=True)}",
        )
