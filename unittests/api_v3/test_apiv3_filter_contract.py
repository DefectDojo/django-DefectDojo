r"""
Filter-contract snapshot test for API v3 (D6 / §4.9, §6 OS2 / I2).

The per-object filter vocabulary (params + orderings + search fields) is a *tested artifact*: this
test renders every registered ``FilterSpec`` to ``unittests/api_v3/snapshots/filters.json`` and
fails on any drift, so a contract change can never land silently -- it must be an intentional
snapshot update.

WHY the vocabulary is a locked, tested contract (not just a convenience test):

1. **It closes a silent-failure mode.** v2 (django-filter / DRF) *ignores* query params it does not
   recognise: ``GET /findings?severty=Critical`` (a typo for ``severity``) silently drops the filter
   and returns EVERY finding, while the caller believes they are looking at criticals only -- a
   dangerous illusion for a security product (you think you triaged all criticals; you triaged
   nothing). v3 rejects any unknown param with a 400 ``filter`` problem+json (§12 OS2), which is only
   safe if the accepted vocabulary is a *closed, reviewed set*. This snapshot is what keeps it closed:
   the vocabulary cannot grow (or a typo-prone alias sneak in) without a visible, reviewed change.

2. **One vocabulary drives many projections (D6).** The exact same params drive the list, the
   ``?include=counts`` aggregate over the filtered/authorized queryset, and -- by design -- future
   aggregation/chart endpoints, CSV/export, and the reserved ``POST /<resource>/query`` saved-view
   substrate. A param that silently changes meaning (or disappears) therefore doesn't break one
   endpoint; it breaks persisted saved filters and dashboards months later, far from the change that
   caused it. Pinning the vocabulary in one snapshot makes every consumer's contract move together.

3. **The workflow makes drift reviewable.** Unintended drift fails CI here. A *deliberate* contract
   change is made by regenerating the snapshot, so the change shows up as a reviewable diff in
   ``snapshots/filters.json`` in the same PR -- the vocabulary change is reviewed as data, not buried
   in a route diff.

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
            "API v3 filter-contract drift detected. The per-object filter vocabulary is a LOCKED, "
            "tested contract (see this module's docstring): unknown params 400 in v3, so the accepted "
            "set must stay closed, and the SAME params drive lists / include=counts / future "
            "aggregations / saved views -- silent drift breaks persisted filters far from the change.\n"
            "  * If this change is UNINTENDED: revert it -- you have altered the filter/ordering "
            "vocabulary.\n"
            "  * If this change is DELIBERATE: regenerate the snapshot so the vocabulary change lands "
            f"as a reviewable diff in {SNAPSHOT.name}, by re-running with "
            "DD_API_V3_UPDATE_SNAPSHOTS=1.\n"
            f"expected: {json.dumps(saved, sort_keys=True)}\n"
            f"actual:   {json.dumps(current, sort_keys=True)}",
        )
