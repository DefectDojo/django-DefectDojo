"""
API v3 import/reimport corpus (ported from ``unittests/test_import_reimport.py``, §10 backlog #1).

Strategy (architect-recorded dual-endpoint adapter): the v2 ``ImportReimportTestAPI`` scenarios and
assertions run **unchanged** against the consolidated ``POST /api/v3-alpha/import`` endpoint by
mixing in :class:`ApiV3ImportShim`, which overrides only the two endpoint helper methods
(``import_scan_with_params`` / ``reimport_scan_with_params``). Everything else -- the finding-list
DB assertions, the endpoint→location count redirect, ``block_execution`` for synchronous
dedupe, the ``@versioned_fixtures`` locations fixture -- is inherited from the v2 class. Both APIs
therefore prove the same import DB state.

The v2 base class is referenced via the ``_v2corpus`` module attribute (never bound as a module-level
name) so Django's ``test*.py`` discovery does not also collect the v2 class inside this v3 package.

Skipped scenarios (honest, enumerated in the port report):
  * the two ``*_statistics`` tests -- they assert the v2 before/after per-severity ``statistics``
    envelope, which v3 deliberately does not emit (v3 returns the delta shape
    ``{new, reactivated, closed, untouched}``; §4.13).
  * the two ``*_additional_endpoint`` tests -- they use ``endpoint_to_add`` (legacy Endpoint
    wiring), which is out of v3 scope (§4.13).
"""
from __future__ import annotations

from unittest import skip

import unittests.test_import_reimport as _v2corpus

from .import_corpus_shim import ApiV3ImportShim


class ApiV3ImportReimportCorpus(ApiV3ImportShim, _v2corpus.ImportReimportTestAPI):

    """The v2 ImportReimportTestAPI corpus (mixin scenarios + API-only scenarios) bound to v3."""

    # --- v2-only response shape: v3 emits the delta statistics, not the before/after envelope ---
    @skip("v3 returns delta statistics {new,reactivated,closed,untouched}, not the v2 before/after envelope (§4.13).")
    def test_import_0_reimport_1_active_verified_reimport_0_active_verified_statistics(self):
        ...

    @skip("v3 returns delta statistics {new,reactivated,closed,untouched}, not the v2 before/after envelope (§4.13).")
    def test_import_0_reimport_1_active_verified_reimport_0_active_verified_statistics_no_history(self):
        ...

    # --- legacy Endpoint param (endpoint_to_add) is out of v3 scope (§4.13) ---
    @skip("endpoint_to_add / legacy Endpoint wiring is out of v3 scope (§4.13).")
    def test_import_param_close_old_findings_with_additional_endpoint(self):
        ...

    @skip("endpoint_to_add / legacy Endpoint wiring is out of v3 scope (§4.13).")
    def test_import_param_close_old_findings_default_with_additional_endpoint(self):
        ...
