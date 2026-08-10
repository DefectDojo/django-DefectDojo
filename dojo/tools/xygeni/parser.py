"""
Parser for Xygeni JSON reports.

Xygeni (https://xygeni.io) is a Software Supply Chain Security platform.
It emits a separate JSON report per scanner kind (SAST, SCA, secrets, IaC,
CI/CD misconfig, DAST, suspect dependencies, code tampering). All reports
share a common ``metadata`` envelope with a ``scanType`` discriminator.

Phase 1 of this parser handles SAST, SCA, and Secrets. Additional scan
types are dispatched-on the same way and can be added incrementally.
"""

import json
import logging

from dojo.tools.xygeni._common import extract_scan_type
from dojo.tools.xygeni.sast import parse_sast
from dojo.tools.xygeni.sca import parse_sca
from dojo.tools.xygeni.secrets import parse_secrets

logger = logging.getLogger(__name__)


SCAN_TYPE_SAST = "Xygeni SAST Scan"
SCAN_TYPE_SCA = "Xygeni SCA Scan"
SCAN_TYPE_SECRETS = "Xygeni Secrets Scan"

# Map from the ``metadata.scanType`` value emitted by the Xygeni CLI to the
# per-kind handler. Keys are lowercase, matching ``extract_scan_type``.
_HANDLERS = {
    "sast": parse_sast,
    "deps": parse_sca,
    "secrets": parse_secrets,
}


class XygeniParser:

    """Single parser dispatching on ``metadata.scanType`` across Xygeni scan kinds."""

    def get_scan_types(self):
        return [SCAN_TYPE_SAST, SCAN_TYPE_SCA, SCAN_TYPE_SECRETS]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        if scan_type == SCAN_TYPE_SAST:
            return "Xygeni SAST JSON report (code vulnerabilities). Generated with 'xygeni scan --scan-type=sast'."
        if scan_type == SCAN_TYPE_SCA:
            return "Xygeni SCA JSON report (open-source dependency vulnerabilities). Generated with 'xygeni scan --scan-type=deps'."
        if scan_type == SCAN_TYPE_SECRETS:
            return "Xygeni Secrets JSON report (hard-coded secrets). Generated with 'xygeni scan --scan-type=secrets'."
        return "Xygeni JSON report."

    def get_findings(self, file, test):
        data = json.load(file)
        kind = extract_scan_type(data)
        handler = _HANDLERS.get(kind)
        if handler is None:
            msg = (
                f"Unsupported Xygeni scanType '{kind}'. "
                f"Phase 1 supports: {sorted(_HANDLERS)}."
            )
            raise ValueError(msg)
        logger.debug("Xygeni parser dispatching on scanType=%s", kind)
        return handler(data, test)
