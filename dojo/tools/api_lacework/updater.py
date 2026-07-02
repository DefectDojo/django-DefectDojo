"""
Lacework API Updater for DefectDojo.

Lacework does not have a concept of issue transitions like SonarQube.
This updater is a placeholder for future synchronization needs.

If Lacework adds API support for vulnerability exception management,
this module can be extended to reflect DefectDojo finding status changes
back to Lacework.
"""

import logging

logger = logging.getLogger(__name__)


class LaceworkApiUpdater:
    def update_lacework_finding(self, finding):
        """Update a finding status in Lacework."""
        logger.debug(
            "Lacework updater called for finding %s. Lacework does not currently support issue transitions.",
            finding.id,
        )
        # Future implementation could use:
        # POST /api/v2/VulnerabilityExceptions to add exceptions
        # for findings that are false positive or risk accepted in DefectDojo
