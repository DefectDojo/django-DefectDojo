from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import (
    TextChoices,
)
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from collections.abc import Iterable


class FindingLocationStatus(TextChoices):

    """Types of supported Location Statuses."""

    Active = "Active", _("Active")
    Mitigated = "Mitigated", _("Mitigated")
    FalsePositive = "FalsePositive", _("False Positive")
    RiskAccepted = "RiskAccepted", _("Risk Accepted")
    OutOfScope = "OutOfScope", _("Out Of Scope")


class ProductLocationStatus(TextChoices):

    """Types of supported Location Statuses."""

    Active = "Active", _("Active")
    Mitigated = "Mitigated", _("Mitigated")


# Statuses a person sets on a location. They outrank whatever a scan reports, so a human
# decision on one location survives every reimport of every test that reports it.
HUMAN_FINDING_LOCATION_STATUSES = (
    FindingLocationStatus.FalsePositive,
    FindingLocationStatus.RiskAccepted,
    FindingLocationStatus.OutOfScope,
)


def status_from_finding(finding) -> str:
    """The status a location reference carries for ``finding``, from the finding's own status."""
    finding_status = finding.status()
    if any(f_status in finding_status for f_status in ["Mitigated", "Inactive", "Duplicate"]):
        return FindingLocationStatus.Mitigated
    if "False Positive" in finding_status:
        return FindingLocationStatus.FalsePositive
    if "Risk Accepted" in finding_status:
        return FindingLocationStatus.RiskAccepted
    # Active, to be on the safe side
    return FindingLocationStatus.Active


def rollup_finding_location_status(statuses: Iterable[str]) -> str | None:
    """
    Return the status of one location on a finding, given the status of each of its reference rows.

    A finding holds one ``LocationFindingReference`` per location and test that reported it, so the
    same location can carry several rows. A human status wins (in the order above), then Active
    when any test still reports the location, then Mitigated. ``None`` when there are no rows.
    """
    present = set(statuses)
    if not present:
        return None
    for status in HUMAN_FINDING_LOCATION_STATUSES:
        if status in present:
            return status
    if FindingLocationStatus.Active in present:
        return FindingLocationStatus.Active
    return FindingLocationStatus.Mitigated
