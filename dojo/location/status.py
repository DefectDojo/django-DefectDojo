from __future__ import annotations

from django.db.models import (
    TextChoices,
)
from django.utils.translation import gettext_lazy as _


class FindingLocationStatus(TextChoices):

    """Types of supported Location Statuses."""

    Active = "Active", _("Active")
    Mitigated = "Mitigated", _("Mitigated")
    FalsePositive = "FalsePositive", _("False Positive")
    RiskExcepted = "RiskExcepted", _("Risk Excepted")
    OutOfScope = "OutOfScope", _("Out Of Scope")


class ProductLocationStatus(TextChoices):

    """Types of supported Location Statuses."""

    Active = "Active", _("Active")
    Mitigated = "Mitigated", _("Mitigated")
