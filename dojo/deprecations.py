import re
from dataclasses import dataclass
from datetime import date

from django.utils import translation
from django.utils.translation import gettext_lazy as _

# Copied from the release milestones. A deprecation names its removal release, and its
# day always comes from here.
RELEASE_DATES = {
    "3.3.0": date(2026, 9, 8),
    "3.4.0": date(2026, 10, 5),
    "3.5.0": date(2026, 11, 2),
    "3.6.0": date(2026, 12, 7),
}

_MINOR_RELEASE = re.compile(r"\d+\.\d+\.0")


@dataclass(frozen=True)
class Deprecation:
    key: str
    title: str
    removal_version: str
    notice_url: str
    action: str = ""
    removed: bool = False

    @property
    def removal_date(self) -> date:
        return RELEASE_DATES[self.removal_version]

    @property
    def removal_label(self) -> str:
        return f"{self.removal_version} ({self.removal_date:%B %Y})"

    def message(self) -> str:
        # Keep the whole sentence in English: no catalog holds it.
        with translation.override(None):
            return (
                f"{self.title} are deprecated and will be removed in DefectDojo {self.removal_label}. "
                "Please plan to migrate away from this feature."
            )


_DEPRECATIONS: dict[str, Deprecation] = {}


_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def _release(version: str) -> tuple[int, ...]:
    match = _VERSION.match(version)
    if match is None:
        msg = f"{version!r} is not an X.Y.Z version"
        raise ValueError(msg)
    return tuple(int(part) for part in match.groups())


def register_deprecation(entry: Deprecation, *, override: bool = False) -> None:
    if not _MINOR_RELEASE.fullmatch(entry.removal_version):
        msg = f"{entry.key}: a feature is removed in a minor release (X.Y.0), not {entry.removal_version}"
        raise ValueError(msg)
    if entry.removal_version not in RELEASE_DATES:
        msg = f"{entry.key}: add {entry.removal_version} to RELEASE_DATES before naming it"
        raise ValueError(msg)
    if entry.key in _DEPRECATIONS and not override:
        return
    _DEPRECATIONS[entry.key] = entry


def get_deprecation(key: str) -> Deprecation | None:
    return _DEPRECATIONS.get(key)


def active_deprecations() -> list[Deprecation]:
    return [entry for entry in _DEPRECATIONS.values() if not entry.removed]


def overdue_deprecations(version: str) -> list[Deprecation]:
    current = _release(version)
    return [entry for entry in active_deprecations() if _release(entry.removal_version) < current]


_UPGRADING_3_2 = "https://docs.defectdojo.com/releases/os_upgrading/3.2/"

register_deprecation(
    Deprecation(key="tool_type", title=_("Tool Types"), removal_version="3.5.0", notice_url=_UPGRADING_3_2),
)
register_deprecation(
    Deprecation(
        key="tool_configuration",
        title=_("Tool Configurations"),
        removal_version="3.5.0",
        notice_url=_UPGRADING_3_2,
    ),
)
register_deprecation(
    Deprecation(
        key="api_scan_configuration",
        title=_("API Scan Configurations"),
        removal_version="3.5.0",
        notice_url=_UPGRADING_3_2,
    ),
)
