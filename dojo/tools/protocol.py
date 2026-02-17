from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LocationData:
    type: str
    data: dict[str, Any] | None = None
    value: Any | None = None
    tags: list[str] | None = None

    def __post_init__(self) -> None:
        if (self.data is None) == (self.value is None):
            error_msg = "Either 'data' or 'value' must be provided."
            raise ValueError(error_msg)

    @classmethod
    def url_from_value(cls, value: str) -> LocationData:
        from dojo.url.models import URL  # noqa: PLC0415
        return cls(
            type=URL.get_location_type(),
            value=value,
        )

    @classmethod
    def url_from_parts(
        cls,
        host: str,
        *,
        port: int | None = None,
        protocol: str = "",
        path: str = "",
        query: str = "",
        fragment: str = "",
        user_info: str = "",
        tags: tuple[str, ...] | list[str] = (),
    ) -> LocationData:
        from dojo.url.models import URL  # noqa: PLC0415
        return cls(
            type=URL.get_location_type(),
            data={
                "host": host,
                "port": port,
                "protocol": protocol,
                "path": path,
                "query": query,
                "fragment": fragment,
                "user_info": user_info,
            },
            tags=list(tags),
        )


"""
@dataclass(frozen=True)
class ParsedData:
    locations: list[LocationData]
    findings: list[Finding]


class Parser(Protocol):
    def get_findings(self, filename: str, test: Test) -> list[Finding]:
        pass

    def parse(self, filename: str, test: Test) -> ParsedData:
        pass
"""
