from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LocationData:
    type: str
    data: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.data:
            error_msg = "'data' must be provided."
            raise ValueError(error_msg)

    @classmethod
    def url_from_value(cls, value: str) -> LocationData:
        return cls.url_from_parts(
            url=value,
        )

    @classmethod
    def url_from_parts(
        cls,
        *,
        url: str = "",
        host: str = "",
        port: int | None = None,
        protocol: str = "",
        path: str = "",
        query: str = "",
        fragment: str = "",
        user_info: str = "",
    ) -> LocationData:
        from dojo.url.models import URL  # noqa: PLC0415
        return cls(
            type=URL.get_location_type(),
            data={
                "url": url,
                "host": host,
                "port": port,
                "protocol": protocol,
                "path": path,
                "query": query,
                "fragment": fragment,
                "user_info": user_info,
            },
        )

    @classmethod
    def dependency(
        cls,
        *,
        purl: str = "",
        purl_type: str = "",
        namespace: str = "",
        name: str = "",
        version: str = "",
        qualifiers: str = "",
        subpath: str = "",
        hashes: dict[str, list[str]] | None = None,
        license_expression: str = "",
    ) -> LocationData:
        pass


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
