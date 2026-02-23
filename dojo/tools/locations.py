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
    def url(
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
        artifact_hashes: dict[str, list[str]] | None = None,
        license_expression: str = "",
    ) -> LocationData:
        return cls(
            type="dependency",
            data={
                "purl": purl,
                "purl_type": purl_type,
                "namespace": namespace,
                "name": name,
                "version": version,
                "qualifiers": qualifiers,
                "subpath": subpath,
                "artifact_hashes": artifact_hashes,
                "license_expression": license_expression,
            },
        )
