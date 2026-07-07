from __future__ import annotations

from dataclasses import dataclass, field
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
        return cls(
            type="url",
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
    def code(
        cls,
        *,
        file_path: str = "",
        line: int | None = None,
        end_line: int | None = None,
        snippet: str = "",
        source_object: str = "",
        sink_object: str = "",
        source_file_path: str = "",
        source_line: int | None = None,
    ) -> LocationData:
        """
        A static-analysis code coordinate. Identity is file_path (+ line);
        the remaining keys are volatile context expected to ride the finding
        reference rather than the location identity, so unset ones are omitted.
        """
        data: dict[str, Any] = {"file_path": file_path, "line": line}
        context = {
            "end_line": end_line,
            "snippet": snippet,
            "source_object": source_object,
            "sink_object": sink_object,
            "source_file_path": source_file_path,
            "source_line": source_line,
        }
        # Tuple (not set) membership: uses == rather than hashing, so an unset
        # check never crashes on an unhashable value a parser might pass.
        data.update({key: value for key, value in context.items() if value not in ("", None)})
        return cls(type="code", data=data)

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
        file_path: str = "",
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
                "artifact_hashes": artifact_hashes or {},
                "license_expression": license_expression,
                "file_path": file_path,
            },
        )


@dataclass(frozen=True)
class LocationAssociationData:
    relationship_type: str = ""
    relationship_data: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.relationship_type) or bool(self.relationship_data)
