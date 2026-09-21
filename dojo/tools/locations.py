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
        # Truthiness filter (not set membership): never hashes `value`, so the
        # unset check can't crash on an unhashable value a parser might pass.
        # Drops None/""/0/empty — all "no data" for these context fields.
        data.update({key: value for key, value in context.items() if value})
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

    @classmethod
    def image(
        cls,
        *,
        registry: str = "",
        repository: str = "",
        digest: str = "",
        tag: str = "",
        oci_source: str = "",
        oci_revision: str = "",
    ) -> LocationData:
        """
        A container image a finding was found in. Exactly these six keys, always
        present, so every consumer reads one shape: ``registry`` and ``repository``
        as reported (the consumer normalises Docker Hub aliases and the ``library/``
        prefix), ``digest`` as ``sha256:<64 hex>`` when the scanner knows it, ``tag``
        as reported, and the ``org.opencontainers.image.source`` / ``.revision``
        labels when the tool exposes image labels. Identity is the digest when
        present, else registry/repository:tag; an image with neither digest nor
        tag is still a valid location for its repository.
        """
        return cls(
            type="image",
            data={
                "registry": registry,
                "repository": repository,
                "digest": digest,
                "tag": tag,
                "oci_source": oci_source,
                "oci_revision": oci_revision,
            },
        )


def split_image_reference(reference: str) -> dict[str, str]:
    """
    Split ``[registry/]repository[:tag][@digest]`` into its raw parts without
    normalising them. The first path segment is a registry only when it contains a
    dot or a colon or is ``localhost``; ``nginx:1.25`` therefore has no registry and
    the consumer decides what the default registry is. Returns empty strings for the
    parts that are absent, and an empty dict for an empty reference.
    """
    text = (reference or "").strip()
    if not text:
        return {}
    digest = ""
    if "@" in text:
        text, _, digest = text.partition("@")
    registry = ""
    first, sep, rest = text.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, text = first, rest
    tag = ""
    last_segment = text.rsplit("/", 1)[-1]
    if ":" in last_segment:
        text, _, tag = text.rpartition(":")
    return {"registry": registry, "repository": text, "tag": tag, "digest": digest}


@dataclass(frozen=True)
class LocationAssociationData:
    relationship_type: str = ""
    relationship_data: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.relationship_type) or bool(self.relationship_data)
