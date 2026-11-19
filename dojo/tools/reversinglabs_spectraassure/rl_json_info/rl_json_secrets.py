"""
Extract secrets information from a Spectra Assure ``report.rl.json`` report.

The extraction walks the violation -> component -> secret -> evidence chain:

1. ``metadata.violations``: keep violations with ``status == "fail"`` and ``category == "secrets"``.
2. Remember ``rule_id``, ``description`` and the referenced ``component_uuid``s.
3. ``metadata.components``: drop component_uuids whose ``quality.status`` is not ``"fail"``.
4. Remember ``name`` and ``path`` of the surviving components.
5. ``metadata.secrets``: keep secrets with an evidence item matching both ``rule_id`` and ``component_uuid``.
6. From the secret take ``exposed``, ``service`` and ``timestamp``.
7. From each matching evidence item take ``canary``, ``file_offset``, ``line_number`` and ``liveness``.
8. Return the result as a JSON tree; violation_uuid, component_uuid and secret_uuid are unique,
   so those layers are dicts keyed by uuid and only the evidence layer is a list.

Requires Python 3.13+.
"""

import json
from collections import defaultdict
from typing import Any, TypedDict

type Json = dict[str, Any]

FAIL = "fail"
SECRETS = "secrets"


class EvidenceInfo(TypedDict):

    """One evidence item of a secret, matched on rule_id + component_uuid."""

    canary: bool | None
    file_offset: int | None
    line_number: int | None
    liveness: str | None


class SecretInfo(TypedDict):

    """One secret; a secret may match a component/rule with more than one evidence item."""

    exposed: bool | None
    service: str | None
    timestamp: str | None
    evidence: list[EvidenceInfo]


class ComponentInfo(TypedDict):

    """One failing component referenced by a failing secrets violation, keyed by component_uuid."""

    name: str | None
    path: str | None
    secrets: dict[str, SecretInfo]


class ViolationInfo(TypedDict):

    """One failing violation in the 'secrets' category, keyed by violation_uuid."""

    rule_id: str
    description: str | None
    components: dict[str, ComponentInfo]


class SecretsTree(TypedDict):

    """The complete result tree."""

    violations: dict[str, ViolationInfo]


class SecretsExtractor:

    """
    Extract the failing-secrets tree from the three relevant ``report.metadata`` subtrees.

    Only ``violations``, ``components`` and ``secrets`` are passed in and held, so the rest
    of the report can be released by the caller.

        metadata = report["report"]["metadata"]
        tree = SecretsExtractor(
            violations=metadata.get("violations"),
            components=metadata.get("components"),
            secrets=metadata.get("secrets"),
        ).extract()

    Sections in a real report are sometimes present but ``null`` (not merely absent),
    so each subtree is null tolerant and may be passed as ``None``.
    """

    def __init__(self, violations: Json | None, components: Json | None, secrets: Json | None) -> None:
        """Take the ``metadata.violations``, ``metadata.components`` and ``metadata.secrets`` subtrees."""
        self._violations = self._as_dict(violations)
        self._components = self._as_dict(components)
        self._secrets = self._as_dict(secrets)
        self._evidence_index = self._index_evidence()

    def extract(self) -> SecretsTree:
        """Return the violation -> component -> secret -> evidence tree."""
        return {"violations": {uuid: self._violation_info(violation) for uuid, violation in self._failed_secrets()}}

    def to_json(self, indent: int | None = 2) -> str:
        """Return :meth:`extract` serialized as JSON text."""
        return json.dumps(self.extract(), indent=indent)

    # step 1 + 2

    def _failed_secrets(self) -> list[tuple[str, Json]]:
        """Violations with status 'fail' in the 'secrets' category."""
        return [
            (uuid, violation)
            for uuid, violation in self._violations.items()
            if isinstance(violation, dict) and violation.get("status") == FAIL and violation.get("category") == SECRETS
        ]

    def _violation_info(self, violation: Json) -> ViolationInfo:
        rule_id = str(violation.get("rule_id") or "")
        referenced = self._as_list(self._as_dict(violation.get("references")).get("component"))
        return {
            "rule_id": rule_id,
            "description": violation.get("description"),
            "components": {
                uuid: self._component_info(rule_id, uuid, component) for uuid, component in self._failing(referenced)
            },
        }

    # step 3 + 4

    def _failing(self, component_uuids: list[Any]) -> list[tuple[str, Json]]:
        """Keep only components that exist and whose quality.status is 'fail'."""
        kept: list[tuple[str, Json]] = []
        for uuid in component_uuids:
            component = self._as_dict(self._components.get(uuid))
            if self._as_dict(component.get("quality")).get("status") != FAIL:
                continue
            kept.append((str(uuid), component))
        return kept

    def _component_info(self, rule_id: str, component_uuid: str, component: Json) -> ComponentInfo:
        return {
            "name": component.get("name"),
            "path": component.get("path"),
            "secrets": self._secrets_info(rule_id, component_uuid),
        }

    # step 5 + 6 + 7

    def _index_evidence(self) -> dict[tuple[str, str], dict[str, list[Json]]]:
        """Map (rule_id, component_uuid) -> {secret_uuid: [evidence, ...]}, so lookups stay O(1)."""
        index: dict[tuple[str, str], dict[str, list[Json]]] = defaultdict(lambda: defaultdict(list))
        for secret_uuid, secret in self._secrets.items():
            for evidence in self._as_list(self._as_dict(secret).get("evidence")):
                if not isinstance(evidence, dict):
                    continue
                rule_id = str(evidence.get("rule_id") or "")
                references = self._as_list(self._as_dict(evidence.get("references")).get("component"))
                for component_uuid in references:
                    index[rule_id, str(component_uuid)][str(secret_uuid)].append(evidence)
        return index

    def _secrets_info(self, rule_id: str, component_uuid: str) -> dict[str, SecretInfo]:
        matches = self._evidence_index.get((rule_id, component_uuid), {})
        return {
            secret_uuid: self._secret_info(self._as_dict(self._secrets.get(secret_uuid)), evidence_items)
            for secret_uuid, evidence_items in matches.items()
        }

    @staticmethod
    def _secret_info(secret: Json, evidence_items: list[Json]) -> SecretInfo:
        return {
            "exposed": secret.get("exposed"),
            "service": secret.get("service"),
            "timestamp": secret.get("timestamp"),
            "evidence": [
                {
                    "canary": evidence.get("canary"),
                    "file_offset": evidence.get("file_offset"),
                    "line_number": evidence.get("line_number"),
                    "liveness": evidence.get("liveness"),
                }
                for evidence in evidence_items
            ],
        }

    # null tolerant accessors

    @staticmethod
    def _as_dict(value: Any) -> Json:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []


def extract_secrets(violations: Json | None, components: Json | None, secrets: Json | None) -> SecretsTree:
    """Convenience wrapper around :class:`SecretsExtractor`."""
    return SecretsExtractor(violations, components, secrets).extract()


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        sys.stderr.write(f"usage: {sys.argv[0]} <report.rl.json>\n")
        raise SystemExit(2)

    with Path(sys.argv[1]).open(encoding="utf-8") as handle:
        metadata = json.load(handle)["report"]["metadata"]

    extractor = SecretsExtractor(
        violations=metadata.pop("violations", None),
        components=metadata.pop("components", None),
        secrets=metadata.pop("secrets", None),
    )
    del metadata

    # sys.stdout.write, not print(): upstream's ruff config selects T20, which forbids print
    sys.stdout.write(extractor.to_json() + "\n")
