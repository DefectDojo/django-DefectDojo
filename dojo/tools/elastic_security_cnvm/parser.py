import json
from contextlib import suppress
from datetime import datetime

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# Elastic's severity labels. Anything outside this set is NOT graded by resemblance - each scan type
# falls back differently, which is why severity_from_string reports whether it recognised the label.
SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    "none": "Info",
    "unknown": "Info",
}

CVSS_CRITICAL_FLOOR = 9.0
CVSS_HIGH_FLOOR = 7.0
CVSS_MEDIUM_FLOOR = 4.0


class ElasticSecurityDocuments:

    """
    Shared reading of an Elasticsearch search response for the three Elastic Security scan types.

    Elastic returns every one of them - CNVM vulnerabilities, posture evaluations and detection alerts
    - as documents from the same _search API, with the same ECS asset, host and cloud objects
    describing where the finding sits. The three parsers therefore share the document walk and the
    asset rendering, and differ only in which documents they claim and how they map them. Kept here,
    on the CNVM parser's module, the same way the shipped Invicti parser extends the Netsparker one.
    """

    def documents(self, data):
        """
        Return the documents in the export.

        An Elasticsearch search response nests them under hits.hits; a bare array of documents and a
        single document are accepted too.
        """
        if isinstance(data, list):
            return [doc for doc in data if isinstance(doc, dict)]
        if isinstance(data, dict):
            hits = data.get("hits")
            if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
                return [doc for doc in hits["hits"] if isinstance(doc, dict)]
            if isinstance(hits, list):
                return [doc for doc in hits if isinstance(doc, dict)]
            if "_source" in data:
                return [data]

        msg = (
            "An Elastic Security export is an Elasticsearch search response, a JSON object with "
            f"hits.hits documents; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def source(self, doc):
        source = doc.get("_source")
        return source if isinstance(source, dict) else None

    def block(self, source, key):
        value = source.get(key)
        return value if isinstance(value, dict) else {}

    def strings(self, value):
        """A list of non-empty strings, tolerating a single string."""
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item or "").strip()]
        return []

    def severity_from_string(self, value):
        """
        Grade an Elastic severity label.

        Returns (severity, recognised). An unrecognised label is NOT guessed at: the caller decides
        the fallback, because a CNVM document can be graded from its CVSS score while a posture or
        detection document has nothing else to go on.
        """
        label = str(value or "").strip().lower()
        if label in SEVERITY_BY_LABEL:
            return SEVERITY_BY_LABEL[label], True
        return "Info", False

    def asset_name(self, source):
        """The cloud resource, then the Kubernetes pod, then the host."""
        if name := str(self.block(source, "resource").get("name") or "").strip():
            return name
        pod = self.block(self.block(source, "kubernetes"), "pod")
        if name := str(pod.get("name") or "").strip():
            return name
        return self.host_identity(source)

    def host_identity(self, source):
        host = self.block(source, "host")
        for key in ("name", "hostname"):
            if value := str(host.get(key) or "").strip():
                return value
        return ""

    def asset_lines(self, source):
        """The ECS context lines every Elastic Security finding carries, in the connector's order."""
        lines = [
            self.resource_line(source),
            self.host_line(source),
            self.os_line(source),
            self.cluster_line(source),
            self.cloud_line(source),
        ]
        return [line for line in lines if line]

    def resource_line(self, source):
        resource = self.block(source, "resource")
        name = str(resource.get("name") or "").strip()
        if not name:
            return ""
        line = f"**Resource:** {name}"
        kind = str(resource.get("type") or "").strip()
        if not kind:
            return line
        line += f" ({kind}"
        if sub_type := str(resource.get("sub_type") or "").strip():
            line += f"/{sub_type}"
        return line + ")"

    def host_line(self, source):
        host = self.host_identity(source)
        return f"**Host:** {host}" if host else ""

    def os_line(self, source):
        operating_system = self.os_description(source)
        return f"**OS:** {operating_system}" if operating_system else ""

    def os_description(self, source):
        """Elastic's full OS string when it has one, else the name and version."""
        operating_system = self.block(self.block(source, "host"), "os")
        if full := str(operating_system.get("full") or "").strip():
            return full
        name = str(operating_system.get("name") or "")
        version = str(operating_system.get("version") or "")
        return f"{name} {version}".strip()

    def cluster_identity(self, source):
        orchestrator = self.block(source, "orchestrator")
        if name := str(self.block(orchestrator, "cluster").get("name") or "").strip():
            return name
        return str(orchestrator.get("cluster_name") or "").strip()

    def cluster_line(self, source):
        cluster = self.cluster_identity(source)
        if not cluster:
            return ""
        line = f"**Cluster:** {cluster}"
        if namespace := str(self.block(source, "kubernetes").get("namespace") or "").strip():
            line += f", namespace {namespace}"
        return line

    def cloud_line(self, source):
        cloud = self.block(source, "cloud")
        if not cloud:
            return ""
        bits = []
        if provider := str(cloud.get("provider") or "").strip():
            bits.append(provider)
        if account := str(self.block(cloud, "account").get("name") or "").strip():
            bits.append(f"account {account}")
        if region := str(cloud.get("region") or "").strip():
            bits.append(region)
        return "**Cloud:** " + ", ".join(bits) if bits else ""

    def cloud_tags(self, source):
        tags = []
        cloud = self.block(source, "cloud")
        if provider := str(cloud.get("provider") or "").strip():
            tags.append(provider)
        if region := str(cloud.get("region") or "").strip():
            tags.append(region)
        if cluster := self.cluster_identity(source):
            tags.append(f"cluster:{cluster}")
        return tags

    def dedupe(self, values):
        """
        Sort and deduplicate, as the connector does.

        Worth mirroring rather than tidying: a tag set that differs only in order still reads as a
        change on every reimport.
        """
        return sorted({str(value).strip() for value in values if str(value or "").strip()})

    def date_only(self, timestamp):
        """Elastic timestamps are RFC 3339; only the date is kept."""
        text = str(timestamp or "").strip()
        if not text:
            return None
        with suppress(ValueError):
            return datetime.strptime(text.split("T")[0], "%Y-%m-%d").date()
        return None

    def attach_asset(self, finding, source):
        """
        Record the host the document came from.

        Elastic reports on machines and cloud resources rather than URLs, so the endpoint is the host
        identity, falling back to the resource or pod name.
        """
        name = self.host_identity(source) or self.asset_name(source)
        if not name:
            return
        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations.append(LocationData.url(host=name))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(host=name))

    def flex_float(self, value):
        """Elastic sends these numbers as either a number or a numeric string."""
        if value is None or isinstance(value, bool):
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            trimmed = value.strip().strip('"')
            if trimmed in {"", "null"}:
                return 0.0
            with suppress(ValueError):
                return float(trimmed)
        return 0.0

    def render_number(self, value):
        """Render a float the way the connector does - 7.5 stays 7.5, but 9.0 prints as 9."""
        return str(int(value)) if value == int(value) else repr(value)


class ElasticSecurityCnvmParser(ElasticSecurityDocuments):

    """
    Parses an Elastic Security export, importing Cloud Native Vulnerability Management findings.

    Mirrors the vulnerability half of pkg/tools/elasticsecurity/connector/converter field for field so
    a file import and an API sync deduplicate against each other instead of producing two copies of
    everything. Posture evaluations and detection alerts in the same export are separate scan types -
    see the Elastic Security Posture and Detections parsers - because Elastic models them as different
    kinds of data and the connector imports each behind its own toggle.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeVulnerabilities.
        return ["Elastic Security:CNVM - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Elastic Security:CNVM - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Elastic Security export (JSON) and report its Cloud Native Vulnerability "
            "Management findings. Matches the scan type used by the Elastic Security connector so "
            "file and API findings deduplicate. Posture and detection documents in the same export "
            "are imported by the Elastic Security Posture and Detections parsers."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Elastic Security CNVM Parser.

        Mirrors the connector's vulnerabilityFinding:
        - title: "<CVE> - <package> <version> on <asset>".
        - severity: Elastic's own label, falling back to the CVSS score; see severity().
        - description: the CVE description, the package, the ECS asset context and the CVSS score.
        - mitigation: the fixed version when Elastic reported one.
        - component_name / component_version: the vulnerable package.
        - unique_id_from_tool: the Elasticsearch document id.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "component_name",
            "component_version",
            "cvssv3_score",
            "publish_date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Elastic Security CNVM Parser.

        Copied from the Elastic Security CNVM block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for doc in self.documents(data):
            source = self.source(doc)
            if source is None:
                continue
            vulnerability = self.block(source, "vulnerability")
            if not str(vulnerability.get("id") or "").strip():
                # Not a CNVM document, or one Elastic could not attach to a CVE.
                continue
            findings.append(self.build_finding(doc, source, vulnerability, test))
        return findings

    def build_finding(self, doc, source, vulnerability, test):
        identifier = str(vulnerability["id"]).strip()
        package = self.block(source, "package")
        score = self.block(vulnerability, "score")
        base = self.flex_float(score.get("base")) if score else 0.0

        finding = Finding(
            test=test,
            title=self.title(source, vulnerability, package, identifier),
            severity=self.severity(vulnerability, score, base),
            description=self.describe(source, vulnerability, package, score, base),
            mitigation=self.mitigation(package),
            references=str(vulnerability.get("reference") or "").strip(),
            component_name=str(package.get("name") or "").strip() or None,
            component_version=str(package.get("version") or "").strip() or None,
            unique_id_from_tool=self.unique_id(doc, source, vulnerability, package, identifier),
            vuln_id_from_tool=identifier,
            # CNVM reads a workload's package inventory; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_vulnerability_ids = [identifier]
        finding.unsaved_tags = self.dedupe(["vulnerability", "cnvm", *self.cloud_tags(source)])

        if date := self.date_only(source.get("@timestamp")):
            finding.date = date
        if published := self.date_only(vulnerability.get("published_date")):
            finding.publish_date = published
        # Only a v3 vector's base goes in the v3 field; Elastic also reports v2 scores.
        if base > 0 and str(score.get("version") or "").startswith("3"):
            finding.cvssv3_score = base

        self.attach_asset(finding, source)
        return finding

    def title(self, source, vulnerability, package, identifier):
        title = identifier
        if name := str(package.get("name") or "").strip():
            title += f" - {name}"
            if version := str(package.get("version") or "").strip():
                title += f" {version}"
        if asset := self.asset_name(source):
            title += f" on {asset}"
        return title

    def unique_id(self, doc, source, vulnerability, package, identifier):
        """
        The Elasticsearch document id, which is stable across syncs.

        Only a hand-assembled export lacks one; then the asset, the CVE and the package stand in.
        """
        if document_id := str(doc.get("_id") or "").strip():
            return document_id
        parts = [self.asset_name(source), identifier]
        if package:
            parts.extend([str(package.get("name") or ""), str(package.get("version") or "")])
        return ":".join(parts)

    def severity(self, vulnerability, score, base):
        """
        Elastic's own label wins; an unrecognised one falls back to the CVSS score.

        A CNVM document has a score to fall back on, which is why an unknown label is not simply
        Medium here as it is for the other two scan types.
        """
        severity, recognised = self.severity_from_string(vulnerability.get("severity"))
        if recognised:
            return severity
        if not score:
            return "Info"
        if base >= CVSS_CRITICAL_FLOOR:
            return "Critical"
        if base >= CVSS_HIGH_FLOOR:
            return "High"
        if base >= CVSS_MEDIUM_FLOOR:
            return "Medium"
        if base > 0:
            return "Low"
        return "Info"

    def describe(self, source, vulnerability, package, score, base):
        parts = []
        if description := str(vulnerability.get("description") or "").strip():
            parts.append(description)

        if name := str(package.get("name") or "").strip():
            line = f"**Package:** {name}"
            if version := str(package.get("version") or "").strip():
                line += f" {version}"
            if kind := str(package.get("type") or "").strip():
                line += f" ({kind})"
            parts.append(line)

        parts.extend(self.asset_lines(source))

        if base > 0:
            line = f"**CVSS:** {self.render_number(base)}"
            if version := str(score.get("version") or "").strip():
                line += f" (v{version})"
            parts.append(line)
        return "\n\n".join(parts)

    def mitigation(self, package):
        if fix := str(package.get("fixed_version") or "").strip():
            name = str(package.get("name") or "").strip() or "the affected package"
            return (
                f"Upgrade {name} to {fix} or later, then rebuild and redeploy the affected workload "
                "image."
            )
        return (
            "No fixed version is published for this CVE yet. Track the vendor advisory, and mitigate "
            "by reducing the workload's exposure in the meantime."
        )
