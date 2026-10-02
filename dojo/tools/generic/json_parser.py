import base64
import math

import dateutil
from django.core.files.base import ContentFile

from dojo.finding.cwe import cwe_number
from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, FileUpload, Finding
from dojo.tools.locations import LocationData
from dojo.tools.parser_test import ParserTest
from dojo.tools.utils import drop_repeated_unique_ids

# Accepted fields that map to a numeric column on Finding, and the type they hold.
NUMERIC_FIELDS = {
    "cvssv3_score": float,
    "cvssv4_score": float,
    "cwe": int,
    "epss_percentile": float,
    "epss_score": float,
    "line": int,
    "nb_occurences": int,
    "sast_source_line": int,
    "scanner_confidence": int,
    "thread_id": int,
}


def to_number(value, converter):
    """Convert value with converter, returning None when it does not hold a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        value = value.strip()
    try:
        number = converter(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


class GenericJSONParser:
    ID = "Generic Findings Import"

    def _get_test_json(self, data):
        test_internal = ParserTest(
            name=data.get("name", self.ID),
            parser_type=data.get("type", self.ID),
            version=data.get("version"),
            description=data.get("description"),
            dynamic_tool=data.get("dynamic_tool"),
            static_tool=data.get("static_tool"),
            soc=data.get("soc"),
        )
        test_internal.findings = []
        for item in data.get("findings", []):
            # remove endpoints from the dictionary
            unsaved_locations = None
            if "endpoints" in item:
                unsaved_locations = item["endpoints"]
                del item["endpoints"]
            # remove files from the dictionary
            unsaved_files = None
            if "files" in item:
                unsaved_files = item["files"]
                del item["files"]
            # remove tags from the dictionary
            unsaved_tags = None
            if "tags" in item:
                unsaved_tags = item["tags"]
                del item["tags"]
            # remove vulnerability_ids from the dictionary
            unsaved_vulnerability_ids = None
            if "vulnerability_ids" in item:
                unsaved_vulnerability_ids = item["vulnerability_ids"]
                del item["vulnerability_ids"]
            # remove cwes from the dictionary (multiple CWEs per finding).
            # "cwes" is not a Finding field, so it is popped like vulnerability_ids.
            unsaved_cwes = None
            if "cwes" in item:
                unsaved_cwes = item["cwes"]
                del item["cwes"]
            # check for required keys
            required = {"title", "severity", "description"}

            if "date" in item:
                item["date"] = dateutil.parser.parse(item["date"]).date()

            if "mitigated" in item:
                item["mitigated"] = dateutil.parser.parse(item["mitigated"])

            missing = sorted(required.difference(item))
            if missing:
                msg = f"Required fields are missing: {missing}"
                raise ValueError(msg)

            # check for allowed keys
            allowed = {
                "date",
                "cwe",
                "cve",
                "epss_score",
                "epss_percentile",
                "cvssv3",
                "cvssv3_score",
                "cvssv4",
                "cvssv4_score",
                "mitigation",
                "impact",
                "steps_to_reproduce",
                "severity_justification",
                "references",
                "active",
                "verified",
                "false_p",
                "out_of_scope",
                "risk_accepted",
                "under_review",
                "is_mitigated",
                "thread_id",
                "mitigated",
                "numerical_severity",
                "param",
                "payload",
                "line",
                "file_path",
                "component_name",
                "component_version",
                "static_finding",
                "dynamic_finding",
                "scanner_confidence",
                "unique_id_from_tool",
                "vuln_id_from_tool",
                "sast_source_object",
                "sast_sink_object",
                "sast_source_line",
                "sast_source_file_path",
                "nb_occurences",
                "publish_date",
                "service",
                "planned_remediation_date",
                "planned_remediation_version",
                "effort_for_fixing",
                "tags",
                "kev_date",
                "known_exploited",
                "ransomware_used",
                "fix_available",
                "fix_version",
            }.union(required)
            not_allowed = sorted(set(item).difference(allowed))
            if not_allowed:
                msg = f"Not allowed fields are present: {not_allowed}"
                raise ValueError(msg)

            self._normalize_numeric_fields(item)
            finding = Finding(**item)

            # manage endpoints
            if unsaved_locations:
                if locations_enabled():
                    for location_item in unsaved_locations:
                        if isinstance(location_item, str):
                            if "://" in location_item:  # is the host full uri?
                                location = LocationData.url(url=location_item)
                            else:
                                location = LocationData.url(url="//" + location_item)
                        else:
                            location = LocationData.url(**location_item)
                        finding.unsaved_locations.append(location)
                else:
                    # TODO: Delete this after the move to Locations
                    for endpoint_item in unsaved_locations:
                        if isinstance(endpoint_item, str):
                            if "://" in endpoint_item:  # is the host full uri?
                                endpoint = Endpoint.from_uri(endpoint_item)
                                # can raise exception if the host is not valid URL
                            else:
                                endpoint = Endpoint.from_uri("//" + endpoint_item)
                                # can raise exception if there is no way to parse
                                # the host
                        else:
                            endpoint = Endpoint(**endpoint_item)
                        finding.unsaved_endpoints.append(endpoint)
            if locations_enabled():
                component_name = item.get("component_name")
                component_version = item.get("component_version")
                file_path = item.get("file_path")
                if component_name or component_version or file_path:
                    finding.unsaved_locations.append(
                        LocationData.dependency(
                            name=component_name,
                            version=component_version,
                            file_path=file_path,
                        ),
                    )
                if file_path:
                    line = item.get("line")
                    source_line = item.get("sast_source_line")
                    finding.unsaved_locations.append(
                        LocationData.code(
                            file_path=file_path,
                            line=int(line) if line is not None and str(line).isdigit() else None,
                            source_object=item.get("sast_source_object") or "",
                            sink_object=item.get("sast_sink_object") or "",
                            source_file_path=item.get("sast_source_file_path") or "",
                            source_line=int(source_line) if source_line is not None and str(source_line).isdigit() else None,
                        ),
                    )
            if unsaved_files:
                for unsaved_file in unsaved_files:
                    data = base64.b64decode(unsaved_file.get("data"))
                    title = unsaved_file.get("title", "<No title>")
                    FileUpload(title=title, file=ContentFile(data)).clean()

                finding.unsaved_files = unsaved_files
            if unsaved_tags:
                finding.unsaved_tags = unsaved_tags
            if finding.cve:
                finding.unsaved_vulnerability_ids = [finding.cve]
            if unsaved_vulnerability_ids:
                if isinstance(unsaved_vulnerability_ids, str):
                    unsaved_vulnerability_ids = [unsaved_vulnerability_ids]
                if finding.unsaved_vulnerability_ids:
                    finding.unsaved_vulnerability_ids.extend(
                        unsaved_vulnerability_ids,
                    )
                else:
                    finding.unsaved_vulnerability_ids = list(
                        unsaved_vulnerability_ids,
                    )
            # multiple CWEs: keep the primary on finding.cwe (only if not already
            # supplied via "cwe") and persist the full set via unsaved_cwes. The
            # import pipeline normalizes/deduplicates through finding_cwe_labels().
            if unsaved_cwes:
                if not finding.cwe:
                    finding.cwe = cwe_number(unsaved_cwes[0])
                finding.unsaved_cwes = unsaved_cwes
            test_internal.findings.append(finding)
        # The generic format hands unique_id_from_tool straight to callers' pipelines, and the
        # shipped algorithm is hash-only, so classic matching never reads it. It is still
        # recorded as a vendor identity by consumers that do (an operator-configured unique-id
        # algorithm, Pro's identity ledger), so an id repeating inside one report is dropped
        # rather than stored as if it named a single finding.
        drop_repeated_unique_ids(test_internal.findings)
        return test_internal

    def _normalize_numeric_fields(self, item):
        """
        Coerce the numeric fields of a finding, dropping the ones that hold no number.

        Django accepts any value on assignment and only rejects a non-numeric one when
        the finding is written, so a report using a placeholder such as "N/A" for a line
        number it could not determine aborts the whole import from deep inside the
        database write. Dropping the key here lets the model default apply instead, and
        a number that arrives quoted is kept by converting it.
        """
        for field, converter in NUMERIC_FIELDS.items():
            if field not in item or item[field] is None:
                continue
            number = to_number(item[field], converter)
            if number is None:
                del item[field]
            else:
                item[field] = number
