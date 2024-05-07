import logging

from dojo.models import Endpoint, Finding
from dojo.tools.parser_test import ParserTest

logger = logging.getLogger(__name__)


class GenericJSONParser:
    ID = "Generic Findings Import"

    def _get_test_json(self, data, **kwargs):
        test_internal = ParserTest(
            name=data.get("name", self.ID),
            type=data.get("type", self.ID),
            version=data.get("version"),
        )
        test_internal.findings = []
        for item in data.get("findings", []):
            # remove endpoints of the dictionnary
            unsaved_endpoints = None
            if "endpoints" in item:
                unsaved_endpoints = item["endpoints"]
                del item["endpoints"]
            # remove files of the dictionnary
            unsaved_files = None
            if "files" in item:
                unsaved_files = item["files"]
                del item["files"]
            # remove vulnerability_ids of the dictionnary
            unsaved_vulnerability_ids = None
            if "vulnerability_ids" in item:
                unsaved_vulnerability_ids = item["vulnerability_ids"]
                del item["vulnerability_ids"]

            # check for required keys
            required = {"title", "severity", "description"}
            missing = sorted(required.difference(item))
            if missing:
                msg = f"Required fields are missing: {missing}"
                raise ValueError(msg)

            # check for allowed keys
            allowed = {
                "date",
                "cwe",
                "cve",
                "cvssv3",
                "cvssv3_score",
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
            }.union(required)

            # verify that custom field mapping is of type dict
            custom_fields_mapping = kwargs.get("custom_fields_mapping", None)
            if custom_fields_mapping and isinstance(custom_fields_mapping, dict):
                extracted_custom_fields = {}
                for custom_field, report_column in custom_fields_mapping.items():
                    if not custom_field or not report_column:
                        logger.warning(
                            f"custom_fields_mapping contains empty key or value: {custom_fields_mapping}"
                        )
                        continue

                    if report_column in item:
                        extracted_custom_fields[custom_field] = item[report_column]

                        # remove custom report column from item as finding model most likely will not know this field
                        del item[report_column]

                # write extracted custom fields into finding as json string
                if len(extracted_custom_fields) > 0:
                    item['custom_fields'] = extracted_custom_fields
                    allowed.add("custom_fields")

            not_allowed = sorted(set(item).difference(allowed))
            if not_allowed:
                msg = f"Not allowed fields are present: {not_allowed}"
                raise ValueError(msg)
            finding = Finding(**item)

            # manage endpoints
            if unsaved_endpoints:
                finding.unsaved_endpoints = []
                for endpoint_item in unsaved_endpoints:
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
            if unsaved_files:
                finding.unsaved_files = unsaved_files
            if finding.cve:
                finding.unsaved_vulnerability_ids = [finding.cve]
            if unsaved_vulnerability_ids:
                if finding.unsaved_vulnerability_ids:
                    finding.unsaved_vulnerability_ids.append(
                        unsaved_vulnerability_ids
                    )
                else:
                    finding.unsaved_vulnerability_ids = (
                        unsaved_vulnerability_ids
                    )
            test_internal.findings.append(finding)
        return test_internal
