import re
import io
import logging
import csv
from abc import ABC, abstractmethod
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.http import HttpResponse
from dojo.reports.custom_request import CustomRequest
logger = logging.getLogger(__name__)


class BaseReportManager(ABC):
    def __init__(self, findings, request):
        self.user = request.user
        self.excel_char_limit = 32767
        self.fields = None
        self.request = request
        self.findings = findings

    def get_excludes(self):
        return ["SEVERITIES", "age", "github_issue", "jira_issue", "objects", "risk_acceptance",
        "test__engagement__product__authorized_group", "test__engagement__product__member",
        "test__engagement__product__prod_type__authorized_group", "test__engagement__product__prod_type__member",
        "unsaved_endpoints", "unsaved_vulnerability_ids", "unsaved_files", "unsaved_request", "unsaved_response",
        "unsaved_tags", "vulnerability_ids", "cve", "transferfindingfinding", "transfer_finding"]

    def get_foreign_keys(self):
        return ["defect_review_requested_by", "duplicate_finding", "finding_group", "last_reviewed_by",
            "mitigated_by", "reporter", "review_requested_by", "sonarqube_issue", "test"]

    def get_attributes(self):
        return ["sla_age", "sla_deadline", "sla_days_remaining"]

    def add_findings_data(self):
        return self.findings

    def add_extra_headers(self):
        pass

    def add_extra_values(self):
        pass
    
    def get_findings(self):
        pass

    @abstractmethod
    def generate_report(self, *args, **kwargs):
        """Abstract method to generate a report."""
        pass

    def _generate_headers(self, excludes, attributes, foreign_keys):
        headers = []
        for key in dir(self.findings[0]):
            if key not in excludes and not key.startswith("_"):
                headers.append(key)
        headers.extend(attributes)
        headers.extend(foreign_keys)
        return headers

    def _generate_row(self, finding, excludes, attributes, foreign_keys):
        row = []
        for key in dir(finding):
            if key not in excludes and not key.startswith("_"):
                value = getattr(finding, key, None)
                if callable(value):
                    value = value()
                row.append(value)
        for attr in attributes:
            row.append(getattr(finding, attr, ""))
        for fk in foreign_keys:
            fk_value = getattr(finding, fk, None)
            row.append(str(fk_value) if fk_value else "")
        return row


class CSVReportManager(BaseReportManager):

    def generate_report(self, *args, **kwargs):
        findings = self.add_findings_data()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        allowed_attributes = self.get_attributes()
        excludes_list = self.get_excludes()
        allowed_foreign_keys = self.get_attributes()
        first_row = True

        for finding in findings:
            self.finding = finding
            if first_row:
                fields = []
                self.fields = fields
                for key in dir(finding):
                    try:
                        if key not in excludes_list and (not callable(getattr(finding, key)) or key in allowed_attributes) and not key.startswith("_"):
                            if callable(getattr(finding, key)) and key not in allowed_attributes:
                                continue
                            fields.append(key)
                    except Exception as exc:
                        logger.error("Error in attribute: " + str(exc))
                        fields.append(key)
                        continue
                fields.extend((
                    "test",
                    "found_by",
                    "engagement_id",
                    "engagement",
                    "product_id",
                    "product",
                    "endpoints",
                    "vulnerability_ids",
                    "tags",
                ))
                self.fields = fields
                self.add_extra_headers()

                writer.writerow(fields)

                first_row = False
            if not first_row:
                fields = []
                for key in dir(finding):
                    try:
                        if key not in excludes_list and (not callable(getattr(finding, key)) or key in allowed_attributes) and not key.startswith("_"):
                            if not callable(getattr(finding, key)):
                                value = finding.__dict__.get(key)
                            if (key in allowed_foreign_keys or key in allowed_attributes) and getattr(finding, key):
                                if callable(getattr(finding, key)):
                                    func = getattr(finding, key)
                                    result = func()
                                    value = result
                                else:
                                    value = str(getattr(finding, key))
                            if value and isinstance(value, str):
                                value = value.replace("\n", " NEWLINE ").replace("\r", "")
                            fields.append(value)
                    except Exception as exc:
                        logger.error("Error in attribute: " + str(exc))
                        fields.append("Value not supported")
                        continue
                fields.append(finding.test.title)
                fields.append(finding.test.test_type.name)
                fields.append(finding.test.engagement.id)
                fields.append(finding.test.engagement.name)
                fields.append(finding.test.engagement.product.id)
                fields.append(finding.test.engagement.product.name)

                endpoint_value = ""
                for endpoint in finding.endpoints.all():
                    endpoint_value += f"{endpoint}; "
                endpoint_value = endpoint_value.removesuffix("; ")
                if len(endpoint_value) > self.excel_char_limit:
                    endpoint_value = endpoint_value[:self.excel_char_limit - 3] + "..."
                fields.append(endpoint_value)

                vulnerability_ids_value = ""
                for num_vulnerability_ids, vulnerability_id in enumerate(finding.vulnerability_ids):
                    if num_vulnerability_ids > 5:
                        vulnerability_ids_value += "..."
                        break
                    vulnerability_ids_value += f"{vulnerability_id}; "
                if finding.cve and vulnerability_ids_value.find(finding.cve) < 0:
                    vulnerability_ids_value += finding.cve
                vulnerability_ids_value = vulnerability_ids_value.removesuffix("; ")
                fields.append(vulnerability_ids_value)
                # Tags
                tags_value = ""
                for num_tags, tag in enumerate(finding.tags.all()):
                    if num_tags > 5:
                        tags_value += "..."
                        break
                    tags_value += f"{tag}; "
                tags_value = tags_value.removesuffix("; ")
                fields.append(tags_value)

                self.fields = fields
                self.finding = finding
                self.add_extra_values()

                writer.writerow(fields)
        return buffer