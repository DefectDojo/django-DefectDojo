import re
import sys
import io
import logging
import csv
import boto3
import botocore.exceptions
from dojo.home.helper import get_key_for_user_and_urlpath, encode_string
from hashids import Hashids
from abc import ABC, abstractmethod
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.http import HttpResponse
from dojo.reports.custom_request import CustomRequest
from dojo.models import GeneralSettings
from dojo.reports.utils import get_url_presigned, upload_s3
from dojo.notifications.helper import create_notification
logger = logging.getLogger(__name__)


class BaseReportManager(ABC):
    def __init__(self, findings, request):
        self.user = request.user
        self.excel_char_limit = 32767
        self.fields = None
        self.request = request
        self.findings = findings
    

    def get_url_encode(self):
        return encode_string(self.request.META.get("QUERY_STRING", ""))

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

    def __init__(self, findings, request):
        super().__init__(findings, request)
        self.bucket = GeneralSettings.get_value("BUCKET_NAME_REPORT", "")
        self.expiration_time = GeneralSettings.get_value("EXPIRATION_URL_REPORT", 3600)
        self.key_cache = get_key_for_user_and_urlpath(self.request, base_key="report_finding")
        self.url_path = f"{GeneralSettings.get_value("URL_FILE_BUKECT_REPORT_FINDINGS", 'report/')}{self.request.user.username}_{self.get_url_encode()}.csv"
        self.chunk_size = GeneralSettings.get_value("CHUNK_SIZE_REPORT", 500)
        self.url_presigned = ""

    def get_url(self):
        if value := cache.get(self.key_cache):
            logger.debug(f"REPORT FINDING: Cache get for key {self.key_cache} value {value}")
            return value

    def send_report(self, buffer):
        try:
            session_s3 = boto3.Session().client(
                's3',
                region_name=settings.AWS_REGION)
            upload_s3(session_s3,
                      buffer,
                      self.bucket,
                      self.url_path)
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to upload report to S3: {e}")
            raise

    def generate_report(self, *args, **kwargs):
        findings = self.add_findings_data()
        logger.debug("REPORT FINDING: size of findings: " + str(sys.getsizeof(findings)))
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        logger.debug("REPORT FINDING: size of buffer init: " + str(sys.getsizeof(findings)))
        allowed_attributes = self.get_attributes()
        excludes_list = self.get_excludes()
        allowed_foreign_keys = self.get_attributes()
        first_row = True
        counter = 0

        for counter, finding in enumerate(findings.iterator(chunk_size=self.chunk_size), start=1):
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
        
            if counter % self.chunk_size == 0:
                self.send_report(buffer)
        if counter % self.chunk_size != 0:
            logger.debug("REPORT FINDING: Sending report at the end of the loop")
            self.send_report(buffer)
            session_s3 = boto3.Session().client(
                's3',
                region_name=settings.AWS_REGION)
            url = get_url_presigned(
                session_s3,
                key=self.url_path,
                bucket=self.bucket,
                expires_in=self.expiration_time
            )
            cache.set(
                self.key_cache,
                url,
                self.expiration_time
            )
            logger.debug(f"REPORT FINDING: URL {url}")
            create_notification(
                event="url_report_finding",
                subject="Reporte Finding is ready📄",
                title="Reporte is ready",
                description="Your report is ready. Click the <strong>Download Report</strong> ⬇️ button to get it.",
                url=f"{settings.SITE_URL}/url_presigned/{self.get_url_encode()}",
                recipients=[self.request.user.username],
                icon="download",
                color_icon="#096C11",
                expiration_time=f"{int(self.expiration_time / 60)} minutes")
        return True
