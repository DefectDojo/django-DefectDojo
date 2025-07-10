import re
import sys
import io
import logging
import csv
import boto3
import botocore.exceptions
from abc import ABC, abstractmethod
from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.http import HttpResponse
from dojo.reports.custom_request import CustomRequest
form dojo.models import GeneralSettings
from dojo.reports.utils import get_url_presigned
from dojo.notifications.helper import create_notification
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
        logger.debug("REPORT FINDING: size of findings: " + str(sys.getsizeof(findings)))
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        logger.debug("REPORT FINDING: size of buffer init: " + str(sys.getsizeof(findings)))
        allowed_attributes = self.get_attributes()
        excludes_list = self.get_excludes()
        allowed_foreign_keys = self.get_attributes()
        first_row = True
        chunk_size = 1000
        bucket = GeneralSettings.get_value("BUCKET_NAME_REPORT", "")
        expiration_time = GeneralSettings.get_value("EXPIRATION_URL_REPORT", 3600)

        for counter, finding in enumerate(findings.iterator(chunck_size=chunk_size), start=1):
            if counter % chunk_size == 0:
                try:
                    session_s3 = boto3.Session().client('s3', region_name=settings.AWS_REGION)
                    url = get_url_presigned(
                        session_s3,
                        "reportes/reporte_rene.csv",
                        bucket,
                        expires_in=expiration_time
                    )
                    logger.debug(f"REPORT FINDING: URL {url}")
                    create_notification(
                        event="url_report_finding",
                        subject="Reporte Finding is ready📄",
                        title="Reporte is ready",
                        description="Your report is ready. Click the <strong>Download Report</strong> ⬇️ button to get it.",
                        url=url,
                        recipients=[request.user.username],
                        icon="download",
                        color_icon="#096C11",
                        expiration_time=f"{int(expiration_time / 60)} minutes")
                    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:

                        return response
                except botocore.exceptions.ClientError as e:
                    logger.error(f"Failed to upload report to S3: {e}")
                    raise

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
        logger.debug("REPORT FINDING: size of buffer: " + str(sys.getsizeof(buffer)))
        return buffer


def upload_file_multipart_s3(file_obj, bucket_name, object_name, chunk_size=5 * 1024 * 1024):
    """
    Sube un archivo a S3 en fragmentos (multipart upload) para evitar impacto en la base de datos.
    file_obj: archivo tipo file-like object (por ejemplo, request.FILES['archivo'])
    bucket_name: nombre del bucket S3
    object_name: nombre del objeto en S3
    chunk_size: tamaño de cada fragmento (por defecto 5MB)
    """
    s3_client = boto3.client('s3')
    try:
        # Inicia el multipart upload
        mpu = s3_client.create_multipart_upload(Bucket=bucket_name, Key=object_name)
        parts = []
        part_number = 1
        while True:
            data = file_obj.read(chunk_size)
            if not data:
                break
            part = s3_client.upload_part(
                Bucket=bucket_name,
                Key=object_name,
                PartNumber=part_number,
                UploadId=mpu['UploadId'],
                Body=data
            )
            parts.append({'PartNumber': part_number, 'ETag': part['ETag']})
            part_number += 1
        # Completa el multipart upload
        s3_client.complete_multipart_upload(
            Bucket=bucket_name,
            Key=object_name,
            UploadId=mpu['UploadId'],
            MultipartUpload={'Parts': parts}
        )
        return True
    except (BotoCoreError, ClientError) as e:
        logger.error(f"Error al subir archivo multipart a S3: {e}")
        # Si hay error, aborta el multipart upload
        if 'mpu' in locals():
            s3_client.abort_multipart_upload(
                Bucket=bucket_name,
                Key=object_name,
                UploadId=mpu['UploadId']
            )
        return False