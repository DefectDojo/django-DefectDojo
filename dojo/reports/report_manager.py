import sys
import io
import logging
import csv
import boto3
from itertools import islice
from dojo.authorization.exclusive_permissions import exclude_test_or_finding_with_tag
from django.conf import settings
from openpyxl import Workbook
from openpyxl.styles import Font
import botocore.exceptions
from botocore.client import Config
from dojo.home.helper import get_key_for_user_and_urlpath, encode_string
from abc import ABC, abstractmethod
from django.core.cache import cache
from django.conf import settings
from django.template.loader import render_to_string
from dojo.reports.multipart_uploder import S3MultipartUploader
from dojo.models import GeneralSettings
from dojo.reports.utils import get_url_presigned, upload_s3, configure_headers_excel, configure_values_excel, configure_headers_csv, configure_values_csv
from dojo.notifications.helper import create_notification
from dojo.reports import helper as helper_reports
logger = logging.getLogger(__name__)

class BaseReportManager(ABC):

    MIN_PART_SIZE = 5 * 1024 * 1024 # 5 Mb minimum part size for multipart upload required by AWS S3

    def __init__(self, findings, request):
        self.user = request.user
        self.excel_char_limit = 32767
        self.fields = None
        self.request = request
        self.findings = self.exclude_red_team(findings, request)
        self.bucket = GeneralSettings.get_value("BUCKET_NAME_REPORT", "")
        self.expiration_time = GeneralSettings.get_value("EXPIRATION_URL_REPORT", 3600)
        self.key_cache = get_key_for_user_and_urlpath(self.request, base_key="report_finding") 
        self.chunk_size = GeneralSettings.get_value("CHUNK_SIZE_REPORT", 8000)
        self.session_s3 = boto3.Session().client('s3', region_name=settings.AWS_REGION, config=Config(signature_version='s3v4'))
        self.buffer = io.StringIO()
        self.allowed_attributes = self.get_attributes()
        self.allowed_foreign_keys = self.get_attributes()
        self.first_row = True 
        self.url_presigned = ""
        self.findings_query = self.add_findings_data()
        self.findigns_all_counter = self.findings_query.count() 
    
    def exclude_red_team(self, findings, request):
        if settings.ENABLE_FILTER_FOR_TAG_RED_TEAM:
            findings = exclude_test_or_finding_with_tag(
                objs=findings,
                product=None,
                user=request.user
            )
        return findings
    def get_url_encode(self):
        return encode_string(self.request.META.get("QUERY_STRING", ""))

    def get_foreign_keys(self):
        return ["defect_review_requested_by", "duplicate_finding", "finding_group", "last_reviewed_by",
            "mitigated_by", "reporter", "review_requested_by", "sonarqube_issue", "test"]

    def get_attributes(self):
        return ["sla_age", "sla_deadline", "sla_days_remaining", "priority_classification", "long_term_acceptance"]

    def add_findings_data(self):
        return self.findings

    def add_extra_headers(self):
        pass

    def add_extra_values(self):
        pass
    
    def get_findings(self):
        pass

    def get_url(self):
        if value := cache.get(self.key_cache):
            logger.debug(f"REPORT FINDING: Cache get for key {self.key_cache} value {value}")
            return value

    @abstractmethod 
    def send_report(self):
        try:
            upload_s3(self.session_s3,
                      self.buffer.getvalue(),
                      self.bucket,
                      self.url_path)

        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to upload report to S3: {e}")
            raise
    
    @abstractmethod
    def save_report(self):
        pass
    
    @abstractmethod
    def generate_report(self, *args, **kwargs):
        findings = self.add_findings_data()
        excludes_list = helper_reports.get_excludes()
        allowed_attributes = self.get_attributes()
        allowed_foreign_keys = self.get_attributes()
        if self.findigns_all_counter <= self.chunk_size:
            logger.info(f"REPORT FINDING: Using SINGLE upload for {self.findigns_all_counter} findings")
            self._generate_single_upload(findings, excludes_list, allowed_attributes, allowed_foreign_keys)
            self.save_report()
            self.send_report()
        else:
            logger.info(f"REPORT FINDING: Using MULTIPART upload for {self.findigns_all_counter} findings")
            self._generate_multipart_upload(findings, excludes_list, allowed_attributes, allowed_foreign_keys)
        
        url = get_url_presigned(
            self.session_s3,
            key=self.url_path,
            bucket=self.bucket,
            expires_in=self.expiration_time
        )
        cache.set(
            self.key_cache,
            url,
            self.expiration_time
        )

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
    
    @abstractmethod
    def _add_finding_in_buffer(self, finding, excludes_list, allowed_attributes, allowed_foreign_keys):
        """Abstract method to add a finding to the buffer."""
        pass

    def _generate_single_upload(self, findings, excludes_list, allowed_attributes, allowed_foreign_keys):
        buffer_size_mb = sys.getsizeof(findings) / (1024 * 1024) 
        logger.info(f"REPORT FINDING: size of findings: {buffer_size_mb:.2f} MB")
        for finding in findings.iterator(chunk_size=1000):
            self._add_finding_in_buffer(finding, excludes_list, allowed_attributes, allowed_foreign_keys)
            logger.info(f"REPORT FINDING: buffer size: {sys.getsizeof(self.buffer)} bytes")
        return True

    def _generate_multipart_upload(self, findings, excludes_list, allowed_attributes, allowed_foreign_keys):

        try:
            current_buffer_size = 0
            self.multipart_uploader.start_upload()
            self.first_row = True
            for counter, finding in enumerate(findings.iterator(chunk_size=self.chunk_size), start=1):
                logger.info(f"REPORT FINDING: Processing finding {counter} of {self.findigns_all_counter}")
                self._add_finding_in_buffer(finding, excludes_list, allowed_attributes, allowed_foreign_keys)

                if counter % self.chunk_size == 0:
                    buffer_value = self.buffer.getvalue()
                    if isinstance(buffer_value, str):
                        current_buffer_size = len(buffer_value.encode('utf-8'))
                    elif isinstance(buffer_value, bytes):
                        current_buffer_size = len(buffer_value)
                    else:
                        logger.error(f"REPORT FINDING: Unknown buffer type: {type(buffer_value)}")
                    current_size_mb = current_buffer_size / (1024 * 1024)
                    logger.info(f"REPORT FINDING: Size report with {current_size_mb:.2f}MB ({counter} findings)")
                    if current_buffer_size >= self.MIN_PART_SIZE:
                        self.save_report()
                        logger.info(f"REPORT FINDING: Uploading part with {current_size_mb:.2f}MB ({counter} findings)")
                        self.multipart_uploader.upload_part(self.buffer.getvalue())
                        self.buffer.seek(0)
                        self.buffer.truncate(0)
                        logger.info("REPORT FINDING: cleand buffer after upload")
            if counter % self.chunk_size != 0:
                logger.info("report finding: sending report at the end of the loop")
                self.save_report()
                self.multipart_uploader.upload_part(self.buffer.getvalue())
                self.multipart_uploader.complete_upload()


        except Exception as e:
            if self.multipart_uploader:
                self.multipart_uploader.abort_upload()
            logger.error(f"Error during multipart upload: {e}")
            raise

        return True

    def _generate_row(self, finding, excludes_list, allowed_attributes, foreign_keys):
        row = []
        for key in dir(finding):
            if key not in excludes_list and not key.startswith("_"):
                value = getattr(finding, key, None)
                if callable(value):
                    value = value()
                row.append(value)
        for attr in allowed_attributes:
            row.append(getattr(finding, attr, ""))
        for fk in foreign_keys:
            fk_value = getattr(finding, fk, None)
            row.append(str(fk_value) if fk_value else "")
        return row


class CSVReportManager(BaseReportManager):

    def __init__(self, findings, request):
        super().__init__(findings, request)
        self.url_path = f"{GeneralSettings.get_value('URL_FILE_BUCKET_REPORT_FINDINGS', 'report/')}{self.request.user.username}_{self.get_url_encode()}.csv"
        self.multipart_uploader = S3MultipartUploader(self.session_s3, self.bucket, self.url_path)
        self.writer = csv.writer(self.buffer)
    
    def save_report(self):
        pass

    def send_report(self):
        super().send_report()

    def generate_report(self, *args, **kwargs):
        super().generate_report(*args, **kwargs)
    
    def _add_finding_in_buffer(
            self,
            finding,
            excludes_list,
            allowed_attributes,
            allowed_foreign_keys,
        ):

        if self.first_row:
            fields = []
            self.fields = fields
            configure_headers_csv(finding, excludes_list, allowed_attributes, fields)
            self.fields = fields
            self.add_extra_headers()

            self.writer.writerow(fields)

        self.first_row = False
        if not self.first_row:
            fields = []
            configure_values_csv(finding, excludes_list, allowed_foreign_keys, allowed_attributes, fields, self.excel_char_limit)
            self.fields = fields
            self.finding = finding
            self.add_extra_values()

            self.writer.writerow(fields)
        
        return True

class ExcelReportManager(BaseReportManager):

    EXCEL_CHAR_LIMIT = 32767 

    def __init__(self, findings, request):
        super().__init__(findings, request)
        self.workbook = Workbook()
        self.workbook.iso_dates = True
        self.worksheet = self.workbook.active
        self.row_num = 2
        self.worksheet.title = "Findings"
        self.url_path = f"{GeneralSettings.get_value('URL_FILE_BUCKET_REPORT_FINDINGS', 'report/')}{self.request.user.username}_{self.get_url_encode()}.xlsx"
        self.multipart_uploader = S3MultipartUploader(self.session_s3, self.bucket, self.url_path)
        self.font_bold = Font(bold=True)
        self.buffer = io.BytesIO()
        self.row_num = 1 
        self.col_num = 1
    
    def save_report(self):
        """
        Save the Excel report to the buffer.
        """
        self.workbook.save(self.buffer)
    
    def send_report(self):
        super().send_report()
    
    def generate_report(self, *args, **kwargs):
        super().generate_report(*args, **kwargs)

    def _add_finding_in_buffer(
            self,
            finding,
            excludes_list,
            allowed_attributes,
            allowed_foreign_keys,
        ):
        if self.first_row:
            col_num = 1
            configure_headers_excel(finding, self.worksheet, self.font_bold, excludes_list, allowed_attributes, self.row_num, col_num)
            self.col_num = col_num
            self.row_num += 1
            self.add_extra_headers()
        self.first_row = False
        if not self.first_row:
            col_num = 1
            configure_values_excel(finding, self.worksheet, excludes_list, allowed_foreign_keys, allowed_attributes, self.row_num, col_num, self.EXCEL_CHAR_LIMIT)
            self.col_num = col_num
            self.row_num = self.row_num
            self.findings = finding
            self.add_extra_values()
        self.row_num += 1

        self.buffer.seek(0)
    
        return True

    
class HtmlReportManager(BaseReportManager):

    def __init__(self, findings, request, obj):
        super().__init__(findings, request)
        self.url_path = f"{GeneralSettings.get_value('URL_FILE_BUCKET_REPORT_FINDINGS', 'report/')}{self.request.user.username}_{self.get_url_encode()}.html"
        self.multipart_uploader = S3MultipartUploader(self.session_s3, self.bucket, self.url_path)
        self.buffer = io.BytesIO()
        self.obj = obj
    
    def _add_finding_in_buffer(
            self,
            finding,
            excludes_list,
            allowed_attributes,
            allowed_foreign_keys,
        ):
        pass

    def save_report(self):
        pass

    def send_report(self):
        try:
            upload_s3(self.session_s3,
                      self.buffer,
                      self.bucket,
                      self.url_path)

        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to upload report html to S3: {e}")
            raise
    

    def chunked_iterator(self, queryset, chunk_size):
        it = queryset.iterator()
        while True:
            chunk = list(islice(it, chunk_size))
            if not chunk:
                break
            yield chunk

    
    def generate_report(self, *args, **kwargs):
        product = engagement = test = None

        if self.obj:
            if type(self.obj).__name__ == "Product":
                product = self.obj
            elif type(self.obj).__name__ == "Engagement":
                engagement = self.obj
            elif type(self.obj).__name__ == "Test":
                test = self.obj
        
        if self.findigns_all_counter <= self.chunk_size:
            self.buffer =  render_to_string('dojo/finding_pdf_report.html', {
                        "report_name": "Finding Report",
                        "product": product,
                        "engagement": engagement,
                        "test": test,
                        "findings": self.findings,
                        "user": self.request.user,
                        "team_name": settings.TEAM_NAME,
                        "title": "Finding Report",
                        "user_id": self.request.user.id 
                  })
            logger.info(f"REPORT FINDING: Using SINGLE upload for {self.findigns_all_counter} findings")
            self.send_report()
        else:
            logger.info(f"REPORT FINDING: Using MULTIPART upload for {self.findigns_all_counter} findings")
            try:
                current_buffer_size = 0
                self.multipart_uploader.start_upload()
                self.first_row = True
                for counter, finding_chunk in enumerate(self.chunked_iterator(self.findings, self.chunk_size), start=1):
                    logger.debug(f"REPORT FINDING: Processing chunk html {counter} of {self.findigns_all_counter // self.chunk_size + 1}")
                    self.buffer =  render_to_string('dojo/finding_pdf_report.html', {
                        "report_name": "Finding Report",
                        "product": product,
                        "engagement": engagement,
                        "test": test,
                        "findings": finding_chunk,
                        "user": self.request.user,
                        "team_name": settings.TEAM_NAME,
                        "title": "Finding Report",
                        "user_id": self.request.user.id 
                    })

                    logger.info(f"REPORT FINDING: Processing finding {counter} of {self.findigns_all_counter}")
                    if counter % self.chunk_size == 0:
                        logger.error(f"REPORT FINDING: Unknown buffer type: {type(self.buffer)}")
                        current_size_mb = current_buffer_size / (1024 * 1024)
                        logger.info(f"REPORT FINDING: Size report with {current_size_mb:.2f}MB ({counter} findings)")
                        if current_buffer_size >= self.MIN_PART_SIZE:
                            logger.info(f"REPORT FINDING: Uploading part with {current_size_mb:.2f}MB ({counter} findings)")
                            self.multipart_uploader.upload_part(self.buffer.getvalue())
                            self.buffer.seek(0)
                            self.buffer.truncate(0)
                            logger.info("REPORT FINDING: cleand buffer after upload")
                if counter % self.chunk_size != 0:
                    logger.info("report finding: sending report at the end of the loop")
                    self.multipart_uploader.upload_part(self.buffer)
                    self.multipart_uploader.complete_upload()
            except Exception as e:
                if self.multipart_uploader:
                    self.multipart_uploader.abort_upload()
                logger.error(f"Error during multipart upload: {e}")
                raise

        
        url = get_url_presigned(
            self.session_s3,
            key=self.url_path,
            bucket=self.bucket,
            expires_in=self.expiration_time
        )
        cache.set(
            self.key_cache,
            url,
            self.expiration_time
        )

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
