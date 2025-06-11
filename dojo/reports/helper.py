import boto3
from django.utils import timezone
from dojo.celery import app
from dojo.models import GeneralSettings
from django.http import Http404, HttpRequest, HttpResponse, QueryDict
from dojo.reports.views import get_findings
import io
import csv

BUCKET = 'mybuket-rene'
KEY = 'reportes/reporte.csv'
CHUNKSIZE = 1


def upload_s3(session, queryset, bucket, key, chunksize):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=[field.name for field in queryset.model._meta.fields])
    writer.writeheader()
    # validar si de debe pasar a  un dicionario o mejor se dejar como queryset
    for obj in queryset.iterator():
        row = {field.name: getattr(obj, field.name) for field in queryset.model._meta.fields}
        chunk.append(row)

        if len(chunk) == chunksize:
            writer.writerows(chunk)
            buffer.seek(0)
            print(f"Uploading chunk to S3...")
            session.put_object(Bucket=bucket, Key=key, Body=buffer.getvalue())
            buffer.seek(0)
            chunk = []

        print(f"REPORT FINDING: Uploading chunk {i}, overwriting {key} in S3...")
        # Subir el último chunk si hay datos restantes
    if chunk:
        writer.writerows(chunk)
        buffer.seek(0)
        session.put_object(Bucket=bucket, Key=key, Body=buffer.getvalue())


def get_url_presigned(session,
                      key,
                      buket,
                      expires_in=3600):
    url = session.generate_presigned_url(
        'get_object',
        Params={'Bucket': buket, 'Key': key},
        ExpiresIn=expires_in
    )
    print(f"REPORT FINDING: {url}")
    return url


def get_name_key(user):
    """
    Generate a unique key for the report based on the user's name and current time.
    """
    return f"reportes/{user.username}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"


@app.task
def async_generate_report(*args, **kwargs):
    url = kwargs.get('url', {})
    user = kwargs.get('user', None)
    queryset = get_findings(url=url)
    if url is None or user is None:
        print("REPORT FINDING: No URL or user provided, skipping report generation.")
        return
     
    s3_session = boto3.client('s3', region_name='us-east-1') # TODO: eliminar region
    bucket = GeneralSettings.get_value("BUCKET_NAME_REPORT", "")
    upload_s3(
        s3_session,
        queryset,
        bucket,
        KEY,
        CHUNKSIZE
    )


def get_excludes():
    return ["SEVERITIES", "age", "github_issue", "jira_issue", "objects", "risk_acceptance",
    "test__engagement__product__authorized_group", "test__engagement__product__member",
    "test__engagement__product__prod_type__authorized_group", "test__engagement__product__prod_type__member",
    "unsaved_endpoints", "unsaved_vulnerability_ids", "unsaved_files", "unsaved_request", "unsaved_response",
    "unsaved_tags", "vulnerability_ids", "cve", "transferfindingfinding", "transfer_finding"]


def get_foreign_keys():
    return ["defect_review_requested_by", "duplicate_finding", "finding_group", "last_reviewed_by",
        "mitigated_by", "reporter", "review_requested_by", "sonarqube_issue", "test"]


def get_attributes():
    return ["sla_age", "sla_deadline", "sla_days_remaining"]



def process_report(user, findings, *args, **kwargs):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=findings.csv"
    writer = csv.writer(response)
    allowed_attributes = kwargs["attributes"]
    excludes_list = kwargs["excludes"]
    allowed_foreign_keys = kwargs["get_attributes"]
    first_row = True

    for finding in findings:
        # self.finding = finding
        if first_row:
            fields = []
            # self.fields = fields
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
            if len(endpoint_value) > EXCEL_CHAR_LIMIT:
                endpoint_value = endpoint_value[:EXCEL_CHAR_LIMIT - 3] + "..."
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

    return response


# if __name__ == "__main__":
#     session = boto3.client('s3', region_name='us-east-1')
#     queryset = [
#         {"id": 1, "name": "Alice", "score": 95},
#         {"id": 2, "name": "Bob", "score": 88},
#         {"id": 3, "name": "Charlie", "score": 92},
#     ]
#     upload_s3(
#         session,
#         queryset,
#         BUCKET,
#         KEY,
#         CHUNKSIZE)
#     get_url_presigned(
#         session,
#         KEY,
#         BUCKET,
#         3600)
