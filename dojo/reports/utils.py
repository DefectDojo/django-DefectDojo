from bs4 import BeautifulSoup
from datetime import datetime
import logging
import re
logger = logging.getLogger(__name__)


def get_url_presigned(session,
                      key,
                      bucket,
                      expires_in=3600):
    url = session.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=expires_in
    )
    logger.debug(f"REPORT FINDING: {url}")
    return url

def extract_field_from_text_html(text, field_name):
    text_value = ""
    soup = BeautifulSoup(text, "html.parser")
    text_found = soup.find("strong", string=field_name)
    if text_found:
        text_value = text_found.next_sibling.strip()
    return text_value

def extract_field_from_text_regex(text, field_name):
    pattern = rf'{field_name}:\s*(.+?)(?:\r?\n|$)'
    match = re.search(pattern, text, re.IGNORECASE) if text else None
    
    if match:
        return match.group(1).strip()
    return ""

def upload_s3(session_s3, buffer, bucket, key):
    try:
        response = session_s3.put_object(Bucket=bucket, Key=key, Body=buffer)
        logger.info(f"REPORT FINDING: Upload successful: {response}")
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            return response
        else:
            logger.error(f"REPORT FINDING: Upload failed with status code: {response['ResponseMetadata']['HTTPStatusCode']}")
            raise Exception(response["ResponseMetadata"]["HTTPStatusCode"], "Failed to upload to S3")
    except Exception as e:
        logger.error(f"REPORT FINDING: Error uploading to S3: {e}")
        raise Exception("Failed to upload to S3 after multiple attempts due to expired token.")

def configure_headers_excel(finding, worksheet, font_bold, excludes_list, allowed_attributes, row_num, col_num):
    for key in dir(finding):
        try:
            if key not in excludes_list and (not callable(getattr(finding, key)) or key in allowed_attributes) and not key.startswith("_"):
                if callable(getattr(finding, key)) and key not in allowed_attributes:
                    continue
                cell = worksheet.cell(row=row_num, column=col_num, value=key)
                cell.font = font_bold
                col_num += 1
        except Exception as exc:
            logger.warning(f"Error in attribute: {key}" + str(exc))
            cell = worksheet.cell(row=row_num, column=col_num, value=key)
            col_num += 1
            continue
    cell = worksheet.cell(row=row_num, column=col_num, value="risk_acceptance_expiration_date")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="environment_image")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="cluster")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="registry_image")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="repository_image")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="namespace_image")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="tag_image")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="cloud_id")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="hostname")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="custom_id")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="found_by")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="engagement")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="area_responsible")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="product")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="product_type")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="product_type_environment")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="company")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="endpoints")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="vulnerability_ids")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="tags")
    cell.font = font_bold
    col_num += 1
    cell = worksheet.cell(row=row_num, column=col_num, value="classification")
    cell.font = font_bold
    col_num += 1

def configure_values_excel(finding, worksheet, excludes_list, allowed_foreign_keys, allowed_attributes, row_num, col_num, EXCEL_CHAR_LIMIT):
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
                if value and isinstance(value, datetime):
                    value = value.replace(tzinfo=None)
                worksheet.cell(row=row_num, column=col_num, value=value)
                col_num += 1
        except Exception as exc:
            logger.warning(f"Error in attribute: {key}" + str(exc))
            worksheet.cell(row=row_num, column=col_num, value="Value not supported")
            col_num += 1
            continue
    value_ra_expiration_date = finding.risk_acceptance.expiration_date.strftime("%Y-%m-%d") if finding.risk_acceptance else ""
    worksheet.cell(row=row_num, column=col_num, value=value_ra_expiration_date)
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_regex(finding.impact, "Environment"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Cluster:"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_regex(finding.impact, "Registry"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_regex(finding.impact, "Repository"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Namespaces:"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Tag:"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Cloud Id:"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Hostname:"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Custom Id:"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=finding.test.test_type.name)
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.name)
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_regex(finding.test.engagement.product.description, "AREA RESPONSABLE TI"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.product.name)
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.product.prod_type.name)
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_regex(finding.test.engagement.product.prod_type.description, "Environment"))
    col_num += 1
    worksheet.cell(row=row_num, column=col_num, value=extract_field_from_text_html(finding.description, "Company:"))
    col_num += 1

    endpoint_value = ""
    for endpoint in finding.endpoints.all():
        endpoint_value += f"{endpoint}; \n"
    endpoint_value = endpoint_value.removesuffix("; \n")
    if len(endpoint_value) > EXCEL_CHAR_LIMIT:
        endpoint_value = endpoint_value[:EXCEL_CHAR_LIMIT - 3] + "..."
    worksheet.cell(row=row_num, column=col_num, value=endpoint_value)
    col_num += 1

    vulnerability_ids_value = ""
    for num_vulnerability_ids, vulnerability_id in enumerate(finding.vulnerability_ids):
        if num_vulnerability_ids > 5:
            vulnerability_ids_value += "..."
            break
        vulnerability_ids_value += f"{vulnerability_id}; \n"
    if finding.cve and vulnerability_ids_value.find(finding.cve) < 0:
        vulnerability_ids_value += finding.cve
    vulnerability_ids_value = vulnerability_ids_value.removesuffix("; \n")
    worksheet.cell(row=row_num, column=col_num, value=vulnerability_ids_value)
    col_num += 1
    # tags
    tags_value = ""
    for tag in finding.tags.all():
        tags_value += f"{tag}; \n"
    tags_value = tags_value.removesuffix("; \n")
    worksheet.cell(row=row_num, column=col_num, value=tags_value)
    col_num += 1
    # classification
    if "tenable" in tags_value or "engine_iac" in tags_value:
        classification = finding.impact
    else:
        tags_list = [tag for tag in tags_value.split("; \n") 
                    if tag not in ["black_list", "white_list"]]
        classification = tags_list[0].upper() if tags_list else ""
    worksheet.cell(row=row_num, column=col_num, value=classification)
    col_num += 1

def configure_headers_csv(finding, excludes_list, allowed_attributes, fields):
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
        "risk_acceptance_expiration_date",
        "environment_image",
        "cluster",
        "registry_image",
        "repository_image",
        "namespace_image",
        "tag_image",
        "cloud_id",
        "hostname",
        "custom_id",
        "found_by",
        "engagement",
        "area_responsible",
        "product",
        "product_type",
        "product_type_environment",
        "company",
        "endpoints",
        "vulnerability_ids",
        "tags",
        "classification"
    ))

def configure_values_csv(finding, excludes_list, allowed_foreign_keys, allowed_attributes, fields, EXCEL_CHAR_LIMIT):
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
    
    value_ra_expiration_date = finding.risk_acceptance.expiration_date.strftime("%Y-%m-%d") if finding.risk_acceptance else ""
    fields.append(value_ra_expiration_date)
    fields.append(extract_field_from_text_regex(finding.impact, "Environment"))
    fields.append(extract_field_from_text_html(finding.description, "Cluster:"))
    fields.append(extract_field_from_text_regex(finding.impact, "Registry"))
    fields.append(extract_field_from_text_regex(finding.impact, "Repository"))
    fields.append(extract_field_from_text_html(finding.description, "Namespaces:"))
    fields.append(extract_field_from_text_html(finding.description, "Tag:"))
    fields.append(extract_field_from_text_html(finding.description, "Cloud Id:"))
    fields.append(extract_field_from_text_html(finding.description, "Hostname:"))
    fields.append(extract_field_from_text_html(finding.description, "Custom Id:"))
    fields.append(finding.test.test_type.name)
    fields.append(finding.test.engagement.name)
    fields.append(extract_field_from_text_regex(finding.test.engagement.product.description, "AREA RESPONSABLE TI"))
    fields.append(finding.test.engagement.product.name)
    fields.append(finding.test.engagement.product.prod_type.name)
    fields.append(extract_field_from_text_regex(finding.test.engagement.product.prod_type.description, "Environment"))
    fields.append(extract_field_from_text_html(finding.description, "Company:"))

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
    # Classification
    if "tenable" in tags_value or "engine_iac" in tags_value:
        classification = finding.impact
    else:
        tags_list = [tag for tag in tags_value.split("; ")
                    if tag not in ["black_list", "white_list"]]
        classification = tags_list[0].upper() if tags_list else ""
    fields.append(classification)