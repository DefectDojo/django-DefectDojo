import csv
import io
import re

from dateutil import parser as dateutil_parser

from dojo.models import Endpoint
from dojo.tools.locations import LocationData

SEVERITY_MAPPING = {
    "1": "Info",
    "2": "Low",
    "3": "Medium",
    "4": "High",
    "5": "Critical",
}


def strip_html(text):
    """Remove HTML tags from text and clean up whitespace."""
    if not text:
        return text
    cleaned = re.sub(r"<[^>]+>", "", text)
    return cleaned.strip()


def clean_field_value(value):
    """Strip stray quotes and whitespace from parsed field values."""
    if not value:
        return value
    # Strip whitespace first
    value = value.strip()
    # Remove trailing/leading stray quotes left by non-standard CSV parsing
    value = value.strip('"')
    return value.strip()


def is_qualys_null(value):
    """Check if a value is a Qualys null marker."""
    return not value or value.strip() in {"'-", ""}


def map_qualys_severity(severity_value):
    if severity_value is None:
        return "Info"
    severity_str = str(severity_value).strip()
    return SEVERITY_MAPPING.get(severity_str, "Info")


def build_severity_justification(severity_value):
    if severity_value is None:
        return None
    severity_str = str(severity_value).strip()
    if severity_str in SEVERITY_MAPPING:
        return f"Qualys Severity: {severity_str}"
    return None


def parse_qualys_date(date_string):
    if not date_string or date_string == "'-":
        return None
    try:
        return dateutil_parser.parse(date_string).date()
    except (ValueError, TypeError):
        return None


def truncate_title(title, max_length=500):
    if not title:
        return "Qualys VMDR Finding"
    title = title.strip()
    if len(title) <= max_length:
        return title
    return title[: max_length - 3] + "..."


def build_description_qid(row):
    # Title and Threat are omitted — they map to finding.title and finding.impact
    parts = []

    qid = row.get("QID", "")
    if qid:
        parts.append(f"**QID:** {qid}")

    category = row.get("Category", "")
    if category:
        parts.append(f"**Category:** {category}")

    rti = row.get("RTI", "")
    if rti:
        parts.append(f"**RTI:** {rti}")

    os_info = row.get("Operating System", "")
    if os_info:
        parts.append(f"**Operating System:** {os_info}")

    results = row.get("Results", "")
    if results:
        parts.append(f"**Results:** {clean_field_value(results)}")

    last_detected = row.get("Last Detected", "")
    if last_detected:
        parts.append(f"**Last Detected:** {last_detected}")

    return "\n\n".join(parts) if parts else "No details available."


def build_description_cve(row):
    # Title and Threat are omitted — they map to finding.title and finding.impact
    parts = []

    cve = row.get("CVE", "")
    if cve:
        parts.append(f"**CVE:** {cve}")

    cve_desc = row.get("CVE-Description", "")
    if cve_desc:
        parts.append(f"**CVE Description:** {cve_desc}")

    qid = row.get("QID", "")
    if qid:
        parts.append(f"**QID:** {qid}")

    category = row.get("Category", "")
    if category:
        parts.append(f"**Category:** {category}")

    rti = row.get("RTI", "")
    if rti:
        parts.append(f"**RTI:** {rti}")

    os_info = row.get("Operating System", "")
    if os_info:
        parts.append(f"**Operating System:** {os_info}")

    results = row.get("Results", "")
    if results:
        parts.append(f"**Results:** {clean_field_value(results)}")

    last_detected = row.get("Last Detected", "")
    if last_detected:
        parts.append(f"**Last Detected:** {last_detected}")

    return "\n\n".join(parts) if parts else "No details available."


def _extract_hosts(ipv4_field, ipv6_field):
    if ipv4_field and ipv4_field.strip():
        return [ip.strip() for ip in ipv4_field.split(",") if ip.strip()]
    if ipv6_field and ipv6_field.strip():
        return [ipv6_field.strip()]
    return []


# TODO: Delete this after the move to Locations
def parse_endpoints(ipv4_field, ipv6_field):
    return [Endpoint(host=host) for host in _extract_hosts(ipv4_field, ipv6_field)]


def parse_locations(ipv4_field, ipv6_field):
    return [LocationData.url(host=host) for host in _extract_hosts(ipv4_field, ipv6_field)]


def parse_tags(tags_field):
    if not tags_field or not tags_field.strip():
        return []
    return [tag.strip() for tag in tags_field.split(",") if tag.strip()]


def parse_cvss_score(cvss_field):
    if not cvss_field or cvss_field == "'-":
        return None
    try:
        return float(cvss_field)
    except (ValueError, TypeError):
        return None


def _is_qualys_nonstandard_format(header_line):
    # Non-standard Qualys format uses ,"" as field delimiter
    return ',""' in header_line


def _detect_metadata_lines(lines):
    # Qualys exports: WITH metadata (3 lines before header) or WITHOUT (header at line 1)
    if not lines:
        return 0
    first_line = lines[0].strip()
    # Files with metadata start with the report title line
    if first_line.startswith('"Asset Vuln Datalist Report'):
        return 3
    # Files without metadata start directly with the header
    return 0


def _is_record_end_line(line):
    # Determine if a line ends a multi-line nonstandard CSV record.
    # Record-ending lines end with 3 trailing quotes. Malformed patterns
    # like #table cols=""3"" produce 5+ trailing quotes mid-record.
    # We distinguish by checking the char before the quote run:
    # comma means record end (empty field), otherwise mid-record.
    stripped = line.rstrip()
    if not stripped.endswith('"'):
        return False
    # Count trailing quotes
    quote_count = 0
    for ch in reversed(stripped):
        if ch == '"':
            quote_count += 1
        else:
            break
    if quote_count < 3:
        return False
    if quote_count == 3:
        return True
    # 4+ trailing quotes: record end only if preceded by comma
    prefix = stripped[: len(stripped) - quote_count]
    return prefix.endswith(",")


def _parse_qualys_nonstandard_row(line):
    # Parse a Qualys nonstandard CSV row.
    # Format: "field1,""field2"",""field3"""
    # The outer " wraps the entire row. Fields are separated by ,""
    # and closed with "". Within a field, literal " is escaped as "".
    # We parse character-by-character to correctly handle "" in values.
    line = line.strip()
    if not line:
        return []

    if not (line.startswith('"') and line.endswith('"')):
        return [line]

    # Remove outer quotes
    inner = line[1:-1]

    fields = []
    field = []
    i = 0
    in_quoted = False

    while i < len(inner):
        if not in_quoted:
            # Looking for start of field or comma separator
            if inner[i:i + 2] == '""':
                # Start of a quoted field
                in_quoted = True
                i += 2
            elif inner[i] == ",":
                # End of unquoted field
                fields.append("".join(field))
                field = []
                i += 1
            else:
                field.append(inner[i])
                i += 1
        # Inside a quoted field
        elif inner[i:i + 2] == '""':
            # Either escaped quote or end of field
            # Check if this is end of field: "" followed by , or end of string
            if i + 2 >= len(inner) or inner[i + 2] == ",":
                # End of quoted field
                in_quoted = False
                i += 2
            else:
                # Escaped quote within field
                field.append('"')
                i += 2
        else:
            field.append(inner[i])
            i += 1

    # Append the last field
    fields.append("".join(field))

    return fields


def _parse_standard_csv_row(line):
    line = line.strip()
    if not line:
        return []

    reader = csv.reader(io.StringIO(line))
    for row in reader:
        return list(row)
    return []


def _parse_nonstandard_content(lines, skip_metadata_lines):
    header_line = lines[skip_metadata_lines]
    fieldnames = _parse_qualys_nonstandard_row(header_line)

    if not fieldnames:
        return []

    # Parse data rows handling multi-line records.
    # A record starts with " and may span multiple lines.
    # We detect record boundaries by trailing quote patterns on each line
    # rather than re-parsing the accumulated row every iteration.
    rows = []
    current_row = ""
    in_record = False

    for line in lines[skip_metadata_lines + 1:]:
        if not line.strip():
            if in_record:
                current_row += "\n"
            continue

        if not in_record:
            if line.startswith('"'):
                current_row = line
                in_record = True
            else:
                continue
        else:
            current_row += "\n" + line

        if in_record and _is_record_end_line(line):
            rows.append(current_row)
            current_row = ""
            in_record = False

    if in_record and current_row:
        rows.append(current_row)

    result = []
    for row in rows:
        values = _parse_qualys_nonstandard_row(row)
        if values:
            row_dict = {}
            for i, fieldname in enumerate(fieldnames):
                if i < len(values):
                    row_dict[fieldname] = clean_field_value(values[i])
                else:
                    row_dict[fieldname] = ""
            result.append(row_dict)

    return result


def _parse_standard_content(lines, skip_metadata_lines):
    csv_content = "\n".join(lines[skip_metadata_lines:])
    reader = csv.DictReader(io.StringIO(csv_content))
    return list(reader)


def parse_qualys_csv_content(content, skip_metadata_lines=None):
    lines = content.split("\n")

    if skip_metadata_lines is None:
        skip_metadata_lines = _detect_metadata_lines(lines)

    if len(lines) <= skip_metadata_lines:
        return []

    header_line = lines[skip_metadata_lines]

    if _is_qualys_nonstandard_format(header_line):
        return _parse_nonstandard_content(lines, skip_metadata_lines)
    return _parse_standard_content(lines, skip_metadata_lines)
