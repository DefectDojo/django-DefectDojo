# dojo/tools/rapidfire/parser.py
import csv
import io
import logging
import re
import sys
from urllib.parse import urlparse

from dateutil import parser as date_parser
from django.utils import timezone

from dojo.models import Endpoint, Finding


logger = logging.getLogger(__name__)


class RapidFireParser:

    """RapidFire vulnerability scanner CSV report parser"""

    def get_scan_types(self):
        return ["Rapidfire Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Rapidfire Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Rapidfire vulnerability scan results in CSV format."

    def _convert_severity(self, val):
        """Convert severity value to standard form"""
        val = str(val).capitalize()
        if val in Finding.SEVERITIES:
            return val
        return "Info"

    def _parse_cves(self, val):
        """Parse CVE string into list"""
        if not val:
            return []
        return [cve.strip() for cve in val.split(",") if cve.strip().startswith("CVE-")]

    def _parse_date(self, val):
        """Parse date string to datetime"""
        try:
            return date_parser.parse(val)
        except (TypeError, ValueError):
            return timezone.now()

    def _extract_port(self, ports_str):
        """
        Extract port number from ports string
        Expected format examples: '8080/tcp', '443/tcp (https)'
        Returns None if format is invalid or no port number found
        """
        if not ports_str:
            return None

        # Regular expression to match port number at start of string
        port_match = re.match(r"^\d+(?=/|$)", str(ports_str))
        if port_match:
            port = port_match.group(0)
            try:
                # Validate port number is in valid range
                port_num = int(port)
                if 1 <= port_num <= 65535:
                    return port
            except ValueError:
                pass
        return None

    def _format_references(self, refs_str):
        """
        Format references string into a readable list of links.
        Expected format is comma-separated URLs.
        Returns a markdown formatted string with one reference per line.
        """
        if not refs_str:
            return ""

        # Split on commas and clean up each URL
        refs = refs_str.split(",")
        formatted_refs = []

        for ref in refs:
            # Clean the URL and remove any trailing text
            url = ref.strip()
            if not url:
                continue

            # Remove any text after the URL
            url_match = re.match(r"(https?://[^\s]+)", url)
            if not url_match:
                continue

            clean_url = url_match.group(1)
            # Remove any trailing punctuation
            clean_url = re.sub(r"[.,;]+$", "", clean_url)

            # Get domain and path parts
            try:
                parsed_url = urlparse(clean_url)
                domain = parsed_url.netloc
                path = parsed_url.path

                # Create descriptive name based on URL pattern
                name = None

                if "apache.org" in domain:
                    if "security" in path:
                        # Handle Tomcat security pages
                        version_match = re.search(r"Tomcat[_-](\d+\.\d+\.\d+)", clean_url)
                        if version_match:
                            name = f"Apache Tomcat {version_match.group(1)} Security Advisory"
                        else:
                            name = "Apache Tomcat Security Advisory"
                    elif "thread" in path:
                        name = "Apache Discussion Thread"

                elif "cisa.gov" in domain:
                    if "known-exploited-vulnerabilities" in path:
                        name = "CISA Known Exploited Vulnerabilities"
                    else:
                        name = "CISA Security Advisory"

                elif "cloudflare.com" in domain:
                    if "rapid-reset" in path:
                        name = "Cloudflare HTTP/2 Rapid Reset Analysis"
                    else:
                        name = "Cloudflare Security Advisory"

                elif "cloud.google.com" in domain:
                    if "rapid-reset" in path:
                        name = "Google Cloud HTTP/2 Reset Analysis"
                    else:
                        name = "Google Cloud Security Advisory"

                elif "openwall.com" in domain:
                    name = "Openwall Security Advisory"

                elif "aws.amazon.com" in domain:
                    name = "AWS Security Advisory" if "security" in path else "AWS Documentation"

                # If no specific pattern matched, create a generic title
                if not name:
                    # Use domain as fallback
                    domain_parts = domain.split(".")
                    if len(domain_parts) > 1:
                        name = f"{domain_parts[-2].title()} Security Advisory"
                    else:
                        name = "Security Advisory"

                formatted_refs.append(f"* [{name}]({clean_url})")

            except Exception as e:
                logger.warning(f"Error formatting reference URL {clean_url}: {e!s}")
                continue

        # Return unique references, sorted alphabetically
        unique_refs = sorted(set(formatted_refs))
        return "\n".join(unique_refs)

    def _format_impact(self, vuln_insight, cves):
        """
        Format the impact section combining vulnerability insight and CVE details
        Returns a formatted string with proper markdown formatting
        """
        parts = []

        # Format the vulnerability insight if present
        if vuln_insight:
            # Split on existing bullet points if present
            if vuln_insight.startswith("The following flaws exist:"):
                # Format as a bulleted list
                flaws = vuln_insight.replace("The following flaws exist:", "").strip()
                # Split on '-' but preserve any other dashes in the text
                flaw_list = [f.strip().lstrip("- ") for f in flaws.split("   - ") if f.strip()]
                if flaw_list:
                    parts.extend(["### Identified Flaws", "\n".join(f"* {flaw}" for flaw in flaw_list)])
            else:
                parts.extend(["### Description", vuln_insight])

        # Add CVE information if present
        if cves:
            spacer = [""] if parts else []
            cve_content = ["### Associated CVEs",
                          "\n".join(f"* **{cve}** - [NVD Link](https://nvd.nist.gov/vuln/detail/{cve})" for cve in cves)]
            parts.extend(spacer + cve_content)

        # Join all parts with double newlines
        return "\n\n".join(filter(None, parts))

    def get_findings(self, filename, test):
        if filename is None:
            return []

        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        csv.field_size_limit(int(sys.maxsize // 10))

        try:
            reader = csv.DictReader(io.StringIO(content))
            dupes = {}

            for row in reader:
                # Skip empty rows
                if not row or not any(row.values()):
                    continue

                # Extract CVEs
                cves = self._parse_cves(row.get("CVE", ""))

                # Create finding title
                title = row.get("Issue", "").strip()
                if not title:
                    logger.warning("Finding missing title")
                    continue

                # Build description
                description = []
                if row.get("Summary"):
                    description.append(f"**Summary**: {row['Summary']}")
                if row.get("Vulnerability Detection Result"):
                    description.append(f"**Vulnerability Detection Result**: {row['Vulnerability Detection Result']}")
                if row.get("Vulnerability Detection Method"):
                    description.append(f"**Vulnerability Detection Method**: {row['Vulnerability Detection Method']}")
                if row.get("Known Exploited Vulnerability"):
                    description.append(f"**Known Exploited Vulnerability**: {row['Known Exploited Vulnerability']}")
                if row.get("MAC Address"):
                    description.append(f"**MAC Address**: {row['MAC Address']}")
                
                ransomware_warning = "⚠️ **Warning**: This vulnerability is known to be used in ransomware campaigns"
                if row.get("Known To Be Used In Ransomware Campaigns", "").lower() == "true":
                    description.append(ransomware_warning)

                # Format impact combining vulnerability insight and CVEs
                impact = self._format_impact(row.get("Vulnerability Insight", ""), cves)

                # Create the finding
                find = Finding(
                    title=title,
                    description="\n\n".join(description),
                    severity=self._convert_severity(row.get("Severity", "Info")),
                    references=self._format_references(row.get("References", "")),
                    mitigation=row.get("Solution", ""),
                    impact=impact,
                    date=self._parse_date(row.get("Last Detected", "")),
                    vuln_id_from_tool=row.get("OID", ""),
                    dynamic_finding=True,
                    static_finding=False,
                    test=test,
                )

                # Create endpoint
                hostname = row.get("Hostname", "").strip()
                ip_address = row.get("IP Address", "").strip()
                port = self._extract_port(row.get("Ports", ""))

                if hostname or ip_address:
                    endpoint = Endpoint(
                        host=hostname or ip_address,
                        port=port,
                    )
                    find.unsaved_endpoints = [endpoint]

                # Add CVEs
                if cves:
                    find.unsaved_vulnerability_ids = cves

                # Add tags for ransomware if applicable
                if row.get("Known To Be Used In Ransomware Campaigns", "").lower() == "true":
                    find.tags = "ransomware"

                # Create unique key for deduplication
                dupe_key = f"{title}_{ip_address}_{hostname}_{port}"

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                else:
                    dupes[dupe_key] = find

            return list(dupes.values())

        except csv.Error as e:
            logger.error(f"CSV parsing error: {e!s}")
            raise
        except Exception as e:
            logger.error(f"Error parsing findings: {e!s}")
            raise
