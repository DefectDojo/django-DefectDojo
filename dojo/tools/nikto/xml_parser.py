import hashlib
import logging
import re

from defusedxml import ElementTree
from django.core.exceptions import ValidationError

from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class NiktoXMLParser:
    def process_xml(self, file, test):
        dupes = {}
        tree = ElementTree.parse(file)
        root = tree.getroot()
        scan = root.find("scandetails")
        if scan is not None:
            self.process_scandetail(scan, test, dupes)
        else:
            # New versions of Nikto have a new file type (nxvmlversion="1.2") which adds an additional niktoscan tag
            # This find statement below is to support new file format while not
            # breaking older Nikto scan files versions.
            for scan in root.findall("./niktoscan/scandetails"):
                self.process_scandetail(scan, test, dupes)
        return list(dupes.values())

    def process_scandetail(self, scan, test, dupes):
        for item in scan.findall("item"):
            # Title
            titleText = None
            description = item.findtext("description")
            # Cut the title down to the first sentence
            sentences = re.split(
                r"(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s", description,
            )
            titleText = sentences[0][:900] if len(sentences) > 0 else description[:900]
            # Description
            description = "\n".join(
                [
                    f"**Host:** `{item.findtext('iplink')}`",
                    f"**Description:** `{item.findtext('description')}`",
                    f"**HTTP Method:** `{item.attrib.get('method')}`",
                ],
            )
            # Manage severity the same way with JSON
            severity = "Info"  # Nikto doesn't assign severity, default to Info
            if item.get("osvdbid") is not None and item.get("osvdbid") != "0":
                severity = "Medium"
            finding = Finding(
                title=titleText,
                test=test,
                description=description,
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=item.attrib.get("id"),
                nb_occurences=1,
            )
            # endpoint
            try:
                ip = item.findtext("iplink")
                endpoint = Endpoint.from_uri(ip)
                finding.unsaved_endpoints = [endpoint]
            except ValidationError:
                logger.debug("Invalid iplink in the report")
            dupe_key = hashlib.sha256(description.encode("utf-8")).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.description += "\n-----\n" + finding.description
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = finding
