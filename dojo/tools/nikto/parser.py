
import hashlib
import logging
import re
import hyperlink
import json

from defusedxml import ElementTree as ET

from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class NiktoParser(object):
    """Nikto web server scanner - https://cirt.net/Nikto2

    The current parser support 3 sources:
     - XML output (old)
     - new XML output (with nxvmlversion=\"1.2\" type)
     - JSON output

    See: https://github.com/sullo/nikto
    """

    def get_scan_types(self):
        return ["Nikto Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML output (old and new nxvmlversion=\"1.2\" type) or JSON output"

    def get_findings(self, filename, test):
        if filename.name.lower().endswith('.xml'):
            return self.process_xml(filename, test)
        elif filename.name.lower().endswith('.json'):
            return self.process_json(filename, test)
        else:
            raise ValueError('Unknown File Format')

    def process_json(self, file, test):
        data = json.load(file)

        dupes = dict()
        host = data.get('host')
        port = data.get('port')
        if port is not None:
            port = int(port)
        for vulnerability in data.get('vulnerabilities', []):
            finding = Finding(
                title=vulnerability.get('msg'),
                severity="Info",  # Nikto doesn't assign severity, default to Info
                description="\n".join([
                    f"**id:** `{vulnerability.get('id')}`",
                    f"**msg:** `{vulnerability.get('msg')}`",
                    f"**HTTP Method:** `{vulnerability.get('method')}`",
                    f"**OSVDB:** `{vulnerability.get('OSVDB')}`",
                ]),
                vuln_id_from_tool=vulnerability.get('id'),
                nb_occurences=1,
            )
            # manage if we have an ID from OSVDB
            if "OSVDB" in vulnerability and "0" != vulnerability.get('OSVDB'):
                finding.unique_id_from_tool = "OSVDB-" + vulnerability.get('OSVDB')
                finding.description += "\n*This finding is marked as medium as there is a link to OSVDB*"
                finding.severity = "Medium"
            # build the endpoint
            endpoint = Endpoint(
                host=host,
                port=port,
                path=vulnerability.get('url'),
            )
            finding.unsaved_endpoints = [endpoint]

            # internal de-duplication
            dupe_key = finding.severity + finding.title
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.description += "\n-----\n" + finding.description
                find.unsaved_endpoints.append(endpoint)
                find.unique_id_from_tool = None  # as it is an aggregated finding we erase ids
                find.vuln_id_from_tool = None  # as it is an aggregated finding we erase ids
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def process_xml(self, file, test):
        dupes = dict()

        tree = ET.parse(file)
        root = tree.getroot()
        scan = root.find('scandetails')

        if scan is not None:
            self.process_scandetail(scan, test, dupes)
        else:
            # New versions of Nikto have a new file type (nxvmlversion="1.2") which adds an additional niktoscan tag
            # This find statement below is to support new file format while not breaking older Nikto scan files versions.
            for scan in root.findall('./niktoscan/scandetails'):
                self.process_scandetail(scan, test, dupes)

        return list(dupes.values())

    def process_scandetail(self, scan, test, dupes):
        for item in scan.findall('item'):
            # Title
            titleText = None
            description = item.find("description").text
            # Cut the title down to the first sentence
            sentences = re.split(
                r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', description)
            if len(sentences) > 0:
                titleText = sentences[0][:900]
            else:
                titleText = description[:900]

            # Url
            ip = item.find("iplink").text
            # Remove the port numbers for 80/443
            ip = ip.replace(r":['80']{2}\/?$", "")
            ip = ip.replace(r":['443']{3}\/?$", "")

            # Severity
            severity = "Info"  # Nikto doesn't assign severity, default to Info

            # Description
            description = "\n".join([
                    f"**Host:** `{ip}`",
                    f"**Description:** `{item.find('description').text}`",
                    f"**HTTP Method:** `{item.attrib['method']}`",
            ])

            url = hyperlink.parse(ip)
            endpoint = Endpoint(
                protocol=url.scheme,
                host=url.host,
                port=url.port,
                path="/".join(url.path),
            )

            dupe_key = hashlib.sha256(description.encode("utf-8")).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description = finding.description + "\nHost:" + ip + "\n" + description
                finding.unsaved_endpoints.append(endpoint)
                finding.nb_occurences += 1

            else:
                finding = Finding(title=titleText,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    description=description,
                                    severity=severity,
                                    numerical_severity=Finding.get_numerical_severity(
                                        severity),
                                    dynamic_finding=True,
                                    nb_occurences=1,
                                  )
                finding.unsaved_endpoints = [endpoint]

                dupes[dupe_key] = finding
