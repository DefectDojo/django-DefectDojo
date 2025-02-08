import json
import logging
import zipfile

from lxml import etree

from dojo.tools.sonarqube.sonarqube_restapi_json import SonarQubeRESTAPIJSON
from dojo.tools.sonarqube.sonarqube_restapi_zip import SonarQubeRESTAPIZIP
from dojo.tools.sonarqube.soprasteria_html import SonarQubeSoprasteriaHTML
from dojo.tools.sonarqube.soprasteria_json import SonarQubeSoprasteriaJSON

logger = logging.getLogger(__name__)


class SonarQubeParser:
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_scan_types(self):
        return ["SonarQube Scan", "SonarQube Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        if scan_type == "SonarQube Scan":
            return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format or JSON format. You can get the JSON output directly if you use the SonarQube API or generate with https://github.com/soprasteria/sonar-report version >= 1.1.0, recommend version >= 3.1.2"
        return "Import all findings from sonarqube html report or JSON format. SonarQube output file can be imported in HTML format or JSON format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0, recommend version >= 3.1.2"

    def get_findings(self, file, test):
        if file.name.endswith(".json"):
            json_content = json.load(file)
            if json_content.get("date") and json_content.get("projectName") and json_content.get("hotspotKeys"):
                return SonarQubeSoprasteriaJSON().get_json_items(json_content, test, self.mode)
            if json_content.get("paging") and json_content.get("components"):
                return SonarQubeRESTAPIJSON().get_json_items(json_content, test, self.mode)
            return []
        if file.name.endswith(".zip"):
            if str(file.__class__) == "<class '_io.TextIOWrapper'>":
                input_zip = zipfile.ZipFile(file.name, "r")
            else:
                input_zip = zipfile.ZipFile(file, "r")
            zipdata = {name: input_zip.read(name) for name in input_zip.namelist()}
            return SonarQubeRESTAPIZIP().get_items(zipdata, test, self.mode)
        parser = etree.HTMLParser()
        tree = etree.parse(file, parser)
        if self.mode not in [None, "detailed"]:
            raise ValueError(
                "Internal error: Invalid mode "
                + self.mode
                + ". Expected: one of None, 'detailed'",
            )
        return SonarQubeSoprasteriaHTML().get_items(tree, test, self.mode)
