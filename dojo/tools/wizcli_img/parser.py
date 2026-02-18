import json
import os

from django.conf import settings

from dojo.tools.protocol import LocationData
from dojo.tools.wizcli_common_parsers.parsers import WIZCLI_MANIFEST_TO_PURL, WizcliParsers


class WizcliImgParser:

    """Wizcli Image Scan results in JSON file format."""

    def get_scan_types(self):
        return ["Wizcli Img Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli Img Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli Img report file can be imported in JSON format."

    def get_findings(self, filename, test):
        self.UNSAVED_LOCATIONS = []
        scan_data = filename.read()
        try:
            data = json.loads(scan_data.decode("utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        results = data.get("result", {})

        if settings.V3_FEATURE_LOCATIONS:
            for lib in results.get("libraries") or []:
                lib_name = lib.get("name")
                lib_version = lib.get("version")
                lib_path = lib.get("path", "")
                if lib_name and lib_path:
                    manifest = os.path.basename(lib_path)
                    purl_type = WIZCLI_MANIFEST_TO_PURL.get(manifest)
                    if purl_type:
                        self.UNSAVED_LOCATIONS.append(
                            LocationData(type="dependency", data={"purl_type": purl_type, "name": lib_name, "version": lib_version}),
                        )

        osPackages = results.get("osPackages", None)
        if osPackages:
            findings.extend(WizcliParsers.parse_os_packages(osPackages, test))

        libraries = results.get("libraries", None)
        if libraries:
            findings.extend(WizcliParsers.parse_libraries(libraries, test))

        secrets = results.get("secrets", None)
        if secrets:
            findings.extend(WizcliParsers.parse_secrets(secrets, test))

        return findings
