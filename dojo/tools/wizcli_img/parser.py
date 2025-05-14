import json
import logging

from dojo.tools.wizcli_common_parsers.parsers import WizcliParsers  # Adjust import path

logger = logging.getLogger(__name__)


class WizcliImgParser:

    """Wiz CLI Container Image Scan results in JSON file format."""

    def get_scan_types(self):
        # Use a distinct name for image scans
        return ["Wizcli Img Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wiz CLI Scan (Image)"

    def get_description_for_scan_types(self, scan_type):
        return "Parses Wiz CLI Container Image scan results in JSON format."

    def get_findings(self, file, test):
        try:
            scan_data = file.read()
            if isinstance(scan_data, bytes):
                try:
                    scan_data = scan_data.decode("utf-8-sig")
                except UnicodeDecodeError:
                    scan_data = scan_data.decode("utf-8")
            data = json.loads(scan_data)
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON format: {e}"
            logger.error(msg)
            raise ValueError(msg) from e
        except Exception as e:
            msg = f"Error processing report file: {e}"
            logger.error(msg)
            raise ValueError(msg) from e

        findings = []
        results_data = data.get("result", {})

        if not results_data:
            logger.warning("No 'result' key found in the Wiz report.")
            return findings

        # Parse OS Packages - Key difference for image scans
        os_packages = results_data.get("osPackages")
        if os_packages:
            logger.debug(f"Parsing {len(os_packages)} OS package entries.")
            findings.extend(WizcliParsers.parse_os_packages(os_packages, test))
        else:
            logger.debug("No 'osPackages' data found in results.")

        # Parse Libraries (if present in image scans)
        libraries = results_data.get("libraries")
        if libraries:
            logger.debug(f"Parsing {len(libraries)} library entries.")
            findings.extend(WizcliParsers.parse_libraries(libraries, test))
        else:
            logger.debug("No 'libraries' data found in results.")

        # Parse Secrets (if present in image scans)
        secrets = results_data.get("secrets")
        if secrets:
            logger.debug(f"Parsing {len(secrets)} secret entries.")
            findings.extend(WizcliParsers.parse_secrets(secrets, test))
        else:
            logger.debug("No 'secrets' data found in results.")

        logger.info(f"WizcliImgParser processed {len(findings)} findings.")
        return findings
