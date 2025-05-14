import json
import logging

from dojo.tools.wizcli_common_parsers.parsers import WizcliParsers

logger = logging.getLogger(__name__)


class WizcliDirParser:

    """Wiz CLI Directory/IaC Scan results in JSON file format."""

    def get_scan_types(self):
        return ["Wizcli Dir Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wiz CLI Scan (Directory)"

    def get_description_for_scan_types(self, scan_type):
        return "Parses Wiz CLI Directory/IaC scan results in JSON format, creating granular findings for vulnerabilities and secrets."

    def get_findings(self, file, test):
        """Processes the JSON report and returns a list of DefectDojo Finding objects."""
        try:
            scan_data = file.read()
            if isinstance(scan_data, bytes):
                # Try decoding common encodings
                try:
                    scan_data = scan_data.decode("utf-8-sig")  # Handles BOM
                except UnicodeDecodeError:
                    scan_data = scan_data.decode("utf-8")  # Fallback
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
            logger.warning("No 'result' key found in the Wiz report. Unable to parse findings.")
            return findings

        # Parse Libraries (Vulnerabilities)
        libraries = results_data.get("libraries")
        if libraries:
            logger.debug(f"Parsing {len(libraries)} library entries.")
            findings.extend(WizcliParsers.parse_libraries(libraries, test))
        else:
            logger.debug("No 'libraries' data found in results.")

        # Parse Secrets
        secrets = results_data.get("secrets")
        if secrets:
            logger.debug(f"Parsing {len(secrets)} secret entries.")
            findings.extend(WizcliParsers.parse_secrets(secrets, test))
        else:
            logger.debug("No 'secrets' data found in results.")

        logger.info(f"WizcliDirParser processed {len(findings)} findings.")
        return findings
