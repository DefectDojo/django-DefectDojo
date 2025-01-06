import json
import logging
from typing import Any

from dojo.tools.appcheck_web_application_scanner.engines.appcheck import AppCheckScanningEngineParser
from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngineParser
from dojo.tools.appcheck_web_application_scanner.engines.nmap import NmapScanningEngineParser
from dojo.tools.appcheck_web_application_scanner.engines.openvas import OpenVASScannerEngineParser

LOGGER = logging.getLogger(__name__)


SCANNING_ENGINE_PARSERS: dict[str, BaseEngineParser] = {
    engine.SCANNING_ENGINE: engine() for engine in [
        AppCheckScanningEngineParser, BaseEngineParser, NmapScanningEngineParser, OpenVASScannerEngineParser,
    ]
}


class AppCheckWebApplicationScannerParser:

    """
    AppCheck Web Application Security Scanner.

    AppCheck appears to use multiple 'engines' to perform the actual scans, and then maps the various outputs as best it
    can to its own output format; there are some differences in the interpretation of the data, per-engine. This parser
    relies on engine plugins to actually perform the parsing work. At startup, the .engines package is scanned for any
    classes that implement BaseEngine, and a map of engine name -> instance of engine parser is created. This map
    includes an instance of BaseEngine itself, which attempts to be the most 'generic' engine parser to cover any
    entries that don't explicitly specify an engine or specify one for which no plugin (yet) exists. Each entry in the
    data is then processed: the correct engine parser is determined and called to parse the entry; it returns a tuple of
    (Finding object, duplicate key), the latter entry of which is used to consolidate duplicates from the input data.
    """

    def get_scan_types(self) -> [str]:
        return ["AppCheck Web Application Scanner"]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        return "AppCheck Web Application Scanner"

    def get_description_for_scan_types(self, scan_type: str) -> str:
        return f"Parses JSON scans and aggregates around title, severity, and endpoints, per-engine. Supports the following engines: {'; '.join(SCANNING_ENGINE_PARSERS.keys())}"

    def get_scanning_engine_for_entry(self, item: dict[str, Any]) -> str:
        # From the sample data we have, 'meta' appears to be one of: a dict, an empty list, or nonexistent
        return (item.get("meta") or {}).get("scanning_engine", {}).get("name", BaseEngineParser.SCANNING_ENGINE)

    def get_engine_parser(self, scanning_engine_name: str) -> BaseEngineParser:
        return SCANNING_ENGINE_PARSERS.get(scanning_engine_name, SCANNING_ENGINE_PARSERS[BaseEngineParser.SCANNING_ENGINE])

    def get_findings(self, file, test):
        data = json.load(file)

        findings = {}

        for item in data.get("items", []):
            scanning_engine = self.get_scanning_engine_for_entry(item)
            if parser := self.get_engine_parser(scanning_engine):
                finding, dupe_key = parser.parse_finding(item)
                if dupe_key not in findings:
                    finding.test = test
                    findings[dupe_key] = finding
            else:
                LOGGER.warning(f"Skipping entry; could not find parser for scanning engine named: {scanning_engine}")
        return list(findings.values())
