import re
from typing import Union

from dojo.models import Finding
from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngineParser


class AppCheckScanningEngineParser(BaseEngineParser):
    """
    Parser for data from the (proprietary?) AppCheck scanning engine.

    Results from this engine may include request/response data nested in the 'details' entry. This extracts those values
    and stores them in the Finding unsaved_request/unsaved_response attributes.
    """
    SCANNING_ENGINE = "NewAppCheckScannerMultiple"

    REQUEST_RESPONSE_PATTERN = re.compile(r"^--->\n\n(.+)\n\n<---\n\n(.+)$", re.DOTALL)

    def extract_request_response(self, finding: Finding, value: dict[str, [str]]) -> None:
        if rr_details := self.REQUEST_RESPONSE_PATTERN.findall(value.get("Messages") or ""):
            # Remove the 'Messages' entry since we've parsed it as a request/response pair; don't need to add it to the
            # Finding description
            value.pop("Messages")
            finding.unsaved_request, finding.unsaved_response = (d.strip() for d in rr_details[0])

    def parse_details(self, finding: Finding, value: dict[str, Union[str, dict[str, [str]]]]) -> None:
        self.extract_request_response(finding, value)
        # super's version adds everything else to the description field
        return super().parse_details(finding, value)
