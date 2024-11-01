import re

from dojo.models import Finding
from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngineParser


class AppCheckScanningEngineParser(BaseEngineParser):

    """
    Parser for data from the (proprietary?) AppCheck scanning engine.

    Results from this engine may include request/response data nested in the 'details' entry. This extracts those values
    and stores them in the Finding unsaved_request/unsaved_response attributes.
    """

    SCANNING_ENGINE = "NewAppCheckScannerMultiple"

    HTTP_1_REQUEST_RESPONSE_PATTERN = re.compile(r"^--->\n\n(.+)\n\n<---\n\n(.+)$", re.DOTALL)
    HTTP_2_REQUEST_RESPONSE_PATTERN = re.compile(
        r"^HTTP/2 Request Headers:\n\n(.+)\r\nHTTP/2 Response Headers:\n\n(.+)$", re.DOTALL)

    def extract_request_response(self, finding: Finding, value: dict[str, [str]]) -> None:
        if messages := value.get("Messages"):
            # If we match either HTTP/1 or HTTP/2 request/response entries, remove the 'Messages' entry since we'll have
            # parsed it as a request/response pair; don't need to add it to the Finding description
            if rr_details := self.HTTP_1_REQUEST_RESPONSE_PATTERN.findall(messages)\
                             or self.HTTP_2_REQUEST_RESPONSE_PATTERN.findall(messages):
                value.pop("Messages")
                finding.unsaved_request, finding.unsaved_response = (d.strip() for d in rr_details[0])

    def parse_details(self, finding: Finding, value: dict[str, str | dict[str, list[str]]]) -> None:
        self.extract_request_response(finding, value)
        # super's version adds everything else to the description field
        return super().parse_details(finding, value)
