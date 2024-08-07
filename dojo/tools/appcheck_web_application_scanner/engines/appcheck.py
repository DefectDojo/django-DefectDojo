import re
from typing import Union

from dojo.models import Finding
from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngine


class NewAppCheckScannerMultiple(BaseEngine):
    SCANNING_ENGINE = "NewAppCheckScannerMultiple"

    REQUEST_RESPONSE_PATTERN = re.compile(r"--->\s*(.*)<---\s*(.*)")

    def extract_request_response(self, finding: Finding, value: dict[str, [str]]) -> None:
        if rr_details := self.REQUEST_RESPONSE_PATTERN.findall(value.get("Messages", "")):
            # Remove 'Messages' entry since we've parsed it as a request/response pair
            value.pop("Messages")
            finding.unsaved_request, finding.unsaved_response = rr_details[0]

    def parse_details(self, finding: Finding, value: dict[str, Union[str, dict[str, [str]]]]) -> None:
        self.extract_request_response(finding, value)
        return super().parse_details(finding, value)
