from typing import Any, Union

from dojo.models import Endpoint
from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngine


class NmapScanner(BaseEngine):
    SCANNING_ENGINE = "NMapScanner"

    def is_port_table_entry(self, entry) -> bool:
        return len(entry) > 0 and isinstance(entry[0], int) and 0 < entry[0] <= 65535

    def get_ports(self, item) -> Union[list[int], list[None]]:
        if ports := item.get("meta", {}).get("port_table", []):
            return [port_entry[0] for port_entry in ports if self.is_port_table_entry(port_entry)]
        # Want at least one endpoint reported -- no port provided
        return [None]

    def parse_endpoints(self, item: dict[str, Any]) -> [Endpoint]:
        host = self.get_host(item)
        ports = self.get_ports(item)
        return [self.construct_endpoint(host, port) for port in ports]
