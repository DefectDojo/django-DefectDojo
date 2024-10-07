from typing import Any, Union

from dojo.models import Endpoint
from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngineParser


class NmapScanningEngineParser(BaseEngineParser):

    """
    Parser for data from the Nmap scanning engine.

    Nmap engine results include a list of ports in a 'port_table' data entry that we use to generate several endpoints
    under the same Finding.
    """

    SCANNING_ENGINE = "NMapScanner"

    def is_port_table_entry(self, entry) -> bool:
        return len(entry) > 0 and self.parse_port(entry[0])

    def get_ports(self, item) -> Union[list[int], list[None]]:
        meta = item.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        if ports := meta.get("port_table", []):
            return [port for port_entry in ports if (port := self.is_port_table_entry(port_entry))]
        # Want at least one endpoint reported since we have a host -- no ports provided. This shouldn't happen, but...
        return [None]

    def parse_endpoints(self, item: dict[str, Any]) -> [Endpoint]:
        host = self.get_host(item)
        ports = self.get_ports(item)
        return [self.construct_endpoint(host, port) for port in ports]
