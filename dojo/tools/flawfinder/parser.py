from dojo.tools.sarif.parser import SarifParser


class FlawfinderParser(SarifParser):

    """
    Flawfinder is a CLI static analyser that scans C and C++ source for calls to functions with a
    history of misuse - strcpy, gets, printf-family format strings and similar - and reports each hit
    with a risk level and CWE mapping.

    Flawfinder emits SARIF natively (`--sarif`), so this parser reuses the SARIF parsing logic and
    redefines only the scan type. A dedicated scan type gives Flawfinder its own entry in the tool list
    rather than having its findings land in the generic SARIF bucket alongside every other producer's.

    https://dwheeler.com/flawfinder/
    """

    def get_scan_types(self):
        return ["Flawfinder Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Flawfinder Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the SARIF report produced by `flawfinder --sarif <path>`."
