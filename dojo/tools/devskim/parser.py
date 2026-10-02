from dojo.tools.sarif.parser import SarifParser


class DevskimParser(SarifParser):

    """
    DevSkim is Microsoft's CLI static analyser for dangerous API use and weak cryptography.

    SARIF is DevSkim's native and default output format, so this reuses DefectDojo's SARIF parsing
    and only declares its own scan type.
    """

    def get_scan_types(self):
        return ["DevSkim Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "DevSkim Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the SARIF report produced by "
            "`devskim analyze -I <path> -O report.sarif -f sarif`."
        )
