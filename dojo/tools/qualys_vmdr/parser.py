from dojo.tools.qualys_vmdr.cve_parser import QualysVMDRCVEParser
from dojo.tools.qualys_vmdr.helpers import _detect_metadata_lines
from dojo.tools.qualys_vmdr.qid_parser import QualysVMDRQIDParser


class QualysVMDRParser:

    def get_scan_types(self):
        return ["Qualys VMDR"]

    def get_label_for_scan_types(self, scan_type):
        return "Qualys VMDR"

    def get_description_for_scan_types(self, scan_type):
        return "Import Qualys VMDR vulnerability exports (CSV format, QID or CVE)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        # Normalize line endings (Qualys exports use \r\n)
        content = content.replace("\r\n", "\n").replace("\r", "\n")

        lines = content.split("\n")
        skip = _detect_metadata_lines(lines)

        if len(lines) <= skip:
            return []

        header_line = lines[skip]

        # Auto-detect format: CVE as first column means CVE format, otherwise QID
        if header_line.startswith(('"CVE"', '"CVE,', "CVE,")):
            return QualysVMDRCVEParser().parse(content)
        return QualysVMDRQIDParser().parse(content)
