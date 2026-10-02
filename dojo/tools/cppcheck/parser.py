from dojo.tools.sarif.parser import SarifParser


class CppcheckParser(SarifParser):

    """
    Cppcheck is a CLI static analyser for C and C++ that focuses on defects a compiler will not catch -
    memory leaks, out-of-bounds array access, uninitialised reads and null dereferences - and aims for a
    low false-positive rate rather than exhaustive coverage.

    Cppcheck can emit SARIF (`--output-format=sarif`), so this parser reuses the SARIF parsing logic and
    redefines only the scan type. A dedicated scan type gives Cppcheck its own entry in the tool list, so
    its findings stay separable from the other C/C++ analysers DefectDojo supports.

    Note that Cppcheck writes its report to STDERR, not stdout, which is why the documented command
    redirects with `2>`.

    https://cppcheck.sourceforge.io/
    """

    def get_scan_types(self):
        return ["Cppcheck Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Cppcheck Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the SARIF report produced by `cppcheck --output-format=sarif <path> 2> report.sarif`. "
            "Cppcheck writes its report to stderr."
        )
