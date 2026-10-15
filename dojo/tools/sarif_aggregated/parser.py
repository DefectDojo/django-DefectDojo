from dojo.tools.sarif.parser import SarifParser


class SarifAggregatedParser(SarifParser):

    """
    SARIF, imported as one finding per result rather than one per location.

    A SARIF result can list several ``locations`` (a hard-coded secret in six files, a race
    condition reported at two lines). The ``SARIF`` scan type turns each location into its own
    finding; this scan type keeps the result whole. The finding's own ``file_path`` and ``line``
    come from the first location, and every location is attached as a code Location when the
    Locations feature is enabled, or listed in the description when it is not. The result's
    fingerprint is then unique inside the report and is kept as ``unique_id_from_tool``.
    """

    def get_scan_types(self):
        return ["SARIF Aggregated"]

    def get_label_for_scan_types(self, scan_type):
        return "SARIF Aggregated"

    def get_description_for_scan_types(self, scan_type):
        return (
            "SARIF report file, imported as one finding per result that lists every location "
            "of the result, instead of one finding per location."
        )

    def group_result_locations(self, files):
        return [files]
