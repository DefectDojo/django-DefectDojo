import json
import re
from datetime import datetime
from dojo.models import Finding


class VeracodePipelineParser(object):
    """This parser is written for Veracode Pipeline JSON output.

    For details about the Veracode Pipeline Scan
    see https://help.veracode.com/r/t_run_pipeline_scan
    """

    vc_severity_mapping = {
        1: 'Info',
        2: 'Low',
        3: 'Medium',
        4: 'High',
        5: 'Critical'
    }

    def get_scan_types(self):
        return ["Veracode Pipeline Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Veracode Pipeline Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Veracode Pipeline Scan Results"

    def get_findings(self, filename, test):
        if filename is None:
            return

        tree = json.load(filename)

        if 'findings' not in tree:
            return

        scan_id = tree['scan_id'] if 'scan_id' in tree else ''
        dupes = dict()

        for flaw in tree['findings']:
            dupe_key = flaw['issue_id']

            if dupe_key not in dupes:
                dupes[dupe_key] = self.__json_flaw_to_finding(scan_id, flaw, test)

        return list(dupes.values())

    @classmethod
    def __json_flaw_to_unique_id(cls, scan_id, flaw):
        issue_id = str(flaw['issue_id']) if 'issue_id' in flaw else ''
        return scan_id + '|' + issue_id

    @classmethod
    def __json_flaw_to_severity(cls, flaw):
        return cls.vc_severity_mapping.get(int(flaw['severity']), 'Info')

    @classmethod
    def __json_flaw_to_finding(cls, scan_id, flaw, test):
        finding = Finding()
        finding.test = test
        finding.mitigation = ''
        finding.impact= ''
        finding.static_finding = True
        finding.dynamic_finding = False
        finding.unique_id_from_tool = cls.__json_flaw_to_unique_id(scan_id, flaw)
        finding.severity = cls.__json_flaw_to_severity(flaw)
        finding.cwe = int(flaw['cwe_id'])
        finding.title = flaw['issue_type']
        finding.description = flaw['display_text']
        finding.date = test.target_start
        finding.is_mitigated = False
        finding.mitigated = None

        _source_file_path = None
        _source_line_number = None
        _source_file_function = None

        if 'files' in flaw:
            if 'source_file' in flaw['files']:
                _source_file_path = flaw['files']['source_file']['file']
                _source_line_number = flaw['files']['source_file']['line']
                _source_file_function = flaw['files']['source_file']['function_prototype']
        finding.file_path = _source_file_path
        finding.sourcefile = _source_file_path
        finding.sast_source_file_path = _source_file_path
        finding.source_line = _source_line_number
        finding.sast_source_line = _source_line_number
        _sast_source_obj = _source_file_function
        finding.sast_source_object = _sast_source_obj if _sast_source_obj else None

        return finding
