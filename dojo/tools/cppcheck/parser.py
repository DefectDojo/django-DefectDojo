__author__ = "DFNazipov"

from defusedxml.ElementTree import parse
from dojo.models import Finding


class CppcheckParser:

    def get_scan_types(self):
        return ["Cppcheck"]

    def get_label_for_scan_types(self, scan_type):
        return "Cppcheck"

    def get_description_for_scan_types(self, scan_type):
        return "XML file from SAST Scanner Cppcheck."

    def get_findings(self, filename, test):
        tree = parse(filename)
        root = tree.getroot()
        findings = []
        if "results" not in root.tag:
            msg = "This doesn't seem to be a valid Cppcheck XML file."
            raise ValueError(msg)
        
        errors_element = root.find("errors")
        if errors_element is None:
            return findings

        for error in errors_element.findall('error'):
            error_id = error.get('id')
            msg = error.get('msg')
            title = f"{error_id}: {msg}" if error_id else msg[:100]
            severity = self.convert_severity(error.get('severity', ''))
            cwe = error.get('cwe')
            

            description = f"**Message:** {msg}\n"
            
            if cwe:
                description += f"**CWE:** {cwe}\n"

            locations = []
            for location in error.findall('location'):
                file_loc = location.get('file', '')
                line_loc = location.get('line', '')
                info_loc = location.get('info', '')
                column_loc = location.get('column', '')
                loc_str = f"**File:** {file_loc}"
                if line_loc:
                    loc_str += f", **Line:** {line_loc}"
                if column_loc:
                    loc_str += f", **Column:** {column_loc}"
                if info_loc:
                    loc_str += f" ({info_loc})"
                locations.append(loc_str)

            if locations:
                description += "**Locations:**\n" + "\n".join(locations)

            first_location = error.find('location')
            file_path = None
            line = None
            if first_location is not None:
                file_path = first_location.get('file') 
                line_str = first_location.get('line')
                if line_str and line_str.isdigit():
                    line = int(line_str)
            

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=error_id,
                file_path=file_path,
                line=line,
            )

            if cwe and cwe.isdigit():
                finding.cwe = int(cwe)

            findings.append(finding)

        return findings

    def convert_severity(self, severity):
        mapping = {
            "none": 'Info',
            "style": 'Low',
            "performance": 'Info',
            "portability": 'Low',
            "debug": 'Info',
            'information': 'Info',
            'warning': 'High',
            'error': 'Critical'
        }
        return mapping.get(severity.lower(), 'Info')