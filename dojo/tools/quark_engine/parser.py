import json

from dojo.models import Finding


class QuarkEngineParser:

    """
    Parser for Quark-Engine JSON reports.

    Quark-Engine scores Android behaviours ("crimes") rather than reporting known
    vulnerabilities. Each crime carries a confidence expressing how many of Quark's five
    detection stages matched, which is the closest thing the report has to a severity.
    """

    def get_scan_types(self):
        return ["Quark-Engine Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Quark-Engine reports in JSON format, generated with 'quark -a sample.apk -s -o report.json'."

    def get_findings(self, file, test):
        data = json.load(file)
        apk_filename = data.get("apk_filename")
        md5 = data.get("md5")
        findings = []
        for crime in data.get("crimes", []):
            confidence = self._confidence(crime.get("confidence"))

            description = [f"**Behaviour:** {crime.get('crime')}"]
            if crime.get("rule"):
                description.append(f"**Rule:** {crime['rule']}")
            if crime.get("confidence") is not None:
                description.append(f"**Confidence:** {crime['confidence']}")
            if crime.get("score") is not None:
                description.append(f"**Score:** {crime['score']} (weight {crime.get('weight')})")
            if crime.get("label"):
                description.append(f"**Labels:** {', '.join(crime['label'])}")
            if crime.get("permissions"):
                description.append("**Permissions:**\n" + "\n".join(f"- {p}" for p in crime["permissions"]))
            native_api = [
                f"- {api.get('class')}{api.get('method')}"
                for api in crime.get("native_api", [])
            ]
            if native_api:
                description.append("**Native API calls:**\n" + "\n".join(native_api))
            if apk_filename:
                description.append(f"**APK:** {apk_filename}")
            if md5:
                description.append(f"**MD5:** {md5}")

            findings.append(Finding(
                title=crime.get("crime"),
                test=test,
                description="\n".join(description),
                severity=self._severity(confidence),
                component_name=apk_filename,
                vuln_id_from_tool=crime.get("rule"),
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings

    def _confidence(self, raw):
        """Quark reports confidence as a percentage string, e.g. '100%'."""
        if raw is None:
            return 0
        try:
            return int(str(raw).strip().rstrip("%"))
        except ValueError:
            return 0

    def _severity(self, confidence):
        # Quark's five detection stages map onto 20% increments of confidence. 100% means
        # every required API was used and a data flow between them was confirmed; 80% means
        # the APIs were all present but no data flow was found.
        if confidence >= 100:
            return "High"
        if confidence >= 80:
            return "Medium"
        if confidence >= 40:
            return "Low"
        return "Info"
