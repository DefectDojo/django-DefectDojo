import contextlib
import json
from datetime import datetime

from dojo.models import Finding


class SemgrepProParser:
    def get_scan_types(self):
        return ["Semgrep Pro JSON Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Semgrep Pro findings in JSON format"

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}

        for item in data.get("findings", []):
            # Ensure required fields have default values
            title = item.get("rule_name", "No title")
            file_path = item.get("location", {}).get("file_path", "")
            line = item.get("location", {}).get("line", 0)

            # Map status to active/verified
            status = item.get("status", "new").lower()
            active = status not in {"fixed", "removed"}
            triage_status = item.get("triage_state", "untriaged").lower()
            verified = triage_status != "untriaged"

            finding = Finding(
                test=test,
                title=title,
                severity=self.convert_severity(item.get("severity", "INFO")),
                description=self.get_description(item),
                file_path=file_path,
                line=line,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=item.get("rule_name"),
                nb_occurences=1,
                active=active,
                verified=verified,
            )

            # Add CWE if available
            if "rule" in item and "cwe_names" in item["rule"]:
                try:
                    cwe_name = item["rule"]["cwe_names"][0]  # Take first CWE
                    finding.cwe = int(cwe_name.split("-")[1].split(":")[0])
                except (ValueError, IndexError, KeyError):
                    finding.cwe = None

            # Add references if available
            references = []
            if "line_of_code_url" in item:
                references.append(f"Line of Code: {item['line_of_code_url']}")
            if "rule" in item:
                if "owasp_names" in item["rule"]:
                    references.extend(item["rule"]["owasp_names"])
                if "cwe_names" in item["rule"]:
                    references.extend(item["rule"]["cwe_names"])

            if "external_ticket" in item:
                references.append(f"External Ticket: \n {item['external_ticket']}")

            # Add file location details
            if references:
                finding.references = "\n".join(references)

            # Add mitigation if available
            mitigation_parts = []
            if "assistant" in item:
                assistant = item["assistant"]
                if "guidance" in assistant:
                    if "summary" in assistant["guidance"]:
                        mitigation_parts.append(f"**Guidance Summary:**\n{assistant['guidance']['summary']}")
                    if "instructions" in assistant["guidance"]:
                        mitigation_parts.append(f"**Instructions:**\n{assistant['guidance']['instructions']}")

                if "autofix" in assistant:
                    autofix = assistant["autofix"]
                    if "fix_code" in autofix:
                        mitigation_parts.append(f"**Suggested Fix:**\n```\n{autofix['fix_code']}\n```")
                    if autofix.get("explanation"):
                        mitigation_parts.append(f"**Fix Explanation:**\n{autofix['explanation']}")

                if "autotriage" in assistant:
                    autotriage = assistant["autotriage"]
                    if "verdict" in autotriage:
                        mitigation_parts.append(f"**Auto-triage Verdict:** {autotriage['verdict']}")
                    if "reason" in autotriage:
                        mitigation_parts.append(f"**Auto-triage Reason:** {autotriage['reason']}")

                if "component" in assistant:
                    component = assistant["component"]
                    if "tag" in component:
                        mitigation_parts.append(f"**Component:** {component['tag']}")
                    if "risk" in component:
                        mitigation_parts.append(f"**Risk Level:** {component['risk']}")

            finding.mitigation = "\n\n".join(mitigation_parts) if mitigation_parts else None

            # Add unique identifier
            finding.unique_id_from_tool = item.get("match_based_id")

            # Add component name and version if available
            if "assistant" in item and "component" in item["assistant"]:
                finding.component_name = item["assistant"]["component"].get("tag")

            # Add dates
            if "created_at" in item:
                with contextlib.suppress(ValueError, TypeError):
                    finding.date = datetime.strptime(item["created_at"].split(".")[0], "%Y-%m-%dT%H:%M:%S")

            # Add impact
            impact_parts = []
            if "rule" in item and "vulnerability_classes" in item["rule"]:
                impact_parts.extend(item["rule"]["vulnerability_classes"])
            if "confidence" in item:
                impact_parts.append(f"Confidence: {item['confidence'].capitalize()}")
            if "repository" in item:
                repo = item["repository"]
                impact_parts.append(f"Repository: {repo.get('name', '')} ({repo.get('url', '')})")
            finding.impact = "\n".join(impact_parts)

            # Use match_based_id for deduplication if available, otherwise use file location
            dupe_key = finding.unique_id_from_tool or title + str(file_path) + str(line)

            if dupe_key in dupes:
                dupes[dupe_key].nb_occurences += 1
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def convert_severity(self, val):
        val = val.upper()
        if val in {"ERROR", "HIGH"}:
            return "High"
        if val in {"WARNING", "MEDIUM"}:
            return "Medium"
        if val in {"INFO", "LOW"}:
            return "Low"
        if val == "CRITICAL":
            return "Critical"
        return "Info"

    def get_description(self, item):
        desc = ""
        if "rule_message" in item:
            desc += f"**Message:** {item['rule_message']}\n\n"

        if "rule" in item:
            if "message" in item["rule"]:
                desc += f"**Rule Message:** {item['rule']['message']}\n\n"
            if "category" in item["rule"]:
                desc += f"**Category:** {item['rule']['category']}\n\n"
            if "confidence" in item["rule"]:
                desc += f"**Confidence:** {item['rule']['confidence']}\n\n"
            if "vulnerability_classes" in item["rule"]:
                desc += "**Vulnerability Classes:**\n"
                for vuln_class in item["rule"]["vulnerability_classes"]:
                    desc += f"- {vuln_class}\n"
                desc += "\n"
            if "cwe_names" in item["rule"]:
                desc += "**CWE References:**\n"
                for cwe in item["rule"]["cwe_names"]:
                    desc += f"- {cwe}\n"
                desc += "\n"
            if "owasp_names" in item["rule"]:
                desc += "**OWASP References:**\n"
                for owasp in item["rule"]["owasp_names"]:
                    desc += f"- {owasp}\n"
                desc += "\n"

        # Add categories
        if "categories" in item:
            desc += "**Categories:**\n"
            for category in item["categories"]:
                desc += f"- {category}\n"
            desc += "\n"

        # Add triage information
        if "triage_state" in item:
            desc += f"**Triage State:** {item['triage_state']}\n"
            if "triage_comment" in item:
                desc += f"**Triage Comment:** {item['triage_comment']}\n"
            if "triage_reason" in item:
                desc += f"**Triage Reason:** {item['triage_reason']}\n\n"

        return desc
