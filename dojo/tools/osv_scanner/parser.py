import json
from dojo.models import Finding


class OSVScannerParser:

    def get_scan_types(self):
        return ["OSV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OSV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "OSV scan output can be imported in JSON format (option --format json)."

    def classify_severity(self, input):
        return ("Medium" if input == "MODERATE" else input.lower().capitalize()) if input != "" else "Low"

    def get_findings(self, file, test):
        try:
            data = json.load(file)
        except json.decoder.JSONDecodeError:
            return []
        findings = []
        for result in data.get("results", []):
            # Extract source locations if present
            source_path = result.get("source", {}).get("path", "")
            source_type = result.get("source", {}).get("type", "")
            for package in result.get("packages", []):
                package_name = package.get("package", {}).get("name")
                package_version = package.get("package", {}).get("version")
                package_ecosystem = package.get("package", {}).get("ecosystem", "")
                for vulnerability in package.get("vulnerabilities", []):
                    vulnerabilityid = vulnerability.get("id", "")
                    vulnerabilitysummary = vulnerability.get("summary", "")
                    vulnerabilitydetails = vulnerability.get("details", "")
                    vulnerabilitypackagepurl = ""
                    cwe = None
                    mitigations_by_type = {}  # Dictionnaire pour stocker les versions corrigées par type

                    # Vérification de la section "affected"
                    if (affected := vulnerability.get("affected")) is not None:
                        if len(affected) > 0:
                            # Récupération du package purl si présent
                            if (vulnerabilitypackage := affected[0].get("package", "")) != "":
                                vulnerabilitypackagepurl = vulnerabilitypackage.get("purl", "")
                            # Extraction du CWE
                            if (cwe := affected[0].get("database_specific", {}).get("cwes", None)) is not None:
                                cwe = cwe[0]["cweId"]
                            # Extraction des versions corrigées par type
                            ranges = affected[0].get("ranges", [])
                            for range_item in ranges:
                                range_type = range_item.get("type", "")
                                repo_url = range_item.get("repo", "")
                                for event in range_item.get("events", []):
                                    if "fixed" in event:
                                        fixed_value = event["fixed"]
                                        # Format GIT URL si applicable
                                        if range_type == "GIT" and repo_url:
                                            formatted_value = f"{repo_url}/commit/{fixed_value}"
                                        else:
                                            formatted_value = fixed_value
                                        # Ajouter à la liste par type
                                        if range_type not in mitigations_by_type:
                                            mitigations_by_type[range_type] = []
                                        mitigations_by_type[range_type].append(formatted_value)

                    # Création du texte de mitigation formaté
                    mitigation_text = None
                    if mitigations_by_type:
                        mitigation_text = "**Upgrade to versions**:\n"
                        for typ, versions in mitigations_by_type.items():
                            mitigation_text += f"\t{typ} :\n"
                            for version in versions:
                                mitigation_text += f"\t\t- {version}\n"

                    # Création des références
                    reference = ""
                    for ref in vulnerability.get("references", []):
                        reference += ref.get("url") + "\n"

                    # Définition de la description
                    description = vulnerabilitysummary + "\n"
                    description += f"**Source type**: {source_type}\n"
                    description += f"**Package ecosystem**: {package_ecosystem}\n"
                    description += f"**Vulnerability details**: {vulnerabilitydetails}\n"
                    description += f"**Vulnerability package purl**: {vulnerabilitypackagepurl}\n"

                    sev = vulnerability.get("database_specific", {}).get("severity", "")

                    # Création de l'objet Finding attendu par DefectDojo
                    finding = Finding(
                        title=f"{vulnerabilityid}_{package_name}",
                        test=test,
                        description=description,
                        severity=self.classify_severity(sev),
                        static_finding=True,
                        dynamic_finding=False,
                        component_name=package_name,
                        component_version=package_version,
                        cwe=cwe,
                        file_path=source_path,
                        references=reference,
                    )

                    # Ajout de la mitigation si disponible
                    if mitigation_text:
                        finding.mitigation = mitigation_text

                    # Ajout des IDs de vulnérabilité
                    if vulnerabilityid:
                        finding.unsaved_vulnerability_ids = [vulnerabilityid]

                    findings.append(finding)

        return findings
