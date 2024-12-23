import json

# Définition de la classe du parser OSV directement dans le script
class OSVScannerParser:
    def classify_severity(self, input):
        return ("Medium" if input == "MODERATE" else input.lower().capitalize()) if input != "" else "Low"

    def get_findings(self, file, test):
        try:
            data = json.load(file)
        except json.decoder.JSONDecodeError:
            return []
        findings = []
        for result in data.get("results", []):
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
                    mitigation = None
                    if (affected := vulnerability.get("affected")) is not None:
                        if len(affected) > 0:
                            if (vulnerabilitypackage := affected[0].get("package", "")) != "":
                                vulnerabilitypackagepurl = vulnerabilitypackage.get("purl", "")
                            if (cwe := affected[0].get("database_specific", {}).get("cwes", None)) is not None:
                                cwe = cwe[0]["cweId"]
                            # Extraire la version corrigée (mitigation)
                            ranges = affected[0].get("ranges", [])
                            for range_item in ranges:
                                for event in range_item.get("events", []):
                                    if "fixed" in event:
                                        mitigation = f"Upgrade to version: {event['fixed']}"

                    reference = ""
                    for ref in vulnerability.get("references", []):
                        reference += ref.get("url") + "\n"

                    description = vulnerabilitysummary + "\n"
                    description += "**source_type**: " + source_type + "\n"
                    description += "**package_ecosystem**: " + package_ecosystem + "\n"
                    description += "**vulnerabilitydetails**: " + vulnerabilitydetails + "\n"
                    description += "**vulnerabilitypackagepurl**: " + vulnerabilitypackagepurl + "\n"

                    sev = vulnerability.get("database_specific", {}).get("severity", "")
                    finding = {
                        "title": vulnerabilityid + "_" + package_name,
                        "description": description,
                        "severity": self.classify_severity(sev),
                        "component_name": package_name,
                        "component_version": package_version,
                        "cwe": cwe,
                        "file_path": source_path,
                        "references": reference,
                        "mitigation": mitigation,
                    }
                    findings.append(finding)
        return findings

# Fonction principale pour exécuter le test
def test_osv_parser(json_file_path):
    parser = OSVScannerParser()

    with open(json_file_path, "r") as file:
        findings = parser.get_findings(file, test="Test")

    if findings:
        print(f"Nombre de findings : {len(findings)}\n")
        for finding in findings:
            print(f"--- Finding ---")
            print(f"Title: {finding['title']}")
            print(f"Severity: {finding['severity']}")
            print(f"Description: {finding['description']}")
            print(f"Mitigation: {finding['mitigation'] if finding['mitigation'] else 'Non spécifié'}")
            print(f"References: {finding['references']}")
            print(f"Component Name: {finding['component_name']}")
            print(f"Component Version: {finding['component_version']}")
            print(f"--- Fin du Finding ---\n")
    else:
        print("Aucun finding détecté.")

# Remplacez par le chemin vers votre fichier JSON de test
json_file_path = "test.json"

# Exécuter le test
test_osv_parser(json_file_path)
