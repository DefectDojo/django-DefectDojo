import json

from dojo.models import Endpoint, Finding


class SSHAuditParser:
    def get_scan_types(self):
        return ["SSH Audit Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import result of SSH Audit JSON output."

    def convert_cvss_score(self, raw_value):
        """
        According to CVSS official numbers https://nvd.nist.gov/vuln-metrics/cvss
                        None 	0.0
        Low 	0.0-3.9 	Low 	0.1-3.9
        Medium 	4.0-6.9 	Medium 	4.0-6.9
        High 	7.0-10.0 	High 	7.0-8.9
        Critical 	9.0-10.0
        """
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"

    def get_findings(self, filename, test):
        items = []
        try:
            data = json.load(filename)
        except ValueError:
            data = {}
        if data != {}:
            title = data["banner"]["raw"]
            for cve in data["cves"]:
                cvename = cve["name"]
                description = [
                    f"**CVE**: {cvename}",
                    f"**Description**: {cve['description']}",
                    f"**Banner**: {title}",
                ]
                severity = self.convert_cvss_score(raw_value=cve["cvssv2"])
                finding = Finding(title=str(title) + "_" + str(cvename),
                        test=test,
                        description="\n".join(description),
                        severity=severity,
                        static_finding=False)
                finding.unsaved_vulnerability_ids = []
                finding.unsaved_vulnerability_ids.append(cvename)
                items.append(finding)
                finding.unsaved_endpoints = []
                endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                finding.unsaved_endpoints.append(endpoint)
            for kex in data["kex"]:
                if "fail" in kex["notes"] and "warn" in kex["notes"]:
                    kexname = kex["algorithm"]
                    description = [f"**Algorithm**: {kexname}"]
                    description.append(f"**Description Failure**: {kex['notes']['fail']}")
                    description.append(f"**Description Warning**: {kex['notes']['warn']}")
                    if kex["notes"].get("info"):
                        description.append(f"**Info**: {kex['notes']['info']}")
                    severity = "High"
                    finding = Finding(title=str(title) + "_" + str(kexname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
                elif "fail" in kex["notes"]:
                    kexname = kex["algorithm"]
                    description = [f"**Algorithm**: {kexname}"]
                    description.append(f"**Description Failure**: {kex['notes']['fail']}")
                    if kex["notes"].get("info"):
                        description.append(f"**Info**: {kex['notes']['info']}")
                    severity = "High"
                    finding = Finding(title=str(title) + "_" + str(kexname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
                elif "warn" in kex["notes"]:
                    kexname = kex["algorithm"]
                    description = [f"**Algorithm**: {kexname}"]
                    description.append(f"**Description Warning**: {kex['notes']['warn']}")
                    if kex["notes"].get("info"):
                        description.append(f"**Info**: {kex['notes']['info']}")
                    severity = "Medium"
                    finding = Finding(title=str(title) + "_" + str(kexname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
            for key in data["key"]:
                if "fail" in key["notes"] and "warn" in key["notes"]:
                    keyname = key["algorithm"]
                    description = [f"**Algorithm**: {keyname}"]
                    description.append(f"**Description Failure**: {key['notes']['fail']}")
                    description.append(f"**Description Warning**: {key['notes']['warn']}")
                    if "keysize" in key:
                        description.append(f"**KeySize**: {key['keysize']}")
                    if key["notes"].get("info"):
                        description.append(f"**Info**: {key['notes']['info']}")
                    severity = "High"
                    finding = Finding(title=str(title) + "_" + str(keyname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
                elif "fail" in key["notes"]:
                    keyname = key["algorithm"]
                    description = [f"**Algorithm**: {keyname}"]
                    description.append(f"**Description Failure**: {key['notes']['fail']}")
                    if "keysize" in key:
                        description.append(f"**KeySize**: {key['keysize']}")
                    if key["notes"].get("info"):
                        description.append(f"**Info**: {key['notes']['info']}")
                    severity = "High"
                    finding = Finding(title=str(title) + "_" + str(keyname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
                elif "warn" in key["notes"]:
                    keyname = key["algorithm"]
                    description = [f"**Algorithm**: {keyname}"]
                    description.append(f"**Description Warning**: {key['notes']['warn']}")
                    if "keysize" in key:
                        description.append(f"**KeySize**: {key['keysize']}")
                    if key["notes"].get("info"):
                        description.append(f"**Info**: {key['notes']['info']}")
                    severity = "Medium"
                    finding = Finding(title=str(title) + "_" + str(keyname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
            for mac in data["mac"]:
                if "fail" in mac["notes"] and "warn" in mac["notes"]:
                    macname = mac["algorithm"]
                    description = [f"**Algorithm**: {macname}"]
                    description.append(f"**Description Failure**: {mac['notes']['fail']}")
                    description.append(f"**Description Warning**: {mac['notes']['warn']}")
                    if mac["notes"].get("info"):
                        description.append(f"**Info**: {mac['notes']['info']}")
                    severity = "High"
                    finding = Finding(title=str(title) + "_" + str(macname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
                elif "fail" in mac["notes"]:
                    macname = mac["algorithm"]
                    description = [f"**Algorithm**: {macname}"]
                    description.append(f"**Description Failure**: {mac['notes']['fail']}")
                    if mac["notes"].get("info"):
                        description.append(f"**Info**: {mac['notes']['info']}")
                    severity = "High"
                    finding = Finding(title=str(title) + "_" + str(macname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
                elif "warn" in mac["notes"]:
                    macname = mac["algorithm"]
                    description = [f"**Algorithm**: {macname}"]
                    description.append(f"**Description Warning**: {mac['notes']['warn']}")
                    if mac["notes"].get("info"):
                        description.append(f"**Info**: {mac['notes']['info']}")
                    severity = "Medium"
                    finding = Finding(title=str(title) + "_" + str(macname),
                            test=test,
                            description="\n".join(description),
                            severity=severity,
                            static_finding=False)
                    items.append(finding)
                    finding.unsaved_endpoints = []
                    endpoint = Endpoint(host=data["target"].split(":")[0], port=data["target"].split(":")[1])
                    finding.unsaved_endpoints.append(endpoint)
        return items
