import json
import logging
import zipfile

from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class MSDefenderParser:

    """Import from MSDefender findings"""

    def get_scan_types(self):
        return ["MSDefender Parser"]

    def get_label_for_scan_types(self, scan_type):
        return "MSDefender Parser"

    def get_description_for_scan_types(self, scan_type):
        return ("MSDefender findings can be retrieved using the REST API")

    def get_findings(self, file, test):
        findings = []
        if str(file.name).endswith(".json"):
            vulnerabilityfile = json.load(file)
            vulnerabilitydata = vulnerabilityfile["value"]
            for vulnerability in vulnerabilitydata:
                findings.append(self.process_json(vulnerability))
        elif str(file.name).endswith(".zip"):
            if str(file.__class__) == "<class '_io.TextIOWrapper'>":
                input_zip = zipfile.ZipFile(file.name, "r")
            else:
                input_zip = zipfile.ZipFile(file, "r")

            zipdata = {name: input_zip.read(name) for name in input_zip.namelist()}
            vulnerabilityfiles = []
            machinefiles = []
            for content in list(zipdata):
                if "vulnerabilities/" in content and content != "vulnerabilities/":
                    vulnerabilityfiles.append(content)
                if "machines/" in content and content != "machines/":
                    machinefiles.append(content)

            if len(vulnerabilityfiles) == 0:
                logger.debug("No vulnerabilities.json files found in the vulnerabilities/ folder")
                return []

            vulnerabilities = []
            machines = {}
            for vulnerabilityfile in vulnerabilityfiles:
                logger.debug("Loading vulnerabilitiy file: %s", vulnerabilityfile)
                output = json.loads(zipdata[vulnerabilityfile].decode("ascii"))["value"]
                for data in output:
                    vulnerabilities.append(data)
            for machinefile in machinefiles:
                logger.debug("Loading machine file: %s", vulnerabilityfile)
                output = json.loads(zipdata[machinefile].decode("ascii"))["value"]
                for data in output:
                    machines[data.get("id")] = data
            for vulnerability in vulnerabilities:
                try:
                    machine = machines.get(vulnerability["machineId"], None)
                    if machine is not None:
                        findings.append(self.process_json_with_machine_info(vulnerability, machine))
                    else:
                        logger.debug("fallback to process without machine: no machine id")
                        findings.append(self.process_json(vulnerability))
                except (IndexError, KeyError):
                    logger.exception("fallback to process without machine: exception")
                    self.process_json(vulnerability)
        else:
            return []
        return findings

    def process_json(self, vulnerability):
        description = ""
        description += "cveId: " + str(vulnerability.get("cveId", "")) + "\n"
        description += "machineId: " + str(vulnerability.get("machineId", "")) + "\n"
        description += "fixingKbId: " + str(vulnerability.get("fixingKbId", "")) + "\n"
        description += "productName: " + str(vulnerability.get("productName", "")) + "\n"
        description += "productVendor: " + str(vulnerability.get("productVendor", "")) + "\n"
        description += "productVersion: " + str(vulnerability.get("productVersion", "")) + "\n"
        description += "machine Info: " + "Unable to find or parse machine data, check logs for more information" + "\n"
        title = str(vulnerability.get("cveId", ""))
        finding = Finding(
            title=title + "_" + vulnerability["machineId"],
            severity=self.severity_check(vulnerability["severity"]),
            description=description,
            static_finding=False,
            dynamic_finding=True,
        )
        if vulnerability["fixingKbId"] is not None:
            finding.mitigation = vulnerability["fixingKbId"]
        if vulnerability["cveId"] is not None:
            finding.unsaved_vulnerability_ids = []
            finding.unsaved_vulnerability_ids.append(vulnerability["cveId"])
        finding.unsaved_endpoints = []
        return finding

    def process_json_with_machine_info(self, vulnerability, machine):
        description = ""
        description += "cveId: " + str(vulnerability.get("cveId", "")) + "\n"
        description += "machineId: " + str(vulnerability.get("machineId", "")) + "\n"
        description += "fixingKbId: " + str(vulnerability.get("fixingKbId", "")) + "\n"
        description += "productName: " + str(vulnerability.get("productName", "")) + "\n"
        description += "productVendor: " + str(vulnerability.get("productVendor", "")) + "\n"
        description += "productVersion: " + str(vulnerability.get("productVersion", "")) + "\n"
        description += "machine Info: id: " + str(machine.get("id", "")) + "\n"
        description += "machine Info: osPlatform: " + str(machine.get("osPlatform", "")) + "\n"
        description += "machine Info: osVersion: " + str(machine.get("osVersion", "")) + "\n"
        description += "machine Info: osProcessor: " + str(machine.get("osProcessor", "")) + "\n"
        description += "machine Info: version: " + str(machine.get("version", "")) + "\n"
        description += "machine Info: agentVersion: " + str(machine.get("agentVersion", "")) + "\n"
        description += "machine Info: osBuild: " + str(machine.get("osBuild", "")) + "\n"
        description += "machine Info: healthStatus: " + str(machine.get("healthStatus", "")) + "\n"
        description += "machine Info: deviceValue: " + str(machine.get("deviceValue", "")) + "\n"
        description += "machine Info: rbacGroupId: " + str(machine.get("rbacGroupId", "")) + "\n"
        description += "machine Info: rbacGroupName: " + str(machine.get("rbacGroupName", "")) + "\n"
        description += "machine Info: riskScore: " + str(machine.get("riskScore", "")) + "\n"
        description += "machine Info: exposureLevel: " + str(machine.get("exposureLevel", "")) + "\n"
        description += "machine Info: isAadJoined: " + str(machine.get("isAadJoined", "")) + "\n"
        description += "machine Info: aadDeviceId: " + str(machine.get("aadDeviceId", "")) + "\n"
        description += "machine Info: defenderAvStatus: " + str(machine.get("defenderAvStatus", "")) + "\n"
        description += "machine Info: onboardingStatus: " + str(machine.get("onboardingStatus", "")) + "\n"
        description += "machine Info: osArchitecture: " + str(machine.get("osArchitecture", "")) + "\n"
        description += "machine Info: managedBy: " + str(machine.get("managedBy", "")) + "\n"
        title = str(vulnerability.get("cveId", ""))
        if "computerDnsName" in machine and str(machine["computerDnsName"]) != "null":
            title = title + "_" + str(machine["computerDnsName"])
        if "osPlatform" in machine and str(machine["osPlatform"]) != "null":
            title = title + "_" + str(machine["osPlatform"])
        finding = Finding(
            title=title + "_" + vulnerability["machineId"],
            severity=self.severity_check(vulnerability["severity"]),
            description=description,
            static_finding=False,
            dynamic_finding=True,
        )
        if "fixingKbId" in vulnerability and vulnerability["fixingKbId"] is not None:
            finding.mitigation = vulnerability["fixingKbId"]
        if "cveId" in vulnerability:
            finding.unsaved_vulnerability_ids = []
            finding.unsaved_vulnerability_ids.append(vulnerability["cveId"])
        finding.unsaved_endpoints = []
        if "computerDnsName" in machine and machine["computerDnsName"] is not None:
            finding.unsaved_endpoints.append(Endpoint(host=str(machine["computerDnsName"]).replace(" ", "").replace("(", "_").replace(")", "_")))
        if "lastIpAddress" in machine and machine["lastIpAddress"] is not None:
            finding.unsaved_endpoints.append(Endpoint(host=str(machine["lastIpAddress"])))
        if "lastExternalIpAddress" in machine and machine["lastExternalIpAddress"] is not None:
            finding.unsaved_endpoints.append(Endpoint(host=str(machine["lastExternalIpAddress"])))
        return finding

    def severity_check(self, severity_input):
        if severity_input in {"Informational", "Low", "Medium", "High", "Critical"}:
            return severity_input
        return "Informational"
