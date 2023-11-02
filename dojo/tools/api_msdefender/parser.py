import json
from dojo.models import Finding
from .importer import MSDefenderApiImporter


class ApiMSDefenderParser(object):
    """
    Import from MSDefender API /findings
    """

    def get_scan_types(self):
        return ["MSDefender API"]

    def get_label_for_scan_types(self, scan_type):
        return "MSDefender API"

    def get_description_for_scan_types(self, scan_type):
        return ("MSDefender findings can be directly imported using the REST API")

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return "MSDefender API"

    def api_scan_configuration_hint(self):
        return (
            "Do not set anything here."
        )

    def get_findings(self, file, test):
        if file:
            data = []
            vulnerabilityfile = json.load(file[0])
            vulnerabilitydata = vulnerabilityfile['value']
            data.append(vulnerabilitydata)
            machinefile = json.load(file[1])
            machinedata = machinefile['value']
            data.append(machinedata)
        else:
            data = MSDefenderApiImporter().get_findings(test)
        return self.process_vulnerabilities(test, data)

    def machinelisttranslator(self, machinelist):
        self.dictformachinelist = {}
        i = 0
        for machines in machinelist:
            self.dictformachinelist[machines['id']]=i
            i+=1

    def returnlistfromtranslator(self, machineid, machinelist):
        return machinelist[self.dictformachinelist[machineid]]

    def process_vulnerabilities(self, file, test):
        self.machinelisttranslator(machinelist=test[1])
        findings = []
        for vulnerability in test[0]:
            machine = self.returnlistfromtranslator(machineid=vulnerability['machineId'], machinelist=test[1])
            description = ""
            description += "cveId: " + str(vulnerability['cveId']) + "\n"
            description += "machineId: " + str(vulnerability['machineId']) + "\n"
            description += "fixingKbId: " + str(vulnerability['fixingKbId']) + "\n"
            description += "productName: " + str(vulnerability['productName']) + "\n"
            description += "productVendor: " + str(vulnerability['productVendor']) + "\n"
            description += "productVersion: " + str(vulnerability['productVersion']) + "\n"
            description += "machine Info: id: " + str(machine['id']) + "\n"
            description += "machine Info: computerDnsName: " + str(machine['computerDnsName']) + "\n"
            description += "machine Info: osPlatform: " + str(machine['osPlatform']) + "\n"
            description += "machine Info: osVersion: " + str(machine['osVersion']) + "\n"
            description += "machine Info: osProcessor: " + str(machine['osProcessor']) + "\n"
            description += "machine Info: version: " + str(machine['version']) + "\n"
            description += "machine Info: lastIpAddress: " + str(machine['lastIpAddress']) + "\n"
            description += "machine Info: lastExternalIpAddress: " + str(machine['lastExternalIpAddress']) + "\n"
            description += "machine Info: agentVersion: " + str(machine['agentVersion']) + "\n"
            description += "machine Info: osBuild: " + str(machine['osBuild']) + "\n"
            description += "machine Info: healthStatus: " + str(machine['healthStatus']) + "\n"
            description += "machine Info: deviceValue: " + str(machine['deviceValue']) + "\n"
            description += "machine Info: rbacGroupId: " + str(machine['rbacGroupId']) + "\n"
            description += "machine Info: rbacGroupName: " + str(machine['rbacGroupName']) + "\n"
            description += "machine Info: riskScore: " + str(machine['riskScore']) + "\n"
            description += "machine Info: exposureLevel: " + str(machine['exposureLevel']) + "\n"
            description += "machine Info: isAadJoined: " + str(machine['isAadJoined']) + "\n"
            description += "machine Info: aadDeviceId: " + str(machine['aadDeviceId']) + "\n"
            description += "machine Info: defenderAvStatus: " + str(machine['defenderAvStatus']) + "\n"
            description += "machine Info: onboardingStatus: " + str(machine['onboardingStatus']) + "\n"
            description += "machine Info: osArchitecture: " + str(machine['osArchitecture']) + "\n"
            description += "machine Info: managedBy: " + str(machine['managedBy']) + "\n"
            description += "machine Info: ipAddresses: " + str(machine['ipAddresses']) + "\n"
            finding = Finding(
                title=vulnerability["id"],
                severity=vulnerability['severity'],
                description=description,
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=vulnerability["id"],
            )
            if vulnerability['fixingKbId'] is not None:
                finding.mitigation = vulnerability['fixingKbId']
            if vulnerability['cveId'] is not None:
                finding.cve = vulnerability['cveId']

            findings.append(finding)
        return findings
