from dojo.models import Finding
import re


class SonarQubeRESTAPIJSON:
    def get_json_items(self, json_content, test, mode):
        items = []
        if json_content.get("issues"):
            for issue in json_content.get("issues"):
                if issue.get("type") == "BUG":
                    key = issue.get("key")
                    rule = issue.get("rule")
                    component = issue.get("component")
                    project = issue.get("project")
                    line = str(issue.get("line"))
                    textRange = str(issue.get("textRange"))
                    flows = str(issue.get("flows"))
                    status = issue.get("status")
                    message = issue.get("message")
                    tags = str(issue.get("tags"))
                    type = issue.get("type")
                    scope = issue.get("scope")
                    quickFixAvailable = str(issue.get("quickFixAvailable"))
                    codeVariants = str(issue.get("codeVariants"))
                    description = ""
                    description += "**key:** " + key + "\n"
                    description += "**rule:** " + rule + "\n"
                    description += "**component:** " + component + "\n"
                    description += "**project:** " + project + "\n"
                    description += "**line:** " + line + "\n"
                    description += "**textRange:** " + textRange + "\n"
                    description += "**flows:** " + flows + "\n"
                    description += "**status:** " + status + "\n"
                    description += "**message:** " + message + "\n"
                    description += "**tags:** " + tags + "\n"
                    description += "**type:** " + type + "\n"
                    description += "**scope:** " + scope + "\n"
                    description += self.returncomponent(json_content, component)
                    item = Finding(
                        title=rule + "_" + key,
                        description=description,
                        test=test,
                        severity=self.severitytranslator(issue.get("severity")),
                        static_finding=True,
                        dynamic_finding=False,
                        tags=["bug"],
                    )
                elif issue.get("type") == "VULNERABILITY":
                    key = issue.get("key")
                    rule = issue.get("rule")
                    component = issue.get("component")
                    project = issue.get("project")
                    flows = str(issue.get("flows"))
                    status = issue.get("status")
                    message = issue.get("message")
                    cve = None
                    if "Reference: CVE" in message:
                        cve_pattern = r'Reference: CVE-\d{4}-\d{4,7}'
                        cves = re.findall(cve_pattern, message)
                        if cves:
                            cve = cves[0].split("Reference: ")[1]
                    elif "References: CVE" in message:
                        cve_pattern = r'References: CVE-\d{4}-\d{4,7}'
                        cves = re.findall(cve_pattern, message)
                        if cves:
                            cve = cves[0].split("References: ")[1]
                    elif "Reference: GHSA" in message and cve is None:
                        cve_pattern = r'Reference: GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}'
                        cves = re.findall(cve_pattern, message)
                        if cves:
                            cve = cves[0].split("Reference: ")[1]
                    elif "References: GHSA" in message and cve is None:
                        cve_pattern = r'References: GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}'
                        cves = re.findall(cve_pattern, message)
                        if cves:
                            cve = cves[0].split("References: ")[1]
                    cwe = None
                    if "Category: CWE-" in message:
                        cwe_pattern = r'Category: CWE-\d{1,5}'
                        cwes = re.findall(cwe_pattern, message)
                        if cwes:
                            cwe = cwes[0].split("Category: CWE-")[1]
                    cvss = None
                    if "CVSS Score: " in message:
                        cvss_pattern = r'CVSS Score: \d{1}.\d{1}'
                        cvsss = re.findall(cvss_pattern, message)
                        if cvsss:
                            cvss = cvsss[0].split("CVSS Score: ")[1]
                    component_name = None
                    component_version = None
                    if "Filename: " in message and " | " in message:
                        component_pattern = r'Filename: .* \| '
                        comp = re.findall(component_pattern, message)
                        if comp:
                            component_result = comp[0].split("Filename: ")[1].split(" | ")[0]
                            component_name = component_result.split(":")[0]
                            try:
                                component_version = component_result.split(":")[1]
                            except IndexError:
                                component_version = None
                    scope = issue.get("scope")
                    quickFixAvailable = str(issue.get("quickFixAvailable"))
                    codeVariants = str(issue.get("codeVariants"))
                    tags = str(issue.get("tags"))
                    description = ""
                    description += "**key:** " + key + "\n"
                    description += "**rule:** " + rule + "\n"
                    description += "**component:** " + component + "\n"
                    description += "**project:** " + project + "\n"
                    description += "**flows:** " + flows + "\n"
                    description += "**status:** " + status + "\n"
                    description += "**message:** " + message + "\n"
                    description += "**scope:** " + scope + "\n"
                    description += "**quickFixAvailable:** " + quickFixAvailable + "\n"
                    description += "**codeVariants:** " + codeVariants + "\n"
                    description += "**tags:** " + tags + "\n"
                    description += self.returncomponent(json_content, component)
                    item = Finding(
                        title=rule + "_" + key,
                        description=description,
                        test=test,
                        severity=self.severitytranslator(issue.get("severity")),
                        static_finding=True,
                        dynamic_finding=False,
                        component_name=component_name,
                        component_version=component_version,
                        cve=cve,
                        cwe=cwe,
                        cvssv3_score=cvss,
                        tags=["vulnerability"],
                    )
                elif issue.get("type") == "CODE_SMELL":
                    key = issue.get("key")
                    rule = issue.get("rule")
                    component = issue.get("component")
                    project = issue.get("project")
                    line = str(issue.get("line"))
                    textRange = str(issue.get("textRange"))
                    flows = str(issue.get("flows"))
                    status = issue.get("status")
                    message = issue.get("message")
                    tags = str(issue.get("tags"))
                    scope = issue.get("scope")
                    quickFixAvailable = str(issue.get("quickFixAvailable"))
                    codeVariants = str(issue.get("codeVariants"))
                    description = ""
                    description += "**rule:** " + rule + "\n"
                    description += "**component:** " + component + "\n"
                    description += "**project:** " + project + "\n"
                    description += "**line:** " + line + "\n"
                    description += "**textRange:** " + textRange + "\n"
                    description += "**flows:** " + flows + "\n"
                    description += "**status:** " + status + "\n"
                    description += "**message:** " + message + "\n"
                    description += "**tags:** " + tags + "\n"
                    description += "**scope:** " + scope + "\n"
                    description += "**quickFixAvailable:** " + quickFixAvailable + "\n"
                    description += "**codeVariants:** " + codeVariants + "\n"
                    description += self.returncomponent(json_content, component)
                    item = Finding(
                        title=rule + "_" + key,
                        description=description,
                        test=test,
                        severity=self.severitytranslator(issue.get("severity")),
                        static_finding=True,
                        dynamic_finding=False,
                        tags=["code_smell"],
                    )
                items.append(item)
        if json_content.get("hotspots"):
            for hotspot in json_content.get("hotspots"):
                key = hotspot.get("key")
                component = hotspot.get("component")
                project = hotspot.get("project")
                securityCategory = hotspot.get("securityCategory")
                status = hotspot.get("status")
                line = str(hotspot.get("line"))
                message = hotspot.get("message")
                textRange = str(hotspot.get("textRange"))
                flows = str(hotspot.get("flows"))
                ruleKey = hotspot.get("ruleKey")
                messageFormattings = str(hotspot.get("messageFormattings"))
                description = ""
                description += "**key:** " + key + "\n"
                description += "**component:** " + component + "\n"
                description += "**project:** " + project + "\n"
                description += "**securityCategory:** " + securityCategory + "\n"
                description += "**status:** " + status + "\n"
                description += "**line:** " + line + "\n"
                description += "**message:** " + message + "\n"
                description += "**textRange:** " + textRange + "\n"
                description += "**flows:** " + flows + "\n"
                description += "**ruleKey:** " + ruleKey + "\n"
                description += "**messageFormattings:** " + messageFormattings + "\n"
                description += self.returncomponent(json_content, component)
                item = Finding(
                    title=ruleKey + "_" + key,
                    description=description,
                    test=test,
                    severity=self.severitytranslator(hotspot.get("vulnerabilityProbability")),
                    static_finding=True,
                    dynamic_finding=False,
                    tags=["hotspot"],
                )
                items.append(item)
        return items

    def severitytranslator(self, severity):
        if severity == "BLOCKER":
            return "High"
        elif severity == "MAJOR":
            return "Medium"
        elif severity == "MINOR":
            return "Low"
        else:
            return severity.lower().capitalize()

    def returncomponent(self, json_content, key):
        components = json_content.get("components")
        description = ""
        for comp in components:
            if comp.get("key") == key:
                componentkeys = comp.keys()
                for ck in componentkeys:
                    description += "**Componentkey " + ck + "**: " + str(comp.get(ck)) + "\n"
        return description
