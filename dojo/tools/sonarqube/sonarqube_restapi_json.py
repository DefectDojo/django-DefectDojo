from dojo.models import Finding


class SonarQubeRESTAPIJSON(object):
    def get_json_items(self, json_content, test, mode):
        items = []
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
                    title="vuln_title",
                    description="vuln_description",
                    test=test,
                    severity=self.severitytranslator(issue.get("severity")),
                    static_finding=True,
                    dynamic_finding=False,
                )
            elif issue.get("type") == "VULNERABILITY":
                key = issue.get("key")
                rule = issue.get("rule")
                component = issue.get("component")
                project = issue.get("project")
                flows = str(issue.get("flows"))
                status = issue.get("status")
                message = issue.get("message")
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
                    description += "**Componentkey " + ck + "**: " + str(comp.get("ck")) + "\n"
        return description
