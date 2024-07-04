import json
import textwrap

from dojo.models import Finding


class KubescapeParser:
    def get_scan_types(self):
        return ["Kubescape JSON Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import result of Kubescape JSON output."

    def find_control_summary_by_id(self, data, control_id):
        # Browse summaryDetails to look for matching control id. If the Control id is matching, return the first occurence.
        try:
            controls = data.get("summaryDetails", {}).get("controls", {})
            return controls.get(control_id, None)
        except ValueError:
            return None

    @staticmethod
    def __hyperlink(link: str) -> str:
        return "[" + link + "](" + link + ")"

    def severity_mapper(self, input):
        if input <= 4:
            return "Low"
        elif input <= 7:
            return "Medium"
        elif input <= 9:
            return "High"
        elif input <= 10:
            return "Critical"

    def parse_resource_id(self, resource_id):
        try:
            parts = resource_id.split("/")
            resource_type = parts[-2]
            resource_name = parts[-1]
            return resource_type, resource_name
        except IndexError:
            return None, None

    def get_findings(self, filename, test):
        findings = []
        try:
            data = json.load(filename)
        except ValueError:
            data = {}
        for resource in data["resources"]:
            resourceid = resource["resourceID"]
            resource_type, resource_name = self.parse_resource_id(resourceid)
            results = ([each for each in data["results"] if each.get('resourceID') == resourceid])
            controls = results[0].get("controls", [])

            for control in controls:
                # This condition is true if the result doesn't contain the status for each control (old format)
                retrocompatibility_condition = 'status' not in control or 'status' not in control['status']
                if retrocompatibility_condition or control["status"]["status"] == "failed":
                    control_name = control["name"]
                    if resource_type and resource_name and control_name:
                        title = f"{control_name} - {resource_type} {resource_name}"
                    else:
                        title = f"{control_name} - {resourceid}"
                    controlID = control['controlID']

                    # Find control details
                    controlSummary = self.find_control_summary_by_id(data, controlID)
                    if controlSummary is None:
                        severity = "Info"
                        mitigation = ""
                    else:
                        severity = self.severity_mapper(controlSummary.get("scoreFactor", 0))
                        # Define mitigation if available
                        if "mitigation" in controlSummary:
                            mitigation = controlSummary["mitigation"]
                        else:
                            mitigation = ""

                    armoLink = f"https://hub.armosec.io/docs/{controlID.lower()}"
                    description = "**Summary:** " + f"The ressource '{resourceid}' has failed the control '{control_name}'." + "\n"
                    if controlSummary is not None and "description" in controlSummary:
                        description += "**Description:** " + controlSummary["description"] + "\n"

                    # Define category if available
                    if controlSummary is not None and "category" in controlSummary and "subCategory" in controlSummary["category"]:
                        category_name = controlSummary["category"]["name"]
                        category_subname = controlSummary["category"]["subCategory"]["name"]
                        category = f"{category_name} > {category_subname}"
                        description += "**Category:** " + category + "\n"
                    elif controlSummary is not None and "category" in controlSummary and "name" in controlSummary["category"]:
                        category = controlSummary["category"]["name"]
                        description += "**Category:** " + category + "\n"

                    description += "View control details here: " + self.__hyperlink(armoLink)

                    steps_to_reproduce = "The following rules have failed :" + "\n"
                    steps_to_reproduce += "\t**Rules:** " + str(json.dumps(control["rules"], indent=4)) + "\n"

                    steps_to_reproduce += "Resource object may contain evidence:" + "\n"
                    steps_to_reproduce += "\t**Resource object:** " + str(json.dumps(resource["object"], indent=4))

                    references = armoLink

                    find = Finding(
                        title=textwrap.shorten(title, 150),
                        test=test,
                        description=description,
                        mitigation=mitigation,
                        steps_to_reproduce=steps_to_reproduce,
                        references=references,
                        severity=severity,
                        component_name=resourceid,
                        static_finding=True,
                        dynamic_finding=False,
                    )
                    findings.append(find)
        return findings
