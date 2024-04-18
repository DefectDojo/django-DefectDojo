from dojo.tools.sonarqube.sonarqube_restapi_json import SonarQubeRESTAPIJSON
import json


class SonarQubeRESTAPIZIP:
    def get_items(self, files, test, mode):
        total_findings_per_file = list()
        for dictkey in files.keys():
            if dictkey.endswith(".json"):
                json_content = json.loads(files[dictkey].decode('ascii'))
                total_findings_per_file += SonarQubeRESTAPIJSON().get_json_items(json_content, test, mode)
        return total_findings_per_file
