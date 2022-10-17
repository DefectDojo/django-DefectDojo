from dojo.tools.api_bugcrowd.api_client import BugcrowdAPI
from dojo.tools.api_cobalt.api_client import CobaltAPI
from dojo.tools.api_edgescan.api_client import EdgescanAPI
from dojo.tools.api_sonarqube.api_client import SonarQubeAPI


SCAN_APIS = {
                'Bugcrowd API': BugcrowdAPI,
                'Cobalt.io': CobaltAPI,
                'Edgescan API': EdgescanAPI,
                'SonarQube': SonarQubeAPI,
             }


def create_API(tool_configuration):
    if tool_configuration.tool_type.name in SCAN_APIS:
        api_class = SCAN_APIS.get(tool_configuration.tool_type.name)
        return api_class(tool_configuration)
    else:
        return None
