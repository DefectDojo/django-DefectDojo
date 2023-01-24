from dojo.tools.sonarqube_api.api_client import SonarQubeAPI
from dojo.tools.cobalt_api.api_client import CobaltAPI
from dojo.tools.edgescan.api_client import EdgescanAPI
from dojo.tools.bugcrowd_api.api_client import BugcrowdAPI

SCAN_APIS = {'SonarQube': SonarQubeAPI,
             'Cobalt.io': CobaltAPI,
             'Edgescan API': EdgescanAPI,
             'Bugcrowd API': BugcrowdAPI
             }


def create_API(tool_configuration):
    if tool_configuration.tool_type.name in SCAN_APIS:
        api_class = SCAN_APIS.get(tool_configuration.tool_type.name)
        return api_class(tool_configuration)
    else:
        return None
