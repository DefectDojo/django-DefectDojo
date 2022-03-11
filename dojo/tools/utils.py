import json
import logging

logger = logging.getLogger(__name__)


def get_npm_cwe(item_node):
    if 'cwe' in item_node:
        cwe_node = item_node['cwe']
        if cwe_node.startswith('CWE-'):
            cwe_string = cwe_node[4:]
            if cwe_string:
                return int(cwe_string)
        elif cwe_node.startswith('['):
            # Somehow multiple CWEs end up in the json report like this
            # [\"CWE-173\",\"CWE-200\",\"CWE-601\"]
            # which becomes after json load:
            # ["CWE-173","CWE-200","CWE-601"]
            # we parse this and take the first CWE

            return int(json.loads(cwe_node)[0][4:])

    # Use CWE-1035 as fallback (vulnerable third party component)
    return 1035
