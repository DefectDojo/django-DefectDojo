import json
import logging

logger = logging.getLogger(__name__)


def get_npm_cwe(item_node):
    """
        possible values:
            "cwe": ["CWE-173", "CWE-200","CWE-601"]  (or [])
            "cwe": "CWE-1234"
            "cwe": "[\"CWE-173\",\"CWE-200\",\"CWE-601\"]" (or "[]")
    """
    if 'cwe' in item_node:
        cwe_node = item_node['cwe']
        if type(cwe_node) == list:
            if cwe_node:
                return int(cwe_node[0][4:])
        elif cwe_node.startswith('CWE-'):
            cwe_string = cwe_node[4:]
            if cwe_string:
                return int(cwe_string)
        elif cwe_node.startswith('['):
            cwe = json.loads(cwe_node)
            if cwe:
                return int(cwe[0][4:])

    # Use CWE-1035 as fallback (vulnerable third party component)
    return 1035
