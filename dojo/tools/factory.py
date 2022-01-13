import re
import logging
from django.conf import settings
from dojo.models import Test_Type

PARSERS = {}


def register(parser_type):
    for scan_type in parser_type().get_scan_types():
        parser = parser_type()
        if scan_type.endswith("detailed"):
            parser.set_mode("detailed")
        register_parser(scan_type, parser)


def register_parser(scan_type, parser):
    logging.debug(f"register scan_type:{scan_type} with parser:{parser}")
    # check double registration or registration with an existing key
    if scan_type in PARSERS:
        raise ValueError(f"Try to register an existing parser '{scan_type}'")
    PARSERS[scan_type] = parser


def get_parser(scan_type):
    """Return a parser by the scan type"""
    if scan_type not in PARSERS:
        raise ValueError(f"Parser '{scan_type}' does not exists")
    rg = re.compile(settings.PARSER_EXCLUDE)
    if not rg.match(scan_type) or settings.PARSER_EXCLUDE.strip() == "":
        # update DB dynamicaly
        test_type, _ = Test_Type.objects.get_or_create(name=scan_type)
        if test_type.active:
            return PARSERS[scan_type]
    raise ValueError(f"Parser {scan_type} is not active")


def get_scan_types_sorted():
    res = list()
    for key in PARSERS:
        res.append((key, PARSERS[key].get_description_for_scan_types(key)))
    return sorted(tuple(res), key=lambda x: x[0].lower())


def get_choices_sorted():
    res = list()
    for key in PARSERS:
        res.append((key, key))
    return sorted(tuple(res), key=lambda x: x[1].lower())


def requires_file(scan_type):
    if scan_type not in PARSERS:
        return False
    parser = PARSERS[scan_type]
    if hasattr(parser, "requires_file"):
        return parser.requires_file(scan_type)
    return False


def requires_tool_type(scan_type):
    if scan_type not in PARSERS:
        return None
    parser = PARSERS[scan_type]
    if hasattr(parser, "requires_tool_type"):
        return parser.requires_tool_type(scan_type)
    return None


import os
from inspect import isclass
from pathlib import Path
from importlib import import_module
from importlib.util import find_spec

# iterate through the modules in the current package
package_dir = str(Path(__file__).resolve().parent)
for module_name in os.listdir(package_dir):
    # check if it's dir
    if os.path.isdir(os.path.join(package_dir, module_name)):
        try:
            # check if it's a Python module
            if find_spec(f"dojo.tools.{module_name}.parser"):
                # import the module and iterate through its attributes
                module = import_module(f"dojo.tools.{module_name}.parser")
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isclass(attribute) and attribute_name.lower() == module_name.replace("_", "") + "parser":
                        register(attribute)
        except:
            logging.exception(f"failed to load {module_name}")
