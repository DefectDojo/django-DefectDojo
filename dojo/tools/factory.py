import logging
from dojo.models import Test_Type, Tool_Type

PARSERS = {}
# TODO remove that
SCAN_SONARQUBE_API = 'SonarQube API Import'


def register(parser_type):
    for scan_type in parser_type().get_scan_types():
        parser = parser_type()
        if scan_type.endswith('detailed'):
            parser.set_mode('detailed')
        register_parser(scan_type, parser)


def register_parser(scan_type, parser):
    logging.debug(f"register scan_type:{scan_type} with parser:{parser}")
    # check double registration or registration with an existing key
    if scan_type in PARSERS:
        raise ValueError(f"Try to register an existing parser '{scan_type}'")
    PARSERS[scan_type] = parser


def import_parser_factory(file, test, active, verified, scan_type=None):
    """Return a parser by the scan type
    This function exists only for backward compatibility
    """
    if scan_type in PARSERS:
        # create dynamicaly in DB
        test_type, created = Test_Type.objects.get_or_create(name=scan_type)
        if created:
            test_type.save()
        return PARSERS[scan_type]
    else:
        raise ValueError(f'Unknown Test Type {scan_type}')


def get_disabled_scanners():
    scanners = []
    try:
        disabled = Tool_Type.objects.all().filter(enabled=False)
        for scanner in disabled:
            scanners.append(scanner.name.lower())
    except Exception as e:
        logging.warning("Empty Tool_Type table, run: ./manage dump_scanner_list -r")
    return scanners


def get_choices():
    res = list()
    disabled = get_disabled_scanners()
    for key in PARSERS.keys():
        if key.lower() not in disabled:
            res.append((key, PARSERS[key].get_label_for_scan_types(key)))
    return tuple(res)


def requires_file(scan_type):
    if scan_type is None or scan_type not in PARSERS:
        return False
    # FIXME switch to method of the parser
    # parser = PARSERS[scan_type]
    return scan_type != SCAN_SONARQUBE_API


import os
from inspect import isclass
from pkgutil import iter_modules
from pathlib import Path
from importlib import import_module

# iterate through the modules in the current package
package_dir = Path(__file__).resolve().parent
for (path, module_name, _) in iter_modules([package_dir]):
    # check if it's submodule
    if os.path.isdir(os.path.join(package_dir, module_name)):
        try:
            # import the module and iterate through its attributes
            module = import_module(f"dojo.tools.{module_name}.parser")
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                if isclass(attribute) and attribute_name.lower() == module_name.replace("_", "") + 'parser':
                    register(attribute)
        except:
            logging.exception(f"failed to load {module_name}")
