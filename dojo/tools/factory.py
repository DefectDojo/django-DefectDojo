import logging
from dojo.models import Test_Type

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


def get_choices():
    res = list()
    for key in PARSERS:
        res.append((key, key))
    return tuple(res)


def requires_file(scan_type):
    if scan_type is None or scan_type not in PARSERS:
        return False
    # FIXME switch to method of the parser
    # parser = PARSERS[scan_type]
    return scan_type != SCAN_SONARQUBE_API


def handles_active_verified_statuses(scan_type):
    # FIXME switch to method of the parser
    # parser = PARSERS[scan_type]
    return scan_type in [
        'Generic Findings Import', SCAN_SONARQUBE_API, 'Qualys Scan'
    ]


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
