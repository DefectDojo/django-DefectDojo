import logging
from dojo.models import Test_Type

PARSERS = {}
# TODO remove that
SCAN_SONARQUBE_API = 'SonarQube API Import'


def register_parser(scan_type, parser):
    logging.info(f"register scan_type:{scan_type}")
    # create dynamicaly in DB
    Test_Type.objects.get_or_create(name=scan_type)
    # check double registration or registration with an existing key
    if scan_type in PARSERS:
        raise ValueError(f'Try to register an existing parser {scan_type}')
    PARSERS[scan_type] = parser


def import_parser_factory(file, test, active, verified, scan_type=None):
    """Return a parser by the scan type
    This fucntion exists only for backward compatibility
    """
    if scan_type in PARSERS:
        return PARSERS[scan_type]
    else:
        raise ValueError(f'Unknown Test Type {scan_type}')


def get_choices():
    res = list()
    for key in PARSERS:
        res.append((key, key))
    return res


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
