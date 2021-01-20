
PARSERS = {}


def register_parser(scan_type, parser):
    if scan_type in PARSERS:
        raise ValueError('Unknown Test Type')
    else:
        PARSERS[scan_type] = parser


def import_parser_factory(file, test, active, verified, scan_type=None):
    """Return a parser by the scan type
    This fucntion exists only for backward compatibility
    """
    if scan_type in PARSERS:
        return PARSERS[scan_type]
    else:
        raise ValueError('Unknown Test Type')
