import logging
from collections.abc import Callable

import cvss.parser
from cvss import CVSS2, CVSS3, CVSS4
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


def cvss3_validator(value: str | list[str], exception_class: Callable = ValidationError) -> None:
    logger.error("cvss3_validator called with value: %s", value)
    cvss_vectors = cvss.parser.parse_cvss_from_text(value)
    if len(cvss_vectors) > 0:
        vector_obj = cvss_vectors[0]

        if isinstance(vector_obj, CVSS3):
            # all is good
            return

        if isinstance(vector_obj, CVSS4):
            # CVSS4 is not supported yet by the parse_cvss_from_text function, but let's prepare for it anyway: https://github.com/RedHatProductSecurity/cvss/issues/53
            msg = "Unsupported CVSS(4) version detected."
            raise exception_class(msg)
        if isinstance(vector_obj, CVSS2):
            # CVSS2 is not supported yet by the parse_cvss_from_text function, but let's prepare for it anyway: https://github.com/RedHatProductSecurity/cvss/issues/53
            msg = "Unsupported CVSS(2) version detected."
            raise exception_class(msg)

        msg = "Unsupported CVSS version detected."
        raise exception_class(msg)

    # Explicitly raise an error if no CVSS vectors are found,
    # to avoid 'NoneType' errors during severity processing later.
    msg = "No CVSS vectors found by cvss.parse_cvss_from_text()"
    raise exception_class(msg)
