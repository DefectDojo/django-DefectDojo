import logging
import re
from collections.abc import Callable

from cvss import CVSS2, CVSS3, CVSS4
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


def tag_validator(value: str | list[str], exception_class: Callable = ValidationError) -> None:
    TAG_PATTERN = re.compile(r'[ ,\'"]')
    error_messages = []

    if isinstance(value, list):
        error_messages.extend(f"Invalid tag: '{tag}'. Tags should not contain spaces, commas, or quotes." for tag in value if TAG_PATTERN.search(tag))
    elif isinstance(value, str):
        if TAG_PATTERN.search(value):
            error_messages.append(f"Invalid tag: '{value}'. Tags should not contain spaces, commas, or quotes.")
    else:
        error_messages.append(f"Value must be a string or list of strings: {value} - {type(value)}.")

    if error_messages:
        logger.debug(f"Tag validation failed: {error_messages}")
        raise exception_class(error_messages)


def cvss3_validator(value: str | list[str], exception_class: Callable = ValidationError) -> None:
    logger.debug("cvss3_validator called with value: %s", value)
    from dojo.utils import parse_cvss_from_text
    cvss_vectors = parse_cvss_from_text(value)
    if len(cvss_vectors) > 0:
        vector_obj = cvss_vectors[0]

        if isinstance(vector_obj, CVSS3):
            # all is good
            return

        if isinstance(vector_obj, CVSS4):
            msg = "CVSS4 vector cannot be stored in the cvssv3 field. Use the cvssv4 field."
            raise exception_class(msg)
        if isinstance(vector_obj, CVSS2):
            msg = "Unsupported CVSS2 version detected."
            raise exception_class(msg)

        msg = "Unsupported CVSS version detected."
        raise exception_class(msg)

    # Explicitly raise an error if no CVSS vectors are found,
    # to avoid 'NoneType' errors during severity processing later.
    msg = "No valid CVSS3 vectors found by cvss.parse_cvss_from_text()"
    raise exception_class(msg)


def cvss4_validator(value: str | list[str], exception_class: Callable = ValidationError) -> None:
    logger.debug("cvss4_validator called with value: %s", value)
    from dojo.utils import parse_cvss_from_text
    cvss_vectors = parse_cvss_from_text(value)
    if len(cvss_vectors) > 0:
        vector_obj = cvss_vectors[0]

        if isinstance(vector_obj, CVSS4):
            # all is good
            return

        if isinstance(vector_obj, CVSS3):
            msg = "CVSS3 vector cannot be stored in the cvssv4 field. Use the cvssv3 field."
            raise exception_class(msg)
        if isinstance(vector_obj, CVSS2):
            msg = "Unsupported CVSS2 version detected."
            raise exception_class(msg)

        msg = "Unsupported CVSS version detected."
        raise exception_class(msg)

    # Explicitly raise an error if no CVSS vectors are found,
    # to avoid 'NoneType' errors during severity processing later.
    msg = "No valid CVSS4 vectors found by cvss.parse_cvss_from_text()"
    raise exception_class(msg)
