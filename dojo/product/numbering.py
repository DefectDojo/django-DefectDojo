"""Restricted, product-specific engagement number formats."""

import re

from django.core.exceptions import ValidationError

FORMAT_PATTERN = re.compile(r"[A-Za-z0-9._-]*\{number(?::0(?:1[0-6]|[1-9])d)?\}[A-Za-z0-9._-]*\Z")


def validate_engagement_number_format(value):
    if value and not FORMAT_PATTERN.fullmatch(value):
        msg = "Use one {number} or {number:0Nd} placeholder (width 1 to 16) with letters, digits, periods, underscores, or hyphens."
        raise ValidationError(msg)


def format_engagement_number(value, number):
    validate_engagement_number_format(value)
    return value.format(number=number)
