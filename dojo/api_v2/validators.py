from django.core.validators import RegexValidator
from django.conf import settings

valid_chars_validator = RegexValidator(
    regex=r"" + settings.REGEX_VALIDATION_NAME,
    message="The name can only contain letters, numbers"
)
