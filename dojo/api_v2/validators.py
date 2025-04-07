from django.core.validators import RegexValidator
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class RegexValidatorCustom(RegexValidator):
    def __call__(self, value):
        try:
            return super().__call__(value)
        except Exception as e:
            logger.error(f"Validation failed for value: '{value}' with regex: '{self.regex.pattern}'")
            raise e


valid_chars_validator = RegexValidatorCustom(
    regex=r"" + settings.REGEX_VALIDATION_NAME,
    message="The name can only contain letters, numbers"
)
