import re

from django.contrib.auth.password_validation import CommonPasswordValidator
from django.core.exceptions import ValidationError
from django.utils.translation import gettext

from dojo.utils import get_system_setting


class MinLengthValidator:
    def validate(self, password, user=None):
        if len(password) < get_system_setting("minimum_password_length"):
            raise ValidationError(
                self.get_help_text(),
                code="password_too_short")
        return

    def get_help_text(self):
        return gettext("Password must be at least %s characters long.") % get_system_setting("minimum_password_length")


class MaxLengthValidator:
    def validate(self, password, user=None):
        if len(password) > get_system_setting("maximum_password_length"):
            raise ValidationError(
                self.get_help_text(),
                code="password_too_short")
        return

    def get_help_text(self):
        return gettext("Password must be less than %s characters long.") % get_system_setting("maximum_password_length")


class NumberValidator:
    def validate(self, password, user=None):
        if not re.findall(r"\d", password) and get_system_setting("number_character_required"):
            raise ValidationError(
                self.get_help_text(),
                code="password_no_number")
        return

    def get_help_text(self):
        return gettext("Password must contain at least 1 digit, 0-9.")


class UppercaseValidator:
    def validate(self, password, user=None):
        if not re.findall("[A-Z]", password) and get_system_setting("uppercase_character_required"):
            raise ValidationError(
                self.get_help_text(),
                code="password_no_upper")
        return

    def get_help_text(self):
        return gettext("Password must contain at least 1 uppercase letter, A-Z.")


class LowercaseValidator:
    def validate(self, password, user=None):
        if not re.findall("[a-z]", password) and get_system_setting("lowercase_character_required"):
            raise ValidationError(
                self.get_help_text(),
                code="password_no_lower")
        return

    def get_help_text(self):
        return gettext("Password must contain at least 1 lowercase letter, a-z.")


class SymbolValidator:
    def validate(self, password, user=None):
        contains_special_character = re.findall(r'[(){}\[\]|~!@#$%^&*_\-+=;:\'",\`<>\./?]', password)
        if not contains_special_character and get_system_setting("special_character_required"):
            raise ValidationError(
                self.get_help_text(),
                code="password_no_symbol")
        return

    def get_help_text(self):
        return gettext("The password must contain at least 1 special character, "
            + """()[]{}|`~!@#$%^&*_-+=;:'",<>./?.""")


class DojoCommonPasswordValidator(CommonPasswordValidator):
    def validate(self, password, user=None):
        if get_system_setting("non_common_password_required"):
            return super().validate(password, user)
        return None
