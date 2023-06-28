import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext
from dojo.models import System_Settings
from django.contrib.auth.password_validation import CommonPasswordValidator


class MinLengthValidator(object):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        if len(password) < self.settings.minimum_password_length:
            raise ValidationError(
                self.get_help_text(), code="password_too_short"
            )
        else:
            return None

    def get_help_text(self):
        return gettext(
            "Password must be at least {minimum_length} characters long.".format(
                minimum_length=self.settings.minimum_password_length
            )
        )


class MaxLengthValidator(object):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        if len(password) > self.settings.maximum_password_length:
            raise ValidationError(
                self.get_help_text(), code="password_too_short"
            )
        else:
            return None

    def get_help_text(self):
        return gettext(
            "Password must be less than {maximum_length} characters long.".format(
                maximum_length=self.settings.maximum_password_length
            )
        )


class NumberValidator(object):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        if (
            not re.findall(r"\d", password)
            and self.settings.number_character_required
        ):
            raise ValidationError(
                self.get_help_text(), code="password_no_number"
            )
        else:
            return None

    def get_help_text(self):
        return gettext("Password must contain at least 1 digit, 0-9.")


class UppercaseValidator(object):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        if (
            not re.findall("[A-Z]", password)
            and self.settings.uppercase_character_required
        ):
            raise ValidationError(
                self.get_help_text(), code="password_no_upper"
            )
        else:
            return None

    def get_help_text(self):
        return gettext(
            "Password must contain at least 1 uppercase letter, A-Z."
        )


class LowercaseValidator(object):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        if (
            not re.findall("[a-z]", password)
            and self.settings.lowercase_character_required
        ):
            raise ValidationError(
                self.get_help_text(), code="password_no_lower"
            )
        else:
            return None

    def get_help_text(self):
        return gettext(
            "Password must contain at least 1 lowercase letter, a-z."
        )


class SymbolValidator(object):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        contains_special_character = re.findall(
            r"[()[\]{}|\\`~!@#$%^&*_\-+=;:\'\",<>./?]", password
        )
        if (
            not contains_special_character
            and self.settings.special_character_required
        ):
            raise ValidationError(
                self.get_help_text(), code="password_no_symbol"
            )
        else:
            return None

    def get_help_text(self):
        return (
            gettext(
                "The password must contain at least 1 special character, "
                + "()[]{}|\\`~!@#$%^&*_-+=;:'\",<>./?."
            ),
        )  # noqa W605


class DojoCommonPasswordValidator(CommonPasswordValidator):
    def validate(self, password, user=None):
        self.settings = System_Settings.objects.get()
        if self.settings.non_common_password_required:
            return super().validate(password, user)
        else:
            return None
