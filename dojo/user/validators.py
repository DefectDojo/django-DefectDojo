import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext
from django.contrib.auth.password_validation import CommonPasswordValidator
from dojo.utils import get_system_setting


class MinLengthValidator(object):
    def validate(self, password, user=None):
        if len(password) < get_system_setting('minimum_password_length'):
            raise ValidationError(
                self.get_help_text(),
                code='password_too_short')
        else:
            return None

    def get_help_text(self):
        return gettext('Password must be at least {minimum_length} characters long.'.format(
            minimum_length=get_system_setting('minimum_password_length')))


class MaxLengthValidator(object):
    def validate(self, password, user=None):
        if len(password) > get_system_setting('maximum_password_length'):
            raise ValidationError(
                self.get_help_text(),
                code='password_too_short')
        else:
            return None

    def get_help_text(self):
        return gettext('Password must be less than {maximum_length} characters long.'.format(
            maximum_length=get_system_setting('maximum_password_length')))


class NumberValidator(object):
    def validate(self, password, user=None):
        if not re.findall('\d', password) and get_system_setting('number_character_required'):  # noqa W605
            raise ValidationError(
                self.get_help_text(),
                code='password_no_number')
        else:
            return None

    def get_help_text(self):
        return gettext('Password must contain at least 1 digit, 0-9.')


class UppercaseValidator(object):
    def validate(self, password, user=None):
        if not re.findall('[A-Z]', password) and get_system_setting('uppercase_character_required'):
            raise ValidationError(
                self.get_help_text(),
                code='password_no_upper')
        else:
            return None

    def get_help_text(self):
        return gettext('Password must contain at least 1 uppercase letter, A-Z.')


class LowercaseValidator(object):
    def validate(self, password, user=None):
        if not re.findall('[a-z]', password) and get_system_setting('lowercase_character_required'):
            raise ValidationError(
                self.get_help_text(),
                code='password_no_lower')
        else:
            return None

    def get_help_text(self):
        return gettext('Password must contain at least 1 lowercase letter, a-z.')


class SymbolValidator(object):
    def validate(self, password, user=None):
        contains_special_character = re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'\",<>./?]', password)  # noqa W605
        if not contains_special_character and get_system_setting('special_character_required'):
            raise ValidationError(
                self.get_help_text(),
                code='password_no_symbol')
        else:
            return None

    def get_help_text(self):
        return gettext('The password must contain at least 1 special character, ' +
            '()[]{}|\`~!@#$%^&*_-+=;:\'\",<>./?.')  # noqa W605


class DojoCommonPasswordValidator(CommonPasswordValidator):
    def validate(self, password, user=None):
        if get_system_setting('non_common_password_required'):
            return super().validate(password, user)
        else:
            return None
