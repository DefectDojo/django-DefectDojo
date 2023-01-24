import re

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext
from dojo.models import System_Settings


class MinLengthValidator(object):
    settings = System_Settings.objects.get()

    def validate(self, password, user=None):
        if len(password) < self.settings.minimum_password_length:
            raise ValidationError(
                ugettext('Password must be at least {minimum_length} characters long.'.format(
                    minimum_length=self.settings.minimum_password_length)),
                code='password_too_short')
        else:
            return None

    def get_help_text(self):
        return ugettext('Password must be at least {minimum_length} characters long.'.format(
            minimum_length=self.settings.minimum_password_length))


class MaxLengthValidator(object):
    settings = System_Settings.objects.get()

    def validate(self, password, user=None):
        if len(password) > self.settings.maximum_password_length:
            raise ValidationError(
                ugettext('Password must be less than {maximum_length} characters long.'.format(
                    maximum_length=self.settings.maximum_password_length)),
                code='password_too_short')
        else:
            return None

    def get_help_text(self):
        return ugettext('Password must be less than {maximum_length} characters long.'.format(
            maximum_length=self.settings.maximum_password_length))


class NumberValidator(object):
    settings = System_Settings.objects.get()

    def validate(self, password, user=None):
        if not re.findall('\d', password) and self.settings.number_character_required:  # noqa W605
            raise ValidationError(
                ugettext('Password must contain at least 1 digit, 0-9.'),
                code='password_no_number')
        else:
            return None

    def get_help_text(self):
        return ugettext('Password must contain at least 1 digit, 0-9.')


class UppercaseValidator(object):
    settings = System_Settings.objects.get()

    def validate(self, password, user=None):
        if not re.findall('[A-Z]', password) and self.settings.uppercase_character_required:
            raise ValidationError(
                ugettext('Password must contain at least 1 uppercase letter, A-Z.'),
                code='password_no_upper')
        else:
            return None

    def get_help_text(self):
        return ugettext('Password must contain at least 1 uppercase letter, A-Z.')


class LowercaseValidator(object):
    settings = System_Settings.objects.get()

    def validate(self, password, user=None):
        if not re.findall('[a-z]', password) and self.settings.lowercase_character_required:
            raise ValidationError(
                ugettext('Password must contain at least 1 lowercase letter, a-z.'),
                code='password_no_lower')
        else:
            return None

    def get_help_text(self):
        return ugettext('Password must contain at least 1 lowercase letter, a-z.')


class SymbolValidator(object):
    settings = System_Settings.objects.get()

    def validate(self, password, user=None):
        contains_special_character = re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'\",<>./?]', password)  # noqa W605
        if not contains_special_character and self.settings.special_character_required:
            raise ValidationError(
                ugettext('The password must contain at least 1 special character, ' +
                    '()[]{}|\`~!@#$%^&*_-+=;:\'\",<>./?.'),  # noqa W605
                code='password_no_symbol')
        else:
            return None

    def get_help_text(self):
        return ugettext('The password must contain at least 1 special character, ' +
            '()[]{}|\`~!@#$%^&*_-+=;:\'\",<>./?.'),  # noqa W605
