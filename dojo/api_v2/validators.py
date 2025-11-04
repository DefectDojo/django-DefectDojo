import re
import logging
from dojo.models import GeneralSettings
from django.forms import ValidationError

logger = logging.getLogger(__name__)

class CharacterValidation():
    def __call__(self, value):
        special_char_regex = GeneralSettings.get_value('REGEX_VALIDATION_NAME', '^.*$') 
        
        if re.search(special_char_regex, value):
            raise ValidationError("The name cannot contain special characters like < > & ( ) { } ; : [ ] '")

        return value  

valid_chars_validator = CharacterValidation()