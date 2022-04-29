from django.conf import settings
from django.core.checks import Error


def check_configuration_deduplication(app_configs, **kwargs):
    errors = []
    for scanner in settings.HASHCODE_FIELDS_PER_SCANNER:
        for field in settings.HASHCODE_FIELDS_PER_SCANNER.get(scanner):
            if field not in settings.HASHCODE_ALLOWED_FIELDS:
                errors.append(
                    Error(
                        f"Configuration error in HASHCODE_FIELDS_PER_SCANNER: Element {field} is not in the allowed list HASHCODE_ALLOWED_FIELDS for {scanner}.",
                        hint=f'Check configuration ["HASHCODE_FIELDS_PER_SCANNER"]["{scanner}"] value',
                        obj=settings.HASHCODE_FIELDS_PER_SCANNER[scanner],
                        id="dojo.E001",
                    )
                )
    return errors
