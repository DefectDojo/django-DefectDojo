from django.conf import settings
from django.core.checks import Error
from django.core.checks import Warning as CheckWarning


def check_configuration_deduplication(app_configs, **kwargs):
    errors = []
    for scanner in settings.HASHCODE_FIELDS_PER_SCANNER:
        errors.extend(Error(
                f"Configuration error in HASHCODE_FIELDS_PER_SCANNER: Element {field} is not in the allowed list HASHCODE_ALLOWED_FIELDS for {scanner}.",
                hint=f'Check configuration ["HASHCODE_FIELDS_PER_SCANNER"]["{scanner}"] value',
                obj=settings.HASHCODE_FIELDS_PER_SCANNER[scanner],
                id="dojo.E001",
            ) for field in settings.HASHCODE_FIELDS_PER_SCANNER.get(scanner)
                if field not in settings.HASHCODE_ALLOWED_FIELDS)

    # A hash-field list only takes effect for an algorithm that computes a hash. A scan type
    # registered in HASHCODE_FIELDS_PER_SCANNER but missing from DEDUPLICATION_ALGORITHM_PER_PARSER
    # falls back to the legacy algorithm, which ignores hash_code when matching -- so the curated
    # field list silently does nothing. That is how "Burp Suite DAST" (a name no parser produces,
    # keyed alongside the correctly-named algorithm entry "Burp Suite DAST Scan") went unnoticed:
    # the two halves of the registration disagreed and neither half applied.
    #
    # This is a Warning rather than an Error because DD_HASHCODE_FIELDS_PER_SCANNER lets an
    # installation add its own entries, and a system check that hard-fails would turn a
    # questionable local override into a failed deployment.
    errors.extend(CheckWarning(
            f"Configuration error in HASHCODE_FIELDS_PER_SCANNER: {scanner} has a hash_code field list "
            f"but no entry in DEDUPLICATION_ALGORITHM_PER_PARSER, so it deduplicates with the legacy "
            f"algorithm and the field list has no effect.",
            hint=f'Add "{scanner}" to DEDUPLICATION_ALGORITHM_PER_PARSER, or remove its HASHCODE_FIELDS_PER_SCANNER entry. '
                 f"If the scan type name is a typo, findings imported under the real name are hashing with the legacy algorithm.",
            obj=settings.HASHCODE_FIELDS_PER_SCANNER[scanner],
            id="dojo.W001",
        ) for scanner in settings.HASHCODE_FIELDS_PER_SCANNER
            if scanner not in settings.DEDUPLICATION_ALGORITHM_PER_PARSER)

    return errors
