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


# The values docker-compose.yml falls back to when DD_SECRET_KEY / DD_CREDENTIAL_AES_256_KEY are not set,
# plus the empty settings.dist defaults. They are public, so an instance running on them is running on
# keys anyone can read.
SHIPPED_SECRET_KEYS = frozenset({"hhZCp@D28z!n@NED*yB!ROMt+WzsY*iq"})
SHIPPED_CREDENTIAL_KEYS = frozenset({"&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw", "."})


def check_configuration_defaults(app_configs, **kwargs):
    """
    Warn about deployment settings left at their shipped values.

    Warnings rather than errors: an existing instance encrypted its stored credentials with
    the key it has, so forcing a new one would make those credentials unreadable. The hint
    says what to change; the deployment decides when.
    """
    warnings = []
    if getattr(settings, "SECRET_KEY", None) in SHIPPED_SECRET_KEYS:
        warnings.append(CheckWarning(
            "DD_SECRET_KEY is the value shipped in docker-compose.yml.",
            hint="Set DD_SECRET_KEY to a long random value. Changing it signs users out and invalidates password reset links.",
            id="dojo.W002",
        ))
    if getattr(settings, "CREDENTIAL_AES_256_KEY", None) in SHIPPED_CREDENTIAL_KEYS:
        warnings.append(CheckWarning(
            "DD_CREDENTIAL_AES_256_KEY is the value shipped with DefectDojo.",
            hint="Set DD_CREDENTIAL_AES_256_KEY to a random 32-character value on a new instance. On an existing instance, "
                 "stored tool configuration passwords are encrypted with the current key and must be re-entered after changing it.",
            id="dojo.W003",
        ))
    if not getattr(settings, "DEBUG", False) and "*" in getattr(settings, "ALLOWED_HOSTS", ()):
        warnings.append(CheckWarning(
            "DD_ALLOWED_HOSTS contains '*'.",
            hint="List the host names the instance is served under, for example DD_ALLOWED_HOSTS=defectdojo.example.com.",
            id="dojo.W004",
        ))
    return warnings
