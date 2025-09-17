from django.core.exceptions import ValidationError


def validate_not_empty(value: str) -> None:
    """Validate that the value is not an empty string."""
    if not value.strip():
        msg = "This field cannot be empty."
        raise ValidationError(msg)


def no_spaces(value: str) -> None:
    """Validate that raises a ValidationError if the input string contains spaces."""
    if " " in value:
        msg = "This field cannot contain spaces."
        raise ValidationError(msg)


def no_colons(value: str) -> None:
    """Validate that raises a ValidationError if the input string contains colons."""
    if ":" in value:
        msg = "This field cannot contain colons."
        raise ValidationError(msg)


def only_lowercase(value: str) -> None:
    """Validate that raises a ValidationError if the input string contains any uppercase letters."""
    if not value.islower():
        msg = "This field must contain only lowercase letters."
        raise ValidationError(msg)
