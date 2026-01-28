from __future__ import annotations

import re
from contextlib import suppress

from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address


def validate_protocol(value: str) -> None:
    """Validate that the protocol for a given protocol is captured."""
    if value not in DEFAULT_PORTS:
        msg = f"{value} is not a supported protocol"
        raise ValidationError(msg)


def validate_query(value: str) -> None:
    """Validate that the query does not start with "?"."""
    if value.startswith("?"):
        msg = "Query cannot begin with a '?'"
        raise ValidationError(msg)


def validate_fragment(value: str) -> None:
    """Validate that the fragment does not start with "#"."""
    if value.startswith("#"):
        msg = "Query cannot begin with a '#'"
        raise ValidationError(msg)


def validate_host_or_ip(value: str) -> None:
    """Validate if the input string is a valid URL, host (with or without a port), or IP address."""
    # Start with the IP address since it is more difficult to match
    with suppress(ValidationError):
        validate_ip(value)
        return
    # Try the host to see if that works
    with suppress(ValidationError):
        validate_host(value)
        return
    # Neither worked... Not much can be done here
    msg = "Host must be a alphanumeric, or a valid IPv4 or IPv6"
    raise ValidationError(msg)


def validate_user_info(value: str) -> False:
    """Validate the user info according to the spec."""
    if not re.compile(
        # https://tools.ietf.org/html/rfc3986#section-3.2.1
        r"^[A-Za-z0-9\.\-_~%\!\$&\'\(\)\*\+,;=:]+$",
    ).match(value):
        msg = "User info is not in the correct format"
        raise ValidationError(msg)


def validate_host(value: str) -> bool:
    """Validate a host without scheme and port."""
    if not re.compile(
        # Zero or more subdomains
        r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)*"
        # Final label (or single label if no dots)
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?|localhost)$",
    ).match(value):
        msg = "Host must be alphanumeric"
        raise ValidationError(msg)


def validate_ip(value: str) -> bool:
    """Validate an IP address (both IPv4 and IPv6)."""
    validate_ipv46_address(value)


# Helper to determine default port based on scheme
DEFAULT_PORTS = {
    "ftp": 21,
    "ssh": 22,
    "sftp": 22,  # sftp uses the same port as ssh
    "telnet": 23,
    "smtp": 25,
    "tftp": 69,
    "http": 80,
    "pop3": 110,
    "nntp": 119,
    "imap": 143,
    "ldap": 389,
    "https": 443,
    "smb": 445,
    "rtsp": 554,
    "nntps": 563,
    "smtps": 465,
    "submission": 587,
    "ldaps": 636,
    "ftps-data": 989,
    "ftps": 990,
    "imaps": 993,
    "pop3s": 995,
    "rdp": 3389,
    "vnc": 5900,
    "sip": 5060,
    "sips": 5061,
    "mqtt": 1883,  # Message Queuing Telemetry Transport, often used in IoT contexts
    "mqtts": 8883,  # Secure MQTT
    "openvpn": 1194,  # included for completeness, though it doesn't fit the URL scheme exactly
    "irc": 194,
    "tcp": None,
    # Empty string is used when the protocol is not specified, port is then assumed to be None as well
    "": None,
}
