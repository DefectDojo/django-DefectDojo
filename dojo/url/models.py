from __future__ import annotations

from contextlib import suppress
from urllib.parse import ParseResult, urlparse

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db.models import BooleanField, CharField, Index, PositiveIntegerField

# Ignoring the N811 error as this is an external library and we cannot change its name
# We are already using "URL" in our own code so we need to alias this import
from hyperlink import URL as HyperlinkURL  # noqa: N811

from dojo.base_models.validators import validate_not_empty
from dojo.location.models import AbstractLocation
from dojo.url.manager import URLManager, URLQueryset
from dojo.url.validators import (
    DEFAULT_PORTS,
    validate_fragment,
    validate_protocol,
    validate_query,
    validate_user_info,
)


class URL(AbstractLocation):

    """Meta class for the URL model."""

    LOCATION_TYPE = "url"

    protocol = CharField(
        max_length=10,
        blank=True,
        default="",
        validators=[validate_protocol],
        help_text="The protocol of the URL (e.g., http, https, ftp, etc.)",
    )
    user_info = CharField(
        max_length=512,
        blank=True,
        default="",
        validators=[validate_user_info],
        help_text="Connection details for a given user",
    )
    host = CharField(
        max_length=256,
        null=False,
        blank=False,
        validators=[
            # The previous endpoint model allowed for so many things such as container references,
            # AWS resources, and many other wild things. We cannot be so strict in phase one of
            # this migration because we do not want to negatively impact user data.
            # validate_host_or_ip,
            validate_not_empty,
        ],
        help_text="The host of the URL, which can be a domain name or an IP address",
    )
    port = PositiveIntegerField(
        validators=[
            MinValueValidator(1),
            MaxValueValidator(65535),
        ],
        blank=True,
        null=True,
        help_text="The port number of the URL (optional)",
    )
    path = CharField(
        max_length=2048,
        blank=True,
        default="",
        help_text="The path of the URL (optional),",
    )
    query = CharField(
        max_length=2048,
        blank=True,
        default="",
        validators=[validate_query],
        help_text="The query string of the URL (optional)",
    )
    fragment = CharField(
        max_length=2048,
        blank=True,
        default="",
        validators=[validate_fragment],
        help_text="The fragment identifier of the URL (optional)",
    )
    host_validation_failure = BooleanField(
        default=False,
        blank=False,
        help_text="Dictates whether the endpoint was found to have host validation issues during creation")

    objects = URLManager().from_queryset(URLQueryset)()

    class Meta:

        verbose_name = "Locations - URL"
        verbose_name_plural = "Locations - URLs"
        indexes = (Index(fields=["host"]),)

    def __str__(self) -> str:
        """Return the string representation of a URL."""
        value = ""
        # Protocol
        if self.protocol is not None and len(self.protocol) > 0:
            value += f"{self.protocol}://"
        # Host will always be present
        value += self.host
        # Port
        if self.port is not None and self.port > 0:
            value += f":{self.port}"
        # Path will always be present (default to '/')
        if self.path is not None and len(self.path) > 0:
            value += f"/{self.path.lstrip('/')}"
        # Query
        if self.query is not None and len(self.query) > 0:
            value += f"?{self.query}"
        # Fragment
        if self.fragment is not None and len(self.fragment) > 0:
            value += f"#{self.fragment}"
        with suppress(Exception):
            # Run this through the URL parser to ensure it is valid
            return HyperlinkURL.from_text(value).to_text()
        return value

    @classmethod
    def get_location_type(cls) -> str:
        return cls.LOCATION_TYPE

    def get_location_value(self) -> str:
        return str(self)

    def pre_save_logic(self) -> None:
        """Allow for some pre save operations by other classes."""
        # Set default port based on protocol if not provided
        if not self.port:
            self.port = DEFAULT_PORTS.get(self.protocol, None)
        super().pre_save_logic()

    @staticmethod
    def _parse_string_value(value: str) -> ParseResult | None:
        """Internal method to parse the string representation of the model"""
        # If there is anything invalid here, an exception will be raised
        return urlparse(value)

    def clean(self, *args: list, **kwargs: dict) -> None:
        """Validate the input supplied."""
        super().clean(*args, **kwargs)
        # Ensure the full value is correctly parsable. If not, an exception will be raised
        URL._parse_string_value(str(self))

    @staticmethod
    def create_location_from_value(value: str) -> URL:
        """Parse a string URL and return the resulting *persisted* URL Model."""
        url = URL.from_value(value)
        url.save()
        return url

    @staticmethod
    def from_value(value: str) -> URL:
        """Parse a string URL and return the resulting *unsaved* URL Model."""
        # Parse the supplied input
        parsed_url = URL._parse_string_value(value)
        # Create the initial object, assuming no exceptions are thrown
        return URL(
            protocol=parsed_url.scheme,
            host=parsed_url.hostname,
            port=parsed_url.port or DEFAULT_PORTS.get(parsed_url.scheme, None),
            path=parsed_url.path.lstrip("/"),
            query=parsed_url.query,
            fragment=parsed_url.fragment,
        )
