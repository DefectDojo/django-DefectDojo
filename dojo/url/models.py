from __future__ import annotations

import hashlib
import ipaddress
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import unquote_plus, urlsplit

import idna
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinLengthValidator, MinValueValidator
from django.db import IntegrityError, transaction
from django.db.models import (
    BooleanField,
    CharField,
    Index,
    PositiveIntegerField,
)

# Ignoring the N811 error as this is an external library and we cannot change its name
# We are already using "URL" in our own code so we need to alias this import
from hyperlink import URL as HyperlinkURL  # noqa: N811
from hyperlink import URLParseError

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


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    protocol: str
    user_info: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str


class HyperlinkParser:
    def from_text(self, value):
        try:
            return HyperlinkURL.from_text(value).normalize()
        except URLParseError as e:
            raise ValidationError(str(e))

    def parse(self, value: str) -> ParsedUrl:
        parsed_url = self.from_text(value)

        # A host value is required by the URL class. If we're not provided one, it's possible we can coerce things if
        # no scheme was included by making it a scheme-relative URL.
        if not parsed_url.host:
            if parsed_url.scheme:
                error_message = f"No host provided in URL: {parsed_url}"
                raise ValidationError(error_message)
            # Reparse, forcing an unwhackunwhack, and recheck
            parsed_url = self.from_text(f"//{value}")
            if not parsed_url.host:
                # Nothing can be done!
                error_message = f"No host provided in URL: {parsed_url}"
                raise ValidationError(error_message)

        if parsed_url.port is not None and (parsed_url.port < 1 or parsed_url.port > 65535):
            error_message = f"Invalid port: {parsed_url.port}"
            raise ValidationError(error_message)

        return ParsedUrl(
            raw=value,
            protocol=parsed_url.scheme,
            user_info=parsed_url.userinfo,
            host=parsed_url.host,
            port=parsed_url.port,
            path="/".join(parsed_url.path),
            query=unquote_plus(urlsplit(parsed_url.to_text()).query),
            fragment=parsed_url.fragment,
        )

    def unparse(self, url: URL) -> str:
        # path/query are stored as flat text; parse them with Hyperlink
        parsed_path_and_query = HyperlinkURL.from_text(f"{url.path}?{url.query}").normalize()

        # Hyperlink assumes the host field is a domain name, and explodes when encoding an IP or something that's not
        # quite a valid hostname but Dojo allows anyway. Check if it's one of such explosion-causing cases to determine
        # whether we should be sneaky and substitute in the hostname manually after the fact.
        unparse_host = True
        try:
            idna.encode(url.host, uts46=True)
        except idna.IDNAError:
            unparse_host = False

        normalized = HyperlinkURL(
            scheme=url.protocol,
            userinfo=url.user_info,
            host=url.host if unparse_host else "",
            port=url.port,
            path=parsed_path_and_query.path,
            rooted=False,
            query=parsed_path_and_query.query,
            fragment=url.fragment,
        # path not normalized if empty, in line with the way Endpoints worked
        ).normalize(path=bool(url.path)).to_uri()

        if not unparse_host:
            normalized = normalized.replace(host=url.host)

        return normalized.to_text().removeprefix("//")


class URL(AbstractLocation):

    LOCATION_TYPE = "url"
    URL_PARSING_CLASS = HyperlinkParser

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
        help_text="Dictates whether the endpoint was found to have host validation issues during creation",
    )
    hash = CharField(
        null=False,
        blank=False,
        max_length=64,
        editable=False,
        unique=True,
        validators=[MinLengthValidator(64)],
        help_text="The hash of the URL for uniqueness",
    )

    objects = URLManager().from_queryset(URLQueryset)()

    class Meta:

        """Metaclass for the URL model."""

        verbose_name = "Locations - URL"
        verbose_name_plural = "Locations - URLs"
        indexes = (Index(fields=["host", "hash"]),)

    def manual_str(self):
        value = ""
        # Protocol
        if self.protocol:
            value += f"{self.protocol}://"
        # User info
        if self.user_info:
            value += f"{self.user_info}@"
        # Host will always be present
        value += self.host
        # Port
        if self.port is not None and self.port > 0:
            value += f":{self.port}"
        # Path will always be present (default to '/')
        if self.path:
            value += f"/{self.path.lstrip('/')}"
        # Query
        if self.query:
            value += f"?{self.query}"
        # Fragment
        if self.fragment:
            value += f"#{self.fragment}"
        return value

    def __str__(self) -> str:
        """Return the string representation of a URL."""
        with suppress(Exception):
            return URL.URL_PARSING_CLASS().unparse(self)
        return self.manual_str()

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, URL) and str(self) == str(other)

    @classmethod
    def get_location_type(cls) -> str:
        return cls.LOCATION_TYPE

    def get_location_value(self) -> str:
        return str(self)[:2048]

    @staticmethod
    def _parse_string_value(value: str) -> ParsedUrl:
        """Internal method to parse the string representation of the model"""
        return URL.URL_PARSING_CLASS().parse(value)

    def clean(self, *args: list, **kwargs: dict) -> None:
        """Validate the input supplied."""
        self.clean_protocol()
        self.clean_user_info()
        self.clean_host()
        self.clean_port()
        self.clean_path()
        self.clean_query()
        self.clean_fragment()
        self.set_db_hash()
        super().clean(*args, **kwargs)

    def clean_protocol(self) -> None:
        if not self.protocol:
            self.protocol = ""
        else:
            self.protocol = self.protocol.lower()

    def clean_user_info(self):
        if not self.user_info:
            self.user_info = ""
        else:
            self.user_info = self.replace_null_bytes(self.user_info.strip())

    def clean_host(self) -> None:
        self.host_validation_failure = False
        if not self.host:
            self.host = ""
        else:
            try:
                # Check if it's a valid IP address first
                self.host = ipaddress.ip_address(self.host).compressed
            except ValueError:
                try:
                    # Attempt to depunify the hostname
                    self.host = idna.encode(self.host, uts46=True).decode("ascii")
                except idna.IDNAError:
                    # Some issue with the hostname exists. We'll store it, but are DEFINITELY making a note of this.
                    self.host = self.replace_null_bytes(self.host.lower())
                    self.host_validation_failure = True

    def clean_port(self) -> None:
        if not bool(self.port):
            # Set default port based on protocol if not provided
            self.port = DEFAULT_PORTS.get(self.protocol, None)
        elif isinstance(self.port, str):
            try:
                self.port = int(self.port)
            except ValueError:
                error_message = f"Invalid port: {self.port}"
                raise ValidationError(error_message)

    def clean_path(self):
        if not self.path:
            self.path = ""
        else:
            self.path = self.replace_null_bytes(self.path.strip().removeprefix("/"))

    def clean_fragment(self) -> None:
        if not self.fragment:
            self.fragment = ""
        else:
            self.fragment = self.replace_null_bytes(self.fragment.strip().removeprefix("#"))

    def clean_query(self) -> None:
        if not self.query:
            self.query = ""
        else:
            self.query = self.replace_null_bytes(self.query.strip().removeprefix("?"))

    def set_db_hash(self):
        self.hash = hashlib.blake2b(str(self).encode(), digest_size=32).hexdigest()

    def replace_null_bytes(self, value: str) -> str:
        return value.replace("\x00", "%00")

    @staticmethod
    def get_or_create_from_object(url: URL) -> URL:
        url.clean()
        with transaction.atomic():
            try:
                return URL.objects.get_or_create(
                    hash=url.hash,
                    defaults={
                        "protocol": url.protocol,
                        "user_info": url.user_info,
                        "host": url.host,
                        "port": url.port,
                        "path": url.path,
                        "query": url.query,
                        "fragment": url.fragment,
                        "host_validation_failure": url.host_validation_failure,
                    },
                )[0]
            except IntegrityError:
                return URL.objects.get(hash=url.hash)

    @staticmethod
    def get_or_create_from_values(
        protocol=None,
        user_info=None,
        host=None,
        port=None,
        path=None,
        query=None,
        fragment=None,
    ) -> URL:
        url = URL(
            protocol=protocol,
            user_info=user_info,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
        )
        return URL.get_or_create_from_object(url)

    @staticmethod
    def create_location_from_value(value: str) -> URL:
        """Parse a string URL and return the resulting *persisted* URL Model."""
        unsaved_url = URL.from_value(value)
        return URL.get_or_create_from_object(unsaved_url)

    @staticmethod
    def from_value(value: str) -> URL:
        """Parse a string URL and return the resulting *unsaved* URL Model."""
        # Parse the supplied input

        parsed_url = URL._parse_string_value(value)

        path = parsed_url.path.removeprefix("/")[:2048]
        query = parsed_url.query.removeprefix("?")[:2048]
        fragment = parsed_url.fragment.removeprefix("#")[:2048]

        # Create the initial object, assuming no exceptions are thrown
        url = URL(
            protocol=parsed_url.protocol,
            user_info=parsed_url.user_info,
            host=parsed_url.host,
            port=parsed_url.port,
            path=path,
            query=query,
            fragment=fragment,
        )
        url.clean()
        return url
