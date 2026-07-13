import contextlib
import logging
import re
from urllib.parse import urlparse

import hyperlink
from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from django.db import connection, models
from django.db.models import F, Q
from django.db.models.functions import Lower
from django.urls import reverse
from django.utils.translation import gettext as _
from tagulous.models import TagField

# get_current_date/get_current_datetime/copy_model_util are defined early in dojo.models,
# before the re-export that loads this module — resolves despite partial circular load.
# Must keep their dojo.models.* path for Django migration serialization.
from dojo.models import copy_model_util, get_current_date, get_current_datetime

logger = logging.getLogger(__name__)


class Endpoint_Params(models.Model):
    param = models.CharField(max_length=150)
    value = models.CharField(max_length=150)
    method_type = (("GET", "GET"),
                   ("POST", "POST"))
    method = models.CharField(max_length=20, blank=False, null=True, choices=method_type)


class Endpoint_Status(models.Model):
    date = models.DateField(default=get_current_date)
    last_modified = models.DateTimeField(null=True, editable=False, default=get_current_datetime)
    mitigated = models.BooleanField(default=False, blank=True)
    mitigated_time = models.DateTimeField(editable=False, null=True, blank=True)
    mitigated_by = models.ForeignKey("dojo.Dojo_User", editable=True, null=True, on_delete=models.RESTRICT)
    false_positive = models.BooleanField(default=False, blank=True)
    out_of_scope = models.BooleanField(default=False, blank=True)
    risk_accepted = models.BooleanField(default=False, blank=True)
    endpoint = models.ForeignKey("dojo.Endpoint", null=False, blank=False, on_delete=models.CASCADE, related_name="status_endpoint")
    finding = models.ForeignKey("dojo.Finding", null=False, blank=False, on_delete=models.CASCADE, related_name="status_finding")

    class Meta:
        indexes = [
            models.Index(fields=["finding", "mitigated"]),
            models.Index(fields=["endpoint", "mitigated"]),
            # Optimize frequent lookups of "active" statuses (mitigated/flags all False)
            models.Index(
                name="idx_eps_active_by_endpoint",
                fields=["endpoint"],
                condition=Q(mitigated=False, false_positive=False, out_of_scope=False, risk_accepted=False),
            ),
            models.Index(
                name="idx_eps_active_by_finding",
                fields=["finding"],
                condition=Q(mitigated=False, false_positive=False, out_of_scope=False, risk_accepted=False),
            ),
        ]
        constraints = [
            models.UniqueConstraint(fields=["finding", "endpoint"], name="endpoint-finding relation"),
        ]

    def __str__(self):
        with Endpoint.allow_endpoint_init():  # TODO: Delete this after the move to Locations
            return f"'{self.finding}' on '{self.endpoint}'"

    def copy(self, finding=None):
        copy = copy_model_util(self)
        current_endpoint = self.endpoint
        if finding:
            copy.finding = finding
        copy.endpoint = current_endpoint
        copy.save()

        return copy

    @property
    def age(self):

        diff = self.mitigated_time.date() - self.date if self.mitigated else get_current_date() - self.date
        days = diff.days
        return max(0, days)


class Endpoint(models.Model):
    protocol = models.CharField(null=True, blank=True, max_length=20,
                                 help_text=_("The communication protocol/scheme such as 'http', 'ftp', 'dns', etc."))
    userinfo = models.CharField(null=True, blank=True, max_length=500,
                              help_text=_("User info as 'alice', 'bob', etc."))
    host = models.CharField(null=True, blank=True, max_length=500,
                            help_text=_("The host name or IP address. It must not include the port number. "
                                      "For example '127.0.0.1', 'localhost', 'yourdomain.com'."))
    port = models.IntegerField(null=True, blank=True,
                               help_text=_("The network port associated with the endpoint."))
    path = models.CharField(null=True, blank=True, max_length=500,
                            help_text=_("The location of the resource, it must not start with a '/'. For example "
                                      "endpoint/420/edit"))
    query = models.CharField(null=True, blank=True, max_length=1000,
                             help_text=_("The query string, the question mark should be omitted."
                                       "For example 'group=4&team=8'"))
    fragment = models.CharField(null=True, blank=True, max_length=500,
                                help_text=_("The fragment identifier which follows the hash mark. The hash mark should "
                                          "be omitted. For example 'section-13', 'paragraph-2'."))
    product = models.ForeignKey("dojo.Product", null=True, blank=True, on_delete=models.CASCADE)
    endpoint_params = models.ManyToManyField("dojo.Endpoint_Params", blank=True, editable=False)
    findings = models.ManyToManyField("dojo.Finding",
                                      blank=True,
                                      verbose_name=_("Findings"),
                                      through="dojo.Endpoint_Status")

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this endpoint. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    class Meta:
        ordering = ["product", "host", "protocol", "port", "userinfo", "path", "query", "fragment"]
        indexes = [
            models.Index(fields=["product"]),
            # Fast case-insensitive equality on host within product scope
            models.Index(
                F("product"),
                Lower("host"),
                name="idx_ep_product_lower_host",
            ),
            # Global search (pro/search/): weighted tsvector FTS + trigram fuzzy match.
            GinIndex(
                SearchVector("host", weight="A", config="english")
                + SearchVector("path", weight="B", config="english"),
                name="dojo_endpoint_fts_gin",
            ),
            GinIndex(fields=["host"], opclasses=["gin_trgm_ops"], name="dojo_endpoint_host_trgm"),
        ]

    def __init__(self, *args, **kwargs):
        if settings.V3_FEATURE_LOCATIONS and not getattr(self, "_allow_v3_init", False):
            msg = "Endpoint model is deprecated when V3_FEATURE_LOCATIONS is enabled"
            raise NotImplementedError(msg)
        super().__init__(*args, **kwargs)

    def __hash__(self):
        return self.__str__().__hash__()

    def __eq__(self, other):
        if isinstance(other, Endpoint):
            contents_match = str(self) == str(other)
            # Use product_id (cached integer) instead of self.product to avoid
            # triggering a FK lookup on every comparison inside NestedObjects.add_edge.
            if self.product_id is not None and other.product_id is not None:
                return self.product_id == other.product_id and contents_match
            return contents_match

        return NotImplemented

    def __str__(self):
        try:
            if self.host:
                dummy_scheme = "dummy-scheme"  # workaround for https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L988
                url = hyperlink.EncodedURL(
                    scheme=self.protocol or dummy_scheme,
                    userinfo=self.userinfo or "",
                    host=self.host,
                    port=self.port,
                    path=tuple(self.path.split("/")) if self.path else (),
                    query=tuple(
                        (
                            qe.split("=", 1)
                            if "=" in qe
                            else (qe, None)
                        )
                        for qe in self.query.split("&")
                    ) if self.query else (),  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1427
                    fragment=self.fragment or "",
                )
                # Return a normalized version of the URL to avoid differences where there shouldn't be any difference.
                # Example: https://google.com and https://google.com:443
                normalize_path = self.path  # it used to add '/' at the end of host
                clean_url = url.normalize(scheme=True, host=True, path=normalize_path, query=True, fragment=True, userinfo=True, percents=True).to_uri().to_text()
                if not self.protocol:
                    if clean_url[:len(dummy_scheme) + 3] == (dummy_scheme + "://"):
                        clean_url = clean_url[len(dummy_scheme) + 3:]
                    else:
                        msg = "hyperlink lib did not create URL as was expected"
                        raise ValueError(msg)
                return clean_url
            msg = "Missing host"
            raise ValueError(msg)
        except:
            url = ""
            if self.protocol:
                url += f"{self.protocol}://"
            if self.userinfo:
                url += f"{self.userinfo}@"
            if self.host:
                url += self.host
            if self.port:
                url += f":{self.port}"
            if self.path:
                url += "{}{}".format("/" if self.path[0] != "/" else "", self.path)
            if self.query:
                url += f"?{self.query}"
            if self.fragment:
                url += f"#{self.fragment}"
            return url

    def get_absolute_url(self):
        return reverse("view_endpoint", args=[str(self.id)])

    @classmethod
    @contextlib.contextmanager
    def allow_endpoint_init(cls):
        # When migrating to Locations, Endpoints are not deleted (hooray backup!). Disallowing the initialization of
        # Endpoints is a good way to catch where they might still be used (oops!). However, there are some circumstances
        # -- object deletes -- where Django itself attempts to instantiate an Endpoint object. This, we need to allow:
        # if a user wants to delete an object, including whatever Endpoints are attached to it, they should be able to.
        # This context manager allows code to initialize Endpoints at our discretion.
        old = getattr(cls, "_allow_v3_init", None)
        cls._allow_v3_init = True
        try:
            yield
        finally:
            cls._allow_v3_init = old

    def clean(self):
        errors = []
        null_char_list = ["0x00", "\x00"]
        db_type = connection.vendor
        if self.protocol is not None:
            if not re.match(r"^[A-Za-z][A-Za-z0-9\.\-\+]+$", self.protocol):  # https://tools.ietf.org/html/rfc3986#section-3.1
                errors.append(ValidationError(f'Protocol "{self.protocol}" has invalid format'))
            if not self.protocol:
                self.protocol = None

        if self.userinfo is not None:
            if not re.match(r"^[A-Za-z0-9\.\-_~%\!\$&\'\(\)\*\+,;=:]+$", self.userinfo):  # https://tools.ietf.org/html/rfc3986#section-3.2.1
                errors.append(ValidationError(f'Userinfo "{self.userinfo}" has invalid format'))
            if not self.userinfo:
                self.userinfo = None

        if self.host:
            if not re.match(r"^[A-Za-z0-9_\-\+][A-Za-z0-9_\.\-\+]+$", self.host):
                try:
                    validate_ipv46_address(self.host)
                except ValidationError:
                    errors.append(ValidationError(f'Host "{self.host}" has invalid format'))
        else:
            errors.append(ValidationError("Host must not be empty"))

        if self.port is not None:
            try:
                int_port = int(self.port)
                if not (0 <= int_port < 65536):
                    errors.append(ValidationError(f'Port "{self.port}" has invalid format - out of range'))
                self.port = int_port
            except ValueError:
                errors.append(ValidationError(f'Port "{self.port}" has invalid format - it is not a number'))

        if self.path is not None:
            while len(self.path) > 0 and self.path[0] == "/":  # Endpoint store "root-less" path
                self.path = self.path[1:]
            if any(null_char in self.path for null_char in null_char_list):
                old_value = self.path
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.path = self.path.replace(remove_str, "%00")
                    logger.error('Path "%s" has invalid format - It contains the NULL character. The following action was taken: %s', old_value, action_string)
            if not self.path:
                self.path = None

        if self.query is not None:
            if len(self.query) > 0 and self.query[0] == "?":
                self.query = self.query[1:]
            if any(null_char in self.query for null_char in null_char_list):
                old_value = self.query
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.query = self.query.replace(remove_str, "%00")
                    logger.error('Query "%s" has invalid format - It contains the NULL character. The following action was taken: %s', old_value, action_string)
            if not self.query:
                self.query = None

        if self.fragment is not None:
            if len(self.fragment) > 0 and self.fragment[0] == "#":
                self.fragment = self.fragment[1:]
            if any(null_char in self.fragment for null_char in null_char_list):
                old_value = self.fragment
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.fragment = self.fragment.replace(remove_str, "%00")
                    logger.error('Fragment "%s" has invalid format - It contains the NULL character. The following action was taken: %s', old_value, action_string)
            if not self.fragment:
                self.fragment = None

        if errors:
            raise ValidationError(errors)

    @property
    def is_broken(self):
        try:
            self.clean()
        except:
            return True
        else:
            return not self.product

    @property
    def mitigated(self):
        return not self.vulnerable

    @property
    def vulnerable(self):
        return Endpoint_Status.objects.filter(
            endpoint=self,
            mitigated=False,
            false_positive=False,
            out_of_scope=False,
            risk_accepted=False,
        ).count() > 0

    @property
    def findings_count(self):
        return self.findings.all().count()

    def active_findings(self):
        return self.findings.filter(
            active=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
        ).order_by("numerical_severity")

    def active_verified_findings(self):
        return self.findings.filter(
            active=True,
            verified=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
        ).order_by("numerical_severity")

    @property
    def active_findings_count(self):
        return self.active_findings().count()

    @property
    def active_verified_findings_count(self):
        return self.active_verified_findings().count()

    def host_endpoints(self):
        return Endpoint.objects.filter(host=self.host,
                                       product=self.product).distinct()

    @property
    def host_endpoints_count(self):
        return self.host_endpoints().count()

    def host_mitigated_endpoints(self):
        meps = Endpoint_Status.objects \
                  .filter(endpoint__in=self.host_endpoints()) \
                  .filter(Q(mitigated=True)
                          | Q(false_positive=True)
                          | Q(out_of_scope=True)
                          | Q(risk_accepted=True)
                          | Q(finding__out_of_scope=True)
                          | Q(finding__mitigated__isnull=False)
                          | Q(finding__false_p=True)
                          | Q(finding__duplicate=True)
                          | Q(finding__active=False))
        return Endpoint.objects.filter(status_endpoint__in=meps).distinct()

    @property
    def host_mitigated_endpoints_count(self):
        return self.host_mitigated_endpoints().count()

    def host_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return Finding.objects.filter(endpoints__in=self.host_endpoints()).distinct()

    @property
    def host_findings_count(self):
        return self.host_findings().count()

    def host_active_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return Finding.objects.filter(
            active=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
            endpoints__in=self.host_endpoints(),
        ).order_by("numerical_severity")

    def host_active_verified_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return Finding.objects.filter(
            active=True,
            verified=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
            endpoints__in=self.host_endpoints(),
        ).order_by("numerical_severity")

    @property
    def host_active_findings_count(self):
        return self.host_active_findings().count()

    @property
    def host_active_verified_findings_count(self):
        return self.host_active_verified_findings().count()

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{"title": self.host,
                "url": reverse("view_endpoint", args=(self.id,))}]
        return bc

    @staticmethod
    def from_uri(uri):
        try:
            url = hyperlink.parse(url=uri)
        except UnicodeDecodeError:
            url = hyperlink.parse(url="//" + urlparse(uri).netloc)
        except hyperlink.URLParseError as e:
            msg = f"Invalid URL format: {e}"
            raise ValidationError(msg)

        query_parts = []  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1768
        for k, v in url.query:
            if v is None:
                query_parts.append(k)
            else:
                query_parts.append(f"{k}={v}")
        query_string = "&".join(query_parts)

        protocol = url.scheme or None
        userinfo = ":".join(url.userinfo) if url.userinfo not in {(), ("",)} else None
        host = url.host or None
        port = url.port
        path = "/".join(url.path)[:500] if url.path not in {None, (), ("",)} else None
        query = query_string[:1000] if query_string is not None and query_string else None
        fragment = url.fragment[:500] if url.fragment is not None and url.fragment else None

        return Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
        )
