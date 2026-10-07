import csv
import io
import logging
import re
from collections import defaultdict

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from django.db import connection, transaction
from django.db.models import Case, Count, F, IntegerField, Q, When, signals
from django.db.models.functions import Lower
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from hyperlink._url import SCHEME_PORT_MAP  # noqa: PLC2701

from dojo.location.models import Location, LocationProductReference
from dojo.models import DojoMeta, Endpoint
from dojo.tags.utils import bulk_add_tag_mapping
from dojo.url.models import URL

logger = logging.getLogger(__name__)


def endpoint_filter(**kwargs):
    qs = Endpoint.objects.all()

    qs = qs.filter(protocol__iexact=kwargs["protocol"]) if kwargs.get("protocol") else qs.filter(protocol__isnull=True)

    qs = qs.filter(userinfo__exact=kwargs["userinfo"]) if kwargs.get("userinfo") else qs.filter(userinfo__isnull=True)

    qs = qs.filter(host__iexact=kwargs["host"]) if kwargs.get("host") else qs.filter(host__isnull=True)

    if kwargs.get("port"):
        if (kwargs.get("protocol")) and \
                (kwargs["protocol"].lower() in SCHEME_PORT_MAP) and \
                (SCHEME_PORT_MAP[kwargs["protocol"].lower()] == kwargs["port"]):
            qs = qs.filter(Q(port__isnull=True) | Q(port__exact=SCHEME_PORT_MAP[kwargs["protocol"].lower()]))
        else:
            qs = qs.filter(port__exact=kwargs["port"])
    elif (kwargs.get("protocol")) and (kwargs["protocol"].lower() in SCHEME_PORT_MAP):
        qs = qs.filter(Q(port__isnull=True) | Q(port__exact=SCHEME_PORT_MAP[kwargs["protocol"].lower()]))
    else:
        qs = qs.filter(port__isnull=True)

    qs = qs.filter(path__exact=kwargs["path"]) if kwargs.get("path") else qs.filter(path__isnull=True)

    qs = qs.filter(query__exact=kwargs["query"]) if kwargs.get("query") else qs.filter(query__isnull=True)

    qs = qs.filter(fragment__exact=kwargs["fragment"]) if kwargs.get("fragment") else qs.filter(fragment__isnull=True)

    if kwargs.get("product"):
        qs = qs.filter(product__exact=kwargs["product"])
    elif kwargs.get("product_id"):
        qs = qs.filter(product_id__exact=kwargs["product_id"])
    else:
        qs = qs.filter(product__isnull=True)

    return qs


def endpoint_get_or_create(**kwargs):
    # This code looks a bit ugly/complicated.
    # But this method is called so frequently that we need to optimize it.
    # It executes at most one SELECT and one optional INSERT.
    qs = endpoint_filter(**kwargs)
    # Fetch up to two matches in a single round-trip. This covers
    # the common cases efficiently: zero (create) or one (reuse).
    matches = list(qs.order_by("id")[:2])
    if not matches:
        # Most common case: nothing exists yet
        return Endpoint.objects.create(**kwargs), True
    if len(matches) == 1:
        # Common case: exactly one existing endpoint
        return matches[0], False
    logger.warning(
        f"Endpoints in your database are broken. "
        f"Please access {reverse('endpoint_migrate')} and migrate them to new format or remove them.",
    )
    # Get the oldest endpoint first, and return that instead
    # a datetime is not captured on the endpoint model, so ID
    # will have to work here instead
    return matches[0], False


def clean_hosts_run(apps, change):
    def err_log(message, html_log, endpoint_html_log, endpoint):
        error_suffix = "It is not possible to migrate it. Delete or edit this endpoint."
        html_log.append({**endpoint_html_log, "message": message})
        logger.error(f"Endpoint (id={endpoint.pk}) {message}. {error_suffix}")
        broken_endpoints.add(endpoint.pk)
    html_log = []
    broken_endpoints = set()
    Endpoint_model = apps.get_model("dojo", "Endpoint")
    Endpoint_Status_model = apps.get_model("dojo", "Endpoint_Status")
    Product_model = apps.get_model("dojo", "Product")
    for endpoint in Endpoint_model.objects.order_by("id"):
        endpoint_html_log = {
            "view": reverse("view_endpoint", args=[endpoint.pk]),
            "edit": reverse("edit_endpoint", args=[endpoint.pk]),
            "delete": reverse("delete_endpoint", args=[endpoint.pk]),
        }
        if endpoint.host:
            if not re.match(r"^[A-Za-z][A-Za-z0-9\.\-\+]+$", endpoint.host):  # is old host valid FQDN?
                try:
                    validate_ipv46_address(endpoint.host)  # is old host valid IPv4/6?
                except ValidationError:
                    try:
                        if "://" in endpoint.host:  # is the old host full uri?
                            parts = Endpoint.from_uri(endpoint.host)
                            # can raise exception if the old host is not valid URL
                        else:
                            parts = Endpoint.from_uri("//" + endpoint.host)
                            # can raise exception if there is no way to parse the old host

                        if parts.protocol:
                            if endpoint.protocol and (endpoint.protocol != parts.protocol):
                                message = (
                                    f"has defined protocol ({endpoint.protocol}) and it is not the same as protocol in host "
                                    f"({parts.protocol})"
                                )
                                err_log(message, html_log, endpoint_html_log, endpoint)
                            elif change:
                                endpoint.protocol = parts.protocol

                        if parts.userinfo:
                            if change:
                                endpoint.userinfo = parts.userinfo

                        if parts.host:
                            if change:
                                endpoint.host = parts.host
                        else:
                            message = f'"{endpoint.host}" use invalid format of host'
                            err_log(message, html_log, endpoint_html_log, endpoint)

                        if parts.port:
                            try:
                                if (endpoint.port is not None) and (int(endpoint.port) != parts.port):
                                    message = (
                                        f"has defined port number ({endpoint.port}) and it is not the same as port number in "
                                        f"host ({parts.port})"
                                    )
                                    err_log(message, html_log, endpoint_html_log, endpoint)
                                elif change:
                                    endpoint.port = parts.port
                            except ValueError:
                                message = f"uses non-numeric port: {endpoint.port}"
                                err_log(message, html_log, endpoint_html_log, endpoint)

                        if parts.path:
                            if endpoint.path and (endpoint.path != parts.path):
                                message = (
                                    f"has defined path ({endpoint.path}) and it is not the same as path in host "
                                    f"({parts.path})"
                                )
                                err_log(message, html_log, endpoint_html_log, endpoint)
                            elif change:
                                endpoint.path = parts.path

                        if parts.query:
                            if endpoint.query and (endpoint.query != parts.query):
                                message = (
                                    f"has defined query ({endpoint.query}) and it is not the same as query in host "
                                    f"({parts.query})"
                                )
                                err_log(message, html_log, endpoint_html_log, endpoint)
                            elif change:
                                endpoint.query = parts.query

                        if parts.fragment:
                            if endpoint.fragment and (endpoint.fragment != parts.fragment):
                                message = (
                                    f"has defined fragment ({endpoint.fragment}) and it is not the same as fragment in host "
                                    f"({parts.fragment})"
                                )
                                err_log(message, html_log, endpoint_html_log, endpoint)
                            elif change:
                                endpoint.fragment = parts.fragment

                        if change and (endpoint.pk not in broken_endpoints):  # do not save broken endpoints
                            endpoint.save()

                    except ValidationError:
                        message = f'"{endpoint.host}" uses invalid format of host'
                        err_log(message, html_log, endpoint_html_log, endpoint)

        try:
            Endpoint.clean(endpoint)  # still don't understand why 'endpoint.clean()' doesn't work
            if change:
                endpoint.save()
        except ValidationError as ves:
            for ve in ves:
                err_log(ve, html_log, endpoint_html_log, endpoint)

        if not endpoint.product:
            err_log("Missing product", html_log, endpoint_html_log, endpoint)

    if broken_endpoints:
        logger.error(f"It is not possible to migrate database because there is/are {len(broken_endpoints)} broken endpoint(s). "
                     "Please check logs.")
    else:
        logger.info("There is not broken endpoint.")

    to_be_deleted = set()
    for product in Product_model.objects.all().distinct():
        for endpoint in Endpoint_model.objects.filter(product=product).distinct():
            if endpoint.id not in to_be_deleted:

                ep = endpoint_filter(
                    protocol=endpoint.protocol,
                    userinfo=endpoint.userinfo,
                    host=endpoint.host,
                    port=endpoint.port,
                    path=endpoint.path,
                    query=endpoint.query,
                    fragment=endpoint.fragment,
                    product_id=product.pk if product else None,
                ).order_by("id")

                if ep.count() > 1:
                    ep_ids = [x.id for x in ep]
                    to_be_deleted.update(ep_ids[1:])
                    if change:
                        message = "Merging Endpoints {} into '{}'".format(
                            [f"{x} (id={x.pk})" for x in ep[1:]],
                            f"{ep[0]} (id={ep[0].pk})")
                        html_log.append(message)
                        logger.info(message)
                        Endpoint_Status_model.objects\
                            .filter(endpoint__in=ep_ids[1:])\
                            .update(endpoint=ep_ids[0])
                        epss = Endpoint_Status_model.objects\
                            .filter(endpoint=ep_ids[0])\
                            .values("finding")\
                            .annotate(total=Count("id"))\
                            .filter(total__gt=1)
                        for eps in epss:
                            esm = Endpoint_Status_model.objects\
                                .filter(finding=eps["finding"])\
                                .order_by("-last_modified")
                            message = "Endpoint Statuses {} will be replaced by '{}'".format(
                                [f"last_modified: {x.last_modified} (id={x.pk})" for x in esm[1:]],
                                f"last_modified: {esm[0].last_modified} (id={esm[0].pk})")
                            html_log.append(message)
                            logger.info(message)
                            esm.exclude(id=esm[0].pk).delete()

    if to_be_deleted:
        if change:
            message = f"Removing endpoints: {list(to_be_deleted)}"
            Endpoint_model.objects.filter(id__in=to_be_deleted).delete()
        else:
            message = f"Redundant endpoints: {list(to_be_deleted)}, migration is required."
        html_log.append(message)
        logger.info(message)

    return html_log


def validate_endpoints_to_add(endpoints_to_add):
    errors = []
    endpoint_list = []
    endpoints = endpoints_to_add.split()
    for endpoint in endpoints:
        try:
            # is it full uri?
            # 1. from_uri validate URI format + split to components
            # 2. from_uri parse any '//localhost', '//127.0.0.1:80', '//foo.bar/path' correctly
            #    format doesn't follow RFC 3986 but users use it
            endpoint_ins = Endpoint.from_uri(endpoint) if "://" in endpoint else Endpoint.from_uri("//" + endpoint)
            endpoint_ins.clean()
            endpoint_list.append([
                endpoint_ins.protocol,
                endpoint_ins.userinfo,
                endpoint_ins.host,
                endpoint_ins.port,
                endpoint_ins.path,
                endpoint_ins.query,
                endpoint_ins.fragment,
            ])
        except ValidationError as ves:
            errors.extend(ValidationError(f"Invalid endpoint {endpoint}: {ve}") for ve in ves)
    return endpoint_list, errors


def save_endpoints_to_add(endpoint_list, product):
    processed_endpoints = []
    for e in endpoint_list:
        endpoint, _created = endpoint_get_or_create(
            protocol=e[0],
            userinfo=e[1],
            host=e[2],
            port=e[3],
            path=e[4],
            query=e[5],
            fragment=e[6],
            product=product,
        )
        processed_endpoints.append(endpoint)
    return processed_endpoints


def endpoint_meta_import(file, product, create_endpoints, create_tags, create_meta, origin="UI", request=None, object_class=Endpoint):
    content = file.read()
    sig = content.decode("utf-8-sig")
    content = sig.encode("utf-8")
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))

    if "hostname" not in reader.fieldnames:
        if origin == "UI":
            messages.add_message(
                request,
                messages.ERROR,
                _('The column "hostname" must be present to map host to Endpoint.'),
                extra_tags="alert-danger")
            return HttpResponseRedirect(reverse("import_endpoint_meta", args=(product.id, )))
        if origin == "API":
            msg = 'The column "hostname" must be present to map host to Endpoint.'
            raise ValidationError(msg)

    keys = [key for key in reader.fieldnames if key != "hostname"]
    rows = []
    for row in reader:
        host = row.get("hostname", None)
        if not host:
            continue
        # Only cells with a value are applied; empty cells leave the existing meta and tags alone.
        rows.append((host, [(key, row.get(key)) for key in keys if row.get(key) is not None and len(row.get(key)) > 0]))

    if rows:
        with transaction.atomic():
            _MetaImport(product, object_class, create_tags=create_tags, create_meta=create_meta).run(
                rows, create_endpoints=create_endpoints,
            )
    return None


class _MetaImport:

    """
    Apply an endpoint meta CSV in a fixed number of queries.

    The rows are applied in file order to an in-memory copy of each endpoint's (or
    location's) tags and meta, exactly as the old per-row loop applied them to the
    database, and only the net difference is written at the end: one lookup for every
    host, one read of the current tags and meta, then bulk inserts, updates and deletes.
    """

    def __init__(self, product, object_class, *, create_tags, create_meta):
        self.product = product
        self.object_class = object_class
        self.create_tags = create_tags
        self.create_meta = create_meta
        self.is_location = object_class == Location

    def run(self, rows, *, create_endpoints):
        hosts = list(dict.fromkeys(host for host, _ in rows))
        objects_by_host = self.load_objects(hosts)
        created = []
        if create_endpoints:
            missing = [host for host in hosts if not objects_by_host.get(host)]
            if missing:
                created = self.create_objects(missing, objects_by_host)

        objects = {obj.pk: obj for objs in objects_by_host.values() for obj in objs}
        if not objects:
            return
        shared = self.shared_location_ids(objects) if self.is_location else set()
        original_tags, through_rows = self.load_tags(objects)
        # Product-inherited tags are sticky: on the old per-row path a row that removed one
        # (a key that is a substring of it) had it put straight back by the m2m signal. The
        # batched writes bypass that signal, so keep them in every row's result instead.
        inherited = self.load_inherited_tags(objects)
        current_meta = self.load_meta(objects)
        tags = {pk: list(names) for pk, names in original_tags.items()}
        meta = {}

        for host, values in rows:
            for obj in objects_by_host.get(host, []):
                # A shared Location has one tag set, so a write here changes what the others see.
                write_tags = self.create_tags and obj.pk not in shared
                if self.create_tags and not write_tags:
                    logger.info("Skipping tags for location %s: it is shared by more than one product", obj.pk)
                if not values:
                    continue
                existing_tags = list(tags[obj.pk])
                for key, value in values:
                    if self.create_meta:
                        meta[obj.pk, key] = value
                    if write_tags:
                        for tag in existing_tags:
                            if key not in tag:
                                continue
                            # found existing. Update it
                            existing_tags.remove(tag)
                            break
                        existing_tags += [key + ":" + value]
                # Tag names are stored lowercase and unique, and read back sorted by name,
                # which is what the next row for the same host saw from the database.
                tags[obj.pk] = sorted({name.lower() for name in existing_tags} | inherited[obj.pk])

        changed = self.write_tags(objects, original_tags, tags, through_rows)
        self.write_meta(objects, current_meta, meta)
        self.apply_inheritance(created, changed)
        if self.is_location:
            # The old loop saved every matched location, which moved its updated timestamp.
            Location.objects.filter(pk__in=list(objects)).update(updated=timezone.now())

    def load_objects(self, hosts):
        objects_by_host = defaultdict(list)
        if self.is_location:
            queryset = (
                Location.objects.filter(url__host__in=hosts, products__product=self.product)
                .annotate(meta_import_host=F("url__host"))
                .order_by("id")
            )
            for location in queryset:
                objects_by_host[location.meta_import_host].append(location)
        else:
            # Filter on lower(host) so the (product, lower(host)) index serves the lookup, then
            # keep the exact matches: host matching has always been case sensitive.
            wanted = set(hosts)
            queryset = (
                Endpoint.objects.annotate(meta_import_host=Lower("host"))
                .filter(product=self.product, meta_import_host__in=self.db_lower(hosts))
                .order_by("id")
            )
            for endpoint in queryset:
                if endpoint.host in wanted:
                    objects_by_host[endpoint.host].append(endpoint)
        return objects_by_host

    def create_objects(self, missing, objects_by_host):
        if self.is_location:
            # Creating a location goes through URL identity hashing and the product reference
            # helpers, so it stays one host at a time.
            created = []
            for host in missing:
                url = URL.get_or_create_from_values(host=host)
                url.location.associate_with_product(self.product)
                objects_by_host[host] = [url.location]
                created.append(url.location)
            return created

        from dojo.tags import inheritance as tag_inheritance  # noqa: PLC0415 -- avoid import cycle via dojo.forms

        created = Endpoint.objects.bulk_create([Endpoint(host=host, product=self.product) for host in missing])
        # bulk_create skips post_save. Send it so receivers that act on a new endpoint (search
        # indexing, Pro prioritization) still see each one; product tag inheritance is applied
        # once for the whole batch afterwards instead of per endpoint.
        with tag_inheritance.suppress_tag_inheritance():
            for endpoint in created:
                signals.post_save.send(
                    sender=Endpoint, instance=endpoint, created=True, update_fields=None, raw=False,
                    using=endpoint._state.db,
                )
        for host, endpoint in zip(missing, created, strict=True):
            objects_by_host[host] = [endpoint]
        # The old path created each endpoint with Endpoint.objects.create(), whose post_save
        # gave it the product's inherited tags before any row was applied, and the rows then
        # saw (and could replace) those tags. Apply them now, before the rows, to match.
        tag_inheritance.apply_inherited_tags_for_endpoints(created)
        return created

    def shared_location_ids(self, objects):
        return set(
            LocationProductReference.objects.filter(location_id__in=list(objects))
            # BaseManager orders by id; clear it or the id joins the GROUP BY.
            .order_by()
            .values("location_id")
            .annotate(product_count=Count("id"))
            .filter(product_count__gt=1)
            .values_list("location_id", flat=True),
        )

    @staticmethod
    def db_lower(values):
        """
        Lowercase values the way Postgres LOWER() does.

        Python's str.lower() differs from the database for some characters (for example a
        dotted capital I), so comparing a Python-lowered host against LOWER(host) can miss
        the row and create a duplicate. One query lowercases them all on the database side.
        """
        values = list(values)
        if not values:
            return []
        with connection.cursor() as cursor:
            cursor.execute("SELECT LOWER(value) FROM UNNEST(%s::text[]) AS value", [values])
            return [row[0] for row in cursor.fetchall()]

    def tag_through(self, field_name="tags"):
        field = self.object_class._meta.get_field(field_name)
        through = field.remote_field.through
        source = target = None
        for through_field in through._meta.fields:
            remote = getattr(through_field, "remote_field", None)
            if remote is None:
                continue
            if remote.model == self.object_class:
                source = through_field.attname
            elif remote.model == field.related_model:
                target = through_field.attname
        return field.related_model, through, source, target

    def load_tags(self, objects):
        _, through, source, target = self.tag_through()
        tags = {pk: [] for pk in objects}
        through_rows = {}
        rows = (
            through.objects.filter(**{f"{source}__in": list(objects)})
            .order_by(f"{target.removesuffix('_id')}__name")
            .values_list("pk", source, target, f"{target.removesuffix('_id')}__name")
        )
        for row_id, obj_id, tag_id, name in rows:
            tags[obj_id].append(name)
            through_rows[obj_id, name] = (row_id, tag_id)
        return tags, through_rows

    def load_inherited_tags(self, objects):
        """The inherited tag names of each object, as stored right now."""
        _, through, source, target = self.tag_through("inherited_tags")
        inherited = {pk: set() for pk in objects}
        rows = through.objects.filter(**{f"{source}__in": list(objects)}).values_list(
            source, f"{target.removesuffix('_id')}__name",
        )
        for obj_id, name in rows:
            inherited[obj_id].add(name)
        return inherited

    def load_meta(self, objects):
        if self.is_location:
            queryset = DojoMeta.objects.filter(location_id__in=list(objects), location_product=self.product)
            owner = "location_id"
        else:
            queryset = DojoMeta.objects.filter(endpoint_id__in=list(objects))
            owner = "endpoint_id"
        return {(getattr(row, owner), row.name): row for row in queryset}

    def write_tags(self, objects, original_tags, tags, through_rows):
        tag_model, through, _, _ = self.tag_through()
        to_add = defaultdict(list)
        removed_rows = []
        changed = []
        for pk, names in tags.items():
            before = set(original_tags[pk])
            after = set(names)
            if before == after:
                continue
            changed.append(objects[pk])
            for name in after - before:
                to_add[name].append(objects[pk])
            removed_rows.extend(through_rows[pk, name] for name in before - after)

        if to_add:
            bulk_add_tag_mapping(dict(to_add))
        if removed_rows:
            # One DELETE: the collector behind QuerySet.delete() would split the ids into
            # batches of 100. Tag through rows have nothing that depends on them, and the
            # tag counts are maintained just below.
            removed = through.objects.filter(pk__in=[row_id for row_id, _ in removed_rows])
            removed._raw_delete(removed.db)
            removed_per_tag = defaultdict(int)
            for _, tag_id in removed_rows:
                removed_per_tag[tag_id] += 1
            tag_model.objects.filter(pk__in=list(removed_per_tag)).update(
                count=Case(
                    *[When(pk=pk, then=F("count") - amount) for pk, amount in removed_per_tag.items()],
                    output_field=IntegerField(),
                ),
            )
            # Same clean-up tagulous does when an instance save drops a tag: a tag nothing
            # uses any more is deleted unless it is protected.
            for tag in tag_model.objects.filter(pk__in=list(removed_per_tag), count__lte=0):
                tag.try_delete()
        return changed

    def write_meta(self, objects, current_meta, meta):
        to_create = []
        to_update = []
        for (pk, name), value in meta.items():
            row = current_meta.get((pk, name))
            if row is None:
                owner = {"location": objects[pk], "location_product": self.product} if self.is_location else {"endpoint": objects[pk]}
                to_create.append(DojoMeta(name=name, value=value, **owner))
            elif row.value != value:
                row.value = value
                to_update.append(row)
        if to_create:
            DojoMeta.objects.bulk_create(to_create, batch_size=1000)
        if to_update:
            DojoMeta.objects.bulk_update(to_update, ["value"], batch_size=1000)

    def apply_inheritance(self, created, changed):
        # The tag writes above bypass the m2m signals that keep product-inherited tags in
        # place, so run inheritance once for every new or retagged object instead.
        from dojo.tags import inheritance as tag_inheritance  # noqa: PLC0415 -- avoid import cycle via dojo.forms

        touched = list({obj.pk: obj for obj in [*created, *changed]}.values())
        if not touched:
            return
        if self.is_location:
            tag_inheritance.apply_inherited_tags_for_locations(touched, product=self.product)
        else:
            tag_inheritance.apply_inherited_tags_for_endpoints(touched)


def remove_broken_endpoint_statuses(apps):
    Endpoint_Status = apps.get_model("dojo", "endpoint_status")
    broken_eps = Endpoint_Status.objects.filter(Q(endpoint=None) | Q(finding=None))
    if broken_eps.count() == 0:
        logger.info("There is no broken endpoint_status")
    else:
        logger.warning("We identified %s broken endpoint_statuses", broken_eps.count())
        deleted = broken_eps.delete()
        logger.warning("We removed: %s", deleted)
