import csv
import io
import logging
import re

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponseRedirect
from django.urls import reverse
from hyperlink._url import SCHEME_PORT_MAP

from dojo.models import DojoMeta, Endpoint

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
    with transaction.atomic():
        qs = endpoint_filter(**kwargs)
        count = qs.count()
        if count == 0:
            return Endpoint.objects.get_or_create(**kwargs)
        if count == 1:
            return qs.order_by("id").first(), False
        logger.warning(
            f"Endpoints in your database are broken. "
            f"Please access {reverse('endpoint_migrate')} and migrate them to new format or remove them.",
        )
        # Get the oldest endpoint first, and return that instead
        # a datetime is not captured on the endpoint model, so ID
        # will have to work here instead
        return qs.order_by("id").first(), False


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


def endpoint_meta_import(file, product, create_endpoints, create_tags, create_meta, origin="UI", request=None):
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
                'The column "hostname" must be present to map host to Endpoint.',
                extra_tags="alert-danger")
            return HttpResponseRedirect(reverse("import_endpoint_meta", args=(product.id, )))
        if origin == "API":
            msg = 'The column "hostname" must be present to map host to Endpoint.'
            raise ValidationError(msg)

    keys = [key for key in reader.fieldnames if key != "hostname"]

    for row in reader:
        endpoint = None
        host = row.get("hostname", None)

        if not host:
            continue

        endpoints = Endpoint.objects.filter(host=host, product=product)
        if not endpoints.count() and create_endpoints:
            endpoints = [Endpoint.objects.create(host=host, product=product)]
        meta = [(key, row.get(key)) for key in keys]

        for endpoint in endpoints:
            existing_tags = [tag.name for tag in endpoint.tags.all()]
            for item in meta:
                # Determine if there is a value here
                if item[1] is not None and len(item[1]) > 0:
                    if create_meta:
                        # check if meta exists first. Don't want to make duplicate endpoints
                        dojo_meta, _create = DojoMeta.objects.get_or_create(
                            endpoint=endpoint,
                            name=item[0])
                        dojo_meta.value = item[1]
                        dojo_meta.save()
                    if create_tags:
                        for tag in existing_tags:
                            if item[0] not in tag:
                                continue
                            # found existing. Update it
                            existing_tags.remove(tag)
                            break
                        existing_tags += [item[0] + ":" + item[1]]
                    # if tags are not supposed to be added, this value remain unchanged
                    endpoint.tags = existing_tags
            endpoint.save()
    return None


def remove_broken_endpoint_statuses(apps):
    Endpoint_Status = apps.get_model("dojo", "endpoint_status")
    broken_eps = Endpoint_Status.objects.filter(Q(endpoint=None) | Q(finding=None))
    if broken_eps.count() == 0:
        logger.info("There is no broken endpoint_status")
    else:
        logger.warning("We identified %s broken endpoint_statuses", broken_eps.count())
        deleted = broken_eps.delete()
        logger.warning("We removed: %s", deleted)
