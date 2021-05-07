import logging
import re
from itertools import chain

from django.core.exceptions import MultipleObjectsReturned
from hyperlink._url import SCHEME_PORT_MAP

from django.core.validators import validate_ipv46_address
from django.core.exceptions import FieldError, ValidationError
from django.db.models import Q, Count

from dojo.models import Endpoint

logger = logging.getLogger(__name__)


def endpoint_filter(**kwargs):
    qs = Endpoint.objects.all()

    if kwargs.get('protocol'):
        qs = qs.filter(protocol__iexact=kwargs['protocol'])
    else:
        qs = qs.filter(protocol__isnull=True)

    if kwargs.get('userinfo'):
        qs = qs.filter(userinfo__exact=kwargs['userinfo'])
    else:
        qs = qs.filter(userinfo__isnull=True)

    if kwargs.get('host'):
        qs = qs.filter(host__iexact=kwargs['host'])
    else:
        qs = qs.filter(host__isnull=True)

    if kwargs.get('port'):
        if (kwargs.get('protocol')) and \
                (kwargs['protocol'].lower() in SCHEME_PORT_MAP) and \
                (SCHEME_PORT_MAP[kwargs['protocol'].lower()] == kwargs['port']):
            qs = qs.filter(Q(port__isnull=True) | Q(port__exact=SCHEME_PORT_MAP[kwargs['protocol'].lower()]))
        else:
            qs = qs.filter(port__exact=kwargs['port'])
    else:
        if (kwargs.get('protocol')) and (kwargs['protocol'].lower() in SCHEME_PORT_MAP):
            qs = qs.filter(Q(port__isnull=True) | Q(port__exact=SCHEME_PORT_MAP[kwargs['protocol'].lower()]))
        else:
            qs = qs.filter(port__isnull=True)

    if kwargs.get('path'):
        qs = qs.filter(path__exact=kwargs['path'])
    else:
        qs = qs.filter(path__isnull=True)

    if kwargs.get('query'):
        qs = qs.filter(query__exact=kwargs['query'])
    else:
        qs = qs.filter(query__isnull=True)

    if kwargs.get('fragment'):
        qs = qs.filter(fragment__exact=kwargs['fragment'])
    else:
        qs = qs.filter(fragment__isnull=True)

    if kwargs.get('product'):
        qs = qs.filter(product__exact=kwargs['product'])
    elif kwargs.get('product_id'):
        qs = qs.filter(product_id__exact=kwargs['product_id'])
    else:
        qs = qs.filter(product__isnull=True)

    return qs


def endpoint_get_or_create(**kwargs):

    qs = endpoint_filter(**kwargs)

    if qs.count() == 0:
        return Endpoint.objects.get_or_create(**kwargs)

    elif qs.count() == 1:
        return qs.first(), False

    else:
        raise MultipleObjectsReturned()


def clean_hosts_run(apps, change):
    broken_endpoints = []
    Endpoint_model = apps.get_model('dojo', 'Endpoint')
    Endpoint_Status_model = apps.get_model('dojo', 'Endpoint_Status')
    Product_model = apps.get_model('dojo', 'Product')
    error_suffix = 'It is not possible to migrate it. Remove or fix this endpoint.'
    # when run on older versions, we haven't had the migration applied which has userinfo field added
    # so defer that field and order by id (default ordering references userinfo field)
    for endpoint in Endpoint_model.objects.defer('userinfo').order_by('id'):
        if not endpoint.host or endpoint.host == '':
            logger.error('Endpoint (id={}) does not have "host" field. {}'.format(endpoint.pk, error_suffix))
            broken_endpoints.append(endpoint.pk)
        else:
            if not re.match(r'^[A-Za-z][A-Za-z0-9\.\-\+]+$', endpoint.host):  # is old host valid FQDN?
                try:
                    validate_ipv46_address(endpoint.host)  # is old host valid IPv4/6?
                except ValidationError:
                    try:
                        if '://' in endpoint.host:  # is the old host full uri?
                            parts = Endpoint.from_uri(endpoint.host)
                            # can raise exception if the old host is not valid URL
                        else:
                            parts = Endpoint.from_uri('//' + endpoint.host)
                            # can raise exception if there is no way to parse the old host

                        if parts.protocol:
                            if endpoint.protocol and (endpoint.protocol != parts.protocol):
                                logger.error('Endpoint (id={}) has defined protocol ({}) and it is not the same as '
                                    'protocol in host ({}). {}'.format(endpoint.pk, endpoint.protocol, parts.protocol,
                                                                        error_suffix))
                                broken_endpoints.append(endpoint.pk)
                            else:
                                if change:
                                    endpoint.protocol = parts.protocol

                        if parts.userinfo:
                            if change:
                                endpoint.userinfo = parts.userinfo

                        if parts.host:
                            if change:
                                endpoint.host = parts.host
                        else:
                            logger.error('Endpoint (id={}) "{}" use invalid format of host. {}'.format(endpoint.pk,
                                endpoint.host, error_suffix))
                            broken_endpoints.append(endpoint.pk)

                        if parts.port:
                            try:
                                if (endpoint.port is not None) and (int(endpoint.port) != parts.port):
                                    logger.error('Endpoint (id={}) has defined port number ({}) and it is not the same '
                                        'as port number in host ({}). {}'.format(endpoint.pk, endpoint.port, parts.port,
                                            error_suffix))
                                    broken_endpoints.append(endpoint.pk)
                                else:
                                    if change:
                                        endpoint.port = parts.port
                            except ValueError:
                                logger.error('Endpoint (id={}) use non-numeric port: {}. {}'.format(endpoint.pk,
                                                                                                    endpoint.port,
                                                                                                    error_suffix))
                                broken_endpoints.append(endpoint.pk)

                        if parts.path:
                            if endpoint.path and (endpoint.path != parts.path):
                                logger.error('Endpoint (id={}) has defined path ({}) and it is not the same as path in '
                                    'host ({}). {}'.format(endpoint.pk, endpoint.path, parts.path, error_suffix))
                                broken_endpoints.append(endpoint.pk)
                            else:
                                if change:
                                    endpoint.path = parts.path

                        if parts.query:
                            if endpoint.query and (endpoint.query != parts.query):
                                logger.error('Endpoint (id={}) has defined query ({}) and it is not the same as query '
                                    'in host ({}). {}'.format(endpoint.pk, endpoint.query, parts.query, error_suffix))
                                broken_endpoints.append(endpoint.pk)
                            else:
                                if change:
                                    endpoint.query = parts.query

                        if parts.fragment:
                            if endpoint.fragment and (endpoint.fragment != parts.fragment):
                                logger.error('Endpoint (id={}) has defined fragment ({}) and it is not the same as '
                                    'fragment in host ({}). {}'.format(endpoint.pk, endpoint.fragment, parts.fragment,
                                                                       error_suffix))
                                broken_endpoints.append(endpoint.pk)
                            else:
                                if change:
                                    endpoint.fragment = parts.fragment

                        if change:
                            endpoint.save()

                    except ValidationError:
                        logger.error('Endpoint (id={}) "{}" use invalid format of host. {}'.format(endpoint.pk,
                            endpoint.host, error_suffix))
                        broken_endpoints.append(endpoint.pk)

    if broken_endpoints != []:
        raise FieldError('It is not possible to migrate database because there is/are {} broken endpoint(s). '
                         'Please check logs.'.format(len(broken_endpoints)))

    if change:
        to_be_deleted = set()
        for product in chain(Product_model.objects.all().distinct(), [None]):
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
                        product_id=product.pk if product else None
                    ).order_by('id')

                    if ep.count() > 1:
                        ep_ids = [x.id for x in ep]
                        logger.info("Merging Endpoints {} into '{}'".format(
                            ["{} (id={})".format(str(x), x.pk) for x in ep[1:]],
                            "{} (id={})".format(str(ep[0]), ep[0].pk)))
                        to_be_deleted.update(ep_ids[1:])
                        Endpoint_Status_model.objects\
                            .filter(endpoint__in=ep_ids[1:])\
                            .update(endpoint=ep_ids[0])
                        epss = Endpoint_Status_model.objects\
                            .filter(endpoint=ep_ids[0])\
                            .values('finding')\
                            .annotate(total=Count('id'))\
                            .filter(total__gt=1)
                        for eps in epss:
                            esm = Endpoint_Status_model.objects\
                                .filter(finding=eps['finding'])\
                                .order_by('-last_modified')
                            logger.info("Endpoint Statuses {} will be replaced by '{}'".format(
                                ["last_modified: {} (id={})".format(x.last_modified, x.pk) for x in esm[1:]],
                                "last_modified: {} (id={})".format(esm[0].last_modified, esm[0].pk)))
                            esm.exclude(id=esm[0].pk).delete()

        if to_be_deleted != set():
            logger.info("Removing endpoints: {}".format(to_be_deleted))
            Endpoint_model.objects.filter(id__in=to_be_deleted).delete()
