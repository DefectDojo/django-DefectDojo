import logging

from django.core.exceptions import MultipleObjectsReturned
from hyperlink._url import SCHEME_PORT_MAP

from django.db.models import Q

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
