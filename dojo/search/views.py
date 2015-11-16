import logging

from django.conf import settings
from django.core.validators import validate_ipv46_address
from django.db.models import Q
from django.shortcuts import render
from pytz import timezone

from dojo.forms import SimpleSearchForm
from dojo.models import Finding, Product, Test
from dojo.utils import add_breadcrumb

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)

# #  search
"""
Jay
status: in development, testing in prod
simple search with special consideration for IP addresses and CVEs
"""


def simple_search(request):
    ip_addresses = []
    dashes = []
    query = []
    tests = None
    findings = None
    products = None
    clean_query = ''
    cookie = False
    terms = ''
    if request.method == 'GET' and "query" in request.GET:
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True
            clean_query = request.GET['query']
            terms = form.cleaned_data['query'].split()
            if request.user.is_staff:
                q = Q()
                for term in terms:
                    try:
                        validate_ipv46_address(term)
                        ip_addresses.append(term)
                    except:
                        if "-" in term:
                            dashes.append(term)
                        else:
                            query.append(term)

                for qy in query:
                    q.add((Q(notes__entry__icontains=qy) |
                           Q(finding__title__icontains=qy) |
                           Q(finding__url__icontains=qy) |
                           Q(finding__description__icontains=qy) |
                           Q(finding__references__icontains=qy) |
                           Q(finding__mitigation__icontains=qy) |
                           Q(finding__impact__icontains=qy)), Q.OR)

                for ip in ip_addresses:
                    q.add(Q(finding__endpoint__icontains=ip), Q.OR)
                dash_query = ''
                for dash in dashes:
                    dash_query = dash
                    q.add(Q(finding__title__icontains=dash_query) |
                          Q(finding__url__icontains=dash_query) |
                          Q(finding__description__icontains=dash_query) |
                          Q(finding__references__icontains=dash_query) |
                          Q(finding__mitigation__icontains=dash_query) |
                          Q(finding__impact__icontains=dash_query) |
                          Q(notes__entry__icontains=dash_query), Q.OR)

                tests = Test.objects.filter(q).order_by("-target_start")

            q = Q()
            for qy in query:
                q.add((Q(notes__entry__icontains=qy) |
                       Q(title__icontains=qy) |
                       Q(url__icontains=qy) |
                       Q(description__icontains=qy) |
                       Q(references__icontains=qy) |
                       Q(mitigation__icontains=qy) |
                       Q(impact__icontains=qy)), Q.OR)
            for ip in ip_addresses:
                q.add(Q(endpoint__icontains=ip) | Q(references__icontains=ip),
                      Q.OR)

            for dash in dashes:
                dash_query = dash
                q.add(Q(title__icontains=dash_query) |
                      Q(url__icontains=dash_query) |
                      Q(description__icontains=dash_query) |
                      Q(references__icontains=dash_query) |
                      Q(mitigation__icontains=dash_query) |
                      Q(impact__icontains=dash_query) |
                      Q(notes__entry__icontains=dash_query), Q.OR)

            findings = Finding.objects.filter(q).order_by("-date")

            if not request.user.is_staff:
                findings = findings.filter(
                    test__engagement__product__authorized_users__in=[
                        request.user])

            q = Q()
            for qy in query:
                q.add((Q(name__icontains=qy) |
                       Q(description__icontains=qy)), Q.OR)
            dash_query = ''
            for dash in dashes:
                dash_query = dash
                q.add(Q(name=dash_query) |
                      Q(description=dash_query), Q.OR)
            products = Product.objects.filter(q).order_by('name')
            if not request.user.is_staff:
                products = products.filter(
                    authorized_users__in=[
                        request.user])
        else:
            form = SimpleSearchForm()
        add_breadcrumb(title="Simple Search", top_level=True, request=request)
        response = render(request, 'dojo/simple_search.html', {
            'clean_query': clean_query,
            'tests': tests,
            'findings': findings,
            'products': products,
            'name': 'Simple Search',
            'metric': False,
            'user': request.user,
            'form': form})

    if cookie:
        response.set_cookie("highlight", value=clean_query,
                            max_age=None, expires=None,
                            path='/', secure=True, httponly=False)
    else:
        response.delete_cookie("highlight", path='/')
    return response
