import logging
from django.conf import settings
from django.core.validators import validate_ipv46_address
from django.db.models import Q
from django.shortcuts import render
from pytz import timezone
from dojo.forms import SimpleSearchForm
from dojo.models import Finding, Product, Test
from dojo.utils import add_breadcrumb
import watson

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
    form = SimpleSearchForm()
    if request.method == 'GET' and "query" in request.GET:
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True
            clean_query = form.cleaned_data['query']
            if request.user.is_staff:
                findings = watson.search(clean_query, models=(Finding,))
                tests = watson.search(clean_query, models=(Test,))
                products = watson.search(clean_query, models=(Product,))
            else:
                findings = watson.search(clean_query, models=(
                Finding.objects.filter(test__engagement__product__authorized_users__in=[
                    request.user]),))
                tests = watson.search(clean_query,
                                      models=(Test.objects.filter(engagement__product__authorized_users__in=[
                                          request.user]),))
                products = watson.search(clean_query, models=(Product.objects.filter(authorized_users__in=[
                    request.user]),))
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
