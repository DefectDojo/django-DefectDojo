import logging
import re

from watson import search as watson
from django.conf import settings
from django.shortcuts import render
from tagging.models import TaggedItem, Tag

from dojo.forms import SimpleSearchForm
from dojo.models import Finding, Product, Test, Endpoint, Engagement
from dojo.utils import add_breadcrumb, get_system_setting

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
    tagged_tests = None
    tagged_findings = None
    tagged_products = None
    tagged_endpoints = None
    tagged_engagements = None
    clean_query = ''
    cookie = False
    terms = ''
    form = SimpleSearchForm()
    if request.method == 'GET' and "query" in request.GET:
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True
            clean_query = form.cleaned_data['query']
            tag_list = re.findall(r"[\w']+", clean_query)
            tags = Tag.objects.filter(name__in=tag_list)
            if request.user.is_staff:
                findings = watson.search(clean_query, models=(Finding,))
                findings = watson.search(clean_query, models=(Finding,))
                tests = watson.search(clean_query, models=(Test,))
                products = watson.search(clean_query, models=(Product,))
                tagged_findings = TaggedItem.objects.get_by_model(Finding, tags)
                tagged_tests = TaggedItem.objects.get_by_model(Test, tags)
                tagged_products = TaggedItem.objects.get_by_model(Product, tags)
                tagged_endpoints = TaggedItem.objects.get_by_model(Endpoint, tags)
                tagged_engagements = TaggedItem.objects.get_by_model(Engagement, tags)
            else:
                findings = watson.search(clean_query, models=(
                    Finding.objects.filter(test__engagement__product__authorized_users__in=[
                        request.user]),))
                tests = watson.search(clean_query,
                                      models=(Test.objects.filter(engagement__product__authorized_users__in=[
                                          request.user]),))
                products = watson.search(clean_query, models=(Product.objects.filter(authorized_users__in=[
                    request.user]),))
                tagged_findings = TaggedItem.objects.get_by_model(
                    Finding.objects.filter(test__engagement__product__authorized_users__in=[request.user]), tags)
                tagged_tests = TaggedItem.objects.get_by_model(
                    Test.objects.filter(engagement__product__authorized_users__in=[request.user]), tags)
                tagged_products = TaggedItem.objects.get_by_model(
                    Product.objects.filter(authorized_users__in=[request.user]), tags)
                tagged_endpoints = TaggedItem.objects.get_by_model(
                    Endpoint.objects.filter(product__authorized_users__in=[request.user]), tags)
                tagged_engagements = TaggedItem.objects.get_by_model(
                    Engagement.objects.filter(product__authorized_users__in=[request.user]), tags)
        else:
            form = SimpleSearchForm()
        add_breadcrumb(title="Simple Search", top_level=True, request=request)

    response = render(request, 'dojo/simple_search.html', {
        'clean_query': clean_query,
        'tests': tests,
        'findings': findings,
        'products': products,
        'tagged_tests': tagged_tests,
        'tagged_findings': tagged_findings,
        'tagged_products': tagged_products,
        'tagged_endpoints': tagged_endpoints,
        'tagged_engagements': tagged_engagements,
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
