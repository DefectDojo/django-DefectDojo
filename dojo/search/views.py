import logging
import re

from django.shortcuts import render
from tagging.models import TaggedItem, Tag
from watson import search as watson
from django.db.models import Q
from dojo.forms import SimpleSearchForm
from dojo.models import Finding, Finding_Template, Product, Test, Endpoint, Engagement, Languages, \
    App_Analysis
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


def simple_search(request):
    ip_addresses = []
    dashes = []
    query = []
    tests = None
    findings = None
    finding_templates = None
    products = None
    tagged_tests = None
    tagged_findings = None
    tagged_products = None
    tagged_endpoints = None
    tagged_engagements = None
    tagged_finding_templates = None
    engagements = None
    endpoints = None
    languages = None
    app_analysis = None
    clean_query = ''
    cookie = False
    terms = ''
    form = SimpleSearchForm()

    if request.method == 'GET' and "query" in request.GET:
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True
            clean_query = form.cleaned_data['query']
            search_operator = ""
            # Check for search operator like finding:, endpoint:, test: product:
            if ":" in clean_query:
                operator = clean_query.split(":")
                search_operator = operator[0]
                clean_query = operator[1].lstrip()
            tag_list = re.findall(r"[\w']+", clean_query)
            tags = Tag.objects.filter(name__in=tag_list)
            if request.user.is_staff:
                if "finding" in search_operator or search_operator is "":
                    findings = watson.search(clean_query, models=(Finding,))

                if "template" in search_operator or search_operator is "":
                    finding_templates = watson.search(clean_query, models=(Finding_Template,))

                if "test" in search_operator or search_operator is "":
                    tests = watson.search(clean_query, models=(Test,))

                if "product" in search_operator or search_operator is "":
                    products = watson.search(clean_query, models=(Product,))

                if "tag" in search_operator or search_operator is "":
                    tagged_findings = TaggedItem.objects.get_by_model(Finding,
                                                                      tags)
                    tagged_finding_templates = TaggedItem.objects.get_by_model(Finding_Template,
                                                                               tags)
                    tagged_tests = TaggedItem.objects.get_by_model(Test, tags)
                    tagged_products = TaggedItem.objects.get_by_model(Product,
                                                                      tags)
                    tagged_endpoints = TaggedItem.objects.get_by_model(Endpoint,
                                                                       tags)
                    tagged_engagements = TaggedItem.objects.get_by_model(
                        Engagement, tags)
                # endpoints = watson.search(clean_query, models=(Endpoint,))

                if "endpoint" in search_operator or search_operator is "":
                    endpoints = Endpoint.objects.filter(Q(host__icontains=clean_query) | Q(path__icontains=clean_query) | Q(fqdn__icontains=clean_query) | Q(protocol__icontains=clean_query))

                if "engagement" in search_operator or search_operator is "":
                    engagements = watson.search(clean_query, models=(Engagement,))

                if "language" in search_operator or search_operator is "":
                    languages = Languages.objects.filter(language__language__icontains=clean_query)

                if "technology" in search_operator or search_operator is "":
                    app_analysis = App_Analysis.objects.filter(name__icontains=clean_query)

            else:
                if "finding" in search_operator or search_operator is "":
                    findings = watson.search(clean_query, models=(
                        Finding.objects.filter(
                            test__engagement__product__authorized_users__in=[
                                request.user]),))

                if "template" in search_operator or search_operator is "":
                    finding_templates = watson.search(clean_query, models=(
                        Finding_Template.objects.filter(
                            authorized_users__in=[
                                request.user]),))

                if "test" in search_operator or search_operator is "":
                    tests = watson.search(
                        clean_query,
                        models=(Test.objects.filter(
                            engagement__product__authorized_users__in=[
                                request.user]),))

                if "product" in search_operator or search_operator is "":
                    products = watson.search(clean_query, models=(
                        Product.objects.filter(authorized_users__in=[
                            request.user]),))

                if "tag" in search_operator or search_operator is "":
                    tagged_findings = TaggedItem.objects.get_by_model(
                        Finding.objects.filter(
                            test__engagement__product__authorized_users__in=[
                                request.user]), tags)
                    tagged_finding_templates = TaggedItem.objects.get_by_model(
                        Finding_Template.objects.filter(
                            authorized_users__in=[
                                request.user]), tags)
                    tagged_tests = TaggedItem.objects.get_by_model(
                        Test.objects.filter(
                            engagement__product__authorized_users__in=[
                                request.user]), tags)
                    tagged_products = TaggedItem.objects.get_by_model(
                        Product.objects.filter(
                            authorized_users__in=[request.user]), tags)
                    tagged_endpoints = TaggedItem.objects.get_by_model(
                        Endpoint.objects.filter(
                            product__authorized_users__in=[request.user]), tags)
                    tagged_engagements = TaggedItem.objects.get_by_model(
                        Engagement.objects.filter(
                            product__authorized_users__in=[request.user]), tags)
        else:
            form = SimpleSearchForm()
        add_breadcrumb(title="Simple Search", top_level=True, request=request)

    response = render(request, 'dojo/simple_search.html', {
        'clean_query': clean_query,
        'languages': languages,
        'app_analysis': app_analysis,
        'tests': tests,
        'findings': findings,
        'finding_templates': finding_templates,
        'products': products,
        'tagged_tests': tagged_tests,
        'tagged_findings': tagged_findings,
        'tagged_finding_templates': tagged_finding_templates,
        'tagged_products': tagged_products,
        'tagged_endpoints': tagged_endpoints,
        'tagged_engagements': tagged_engagements,
        'engagements': engagements,
        'endpoints': endpoints,
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
