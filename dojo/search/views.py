import logging

from django.shortcuts import render
from tagging.models import TaggedItem
from watson import search as watson
from django.db.models import Q
from dojo.forms import SimpleSearchForm
from dojo.models import Finding, Finding_Template, Product, Test, Endpoint, Engagement, Languages, \
    App_Analysis
from dojo.utils import add_breadcrumb
import re

logger = logging.getLogger(__name__)

# explicitly use our own regex pattern here as django-watson is sensitive so we want to control it here independently of models.py etc.
cve_pattern = re.compile(r'(^CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$')


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
            original_clean_query = clean_query
            # print('clean_query: ', clean_query)
            if ":" in clean_query:
                operator = clean_query.split(":")
                search_operator = operator[0]
                clean_query = operator[1].lstrip()

            # if the query contains hyphens, django-watson will escape these leading to problems.
            # for cve we make this workaround because we really want to be able to search for CVEs
            # problem still remains for other case, i.e. searching for "valentijn-scholten" will return no results because of the hyphen.
            # see:
            # - https://github.com/etianen/django-watson/issues/223
            # - https://github.com/DefectDojo/django-DefectDojo/issues/1092
            # - https://github.com/DefectDojo/django-DefectDojo/issues/2081

            if bool(cve_pattern.match(clean_query)):
                clean_query = '\'' + clean_query + '\''
                # print('new clean_query: ', clean_query)

            tags = clean_query
            if request.user.is_staff:
                if "finding" in search_operator or "cve" in search_operator or "id" in search_operator or search_operator == "":
                    findings = watson.search(clean_query, models=(Finding,))

                if "template" in search_operator or search_operator == "":
                    finding_templates = watson.search(clean_query, models=(Finding_Template,))

                if "test" in search_operator or search_operator == "":
                    tests = watson.search(clean_query, models=(Test,))

                if "product" in search_operator or search_operator == "":
                    products = watson.search(clean_query, models=(Product,))

                if "tag" in search_operator or search_operator == "":
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

                if "endpoint" in search_operator or search_operator == "":
                    endpoints = Endpoint.objects.filter(Q(host__icontains=clean_query) | Q(path__icontains=clean_query) | Q(fqdn__icontains=clean_query) | Q(protocol__icontains=clean_query))

                if "engagement" in search_operator or search_operator == "":
                    engagements = watson.search(clean_query, models=(Engagement,))

                if "language" in search_operator or search_operator == "":
                    languages = Languages.objects.filter(language__language__icontains=clean_query)

                if "technology" in search_operator or search_operator == "":
                    app_analysis = App_Analysis.objects.filter(name__icontains=clean_query)

            else:
                if "finding" in search_operator or "cve" in search_operator or "id" in search_operator or search_operator == "":
                    findings = watson.search(clean_query, models=(
                        Finding.objects.filter(
                            test__engagement__product__authorized_users__in=[
                                request.user]),))

                if "template" in search_operator or search_operator == "":
                    finding_templates = watson.search(clean_query, models=(Finding_Template,))

                if "test" in search_operator or search_operator == "":
                    tests = watson.search(
                        clean_query,
                        models=(Test.objects.filter(
                            engagement__product__authorized_users__in=[
                                request.user]),))

                if "product" in search_operator or search_operator == "":
                    products = watson.search(clean_query, models=(
                        Product.objects.filter(authorized_users__in=[
                            request.user]),))

                if "tag" in search_operator or search_operator == "":
                    tagged_findings = TaggedItem.objects.get_by_model(
                        Finding.objects.filter(
                            test__engagement__product__authorized_users__in=[
                                request.user]), tags)
                    tagged_finding_templates = TaggedItem.objects.get_by_model(Finding_Template,
                                                                               tags)
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

            if findings:
                findings = findings.prefetch_related('object', 'object__test', 'object__test__engagement', 'object__test__engagement__product',
                 'object__risk_acceptance_set', 'object__test__test_type', 'object__tagged_items__tag', 'object__test__engagement__product__tagged_items__tag')

            if engagements:
                engagements = engagements.prefetch_related('object', 'object__product', 'object__product__tagged_items__tag', 'object__tagged_items__tag')

            if products:
                products = products.prefetch_related('object', 'object__tagged_items__tag')

            if tests:
                tests = tests.prefetch_related('object', 'object__engagement', 'object__engagement__product', 'object__test_type', 'object__engagement__tagged_items__tag')

            if languages:
                languages = languages.prefetch_related('object', 'object__product', 'object__product__tagged_items__tag')

        else:
            form = SimpleSearchForm()
        add_breadcrumb(title="Simple Search", top_level=True, request=request)

    response = render(request, 'dojo/simple_search.html', {
        'clean_query': original_clean_query,
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
