import logging

from django.shortcuts import render
from tagging.models import TaggedItem
from watson import search as watson
from django.db.models import Q
from dojo.forms import SimpleSearchForm
from dojo.models import Finding, Finding_Template, Product, Test, Endpoint, Engagement, Languages, \
    App_Analysis
from dojo.utils import add_breadcrumb, get_words_for_field
import re
from dojo.finding.views import prefetch_for_findings
from dojo.filters import OpenFindingFilter
from django.conf import settings

logger = logging.getLogger(__name__)

# explicitly use our own regex pattern here as django-watson is sensitive so we want to control it here independently of models.py etc.
cve_pattern = re.compile(r'(^CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$')
# cve_pattern = re.compile(r'(CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))')


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

    original_clean_query = ""
    findings_filter = None
    title_words = None
    component_words = None
    paged_generic = None

    max_results = settings.SEARCH_MAX_RESULTS

    # if request.method == 'GET' and "query" in request.GET:
    if request.method == 'GET':
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            # logger.debug('form vars: %s', vars(form))
            cookie = True
            clean_query = form.cleaned_data['query'] or ''
            search_operator, operator = "", ""
            # Check for search operator like finding:, endpoint:, test: product:
            original_clean_query = clean_query
            # print('clean_query: ', clean_query)
            if ":" in clean_query:
                operator = clean_query.split(":")
                search_operator = operator[0]
                clean_query = operator[1].lstrip()

            logger.debug('operator: %s', operator)
            logger.debug('search_operator: %s', search_operator)
            logger.debug('clean_query: %s', clean_query)

            # if the query contains hyphens, django-watson will escape these leading to problems.
            # for cve we make this workaround because we really want to be able to search for CVEs
            # problem still remains for other case, i.e. searching for "valentijn-scholten" will return no results because of the hyphen.
            # see:
            # - https://github.com/etianen/django-watson/issues/223
            # - https://github.com/DefectDojo/django-DefectDojo/issues/1092
            # - https://github.com/DefectDojo/django-DefectDojo/issues/2081

            # it's not google grade parsing, but let's do some basic stuff right
            query_parts = clean_query.split(" ")
            new_parts = ""
            for part in query_parts:
                if bool(cve_pattern.match(part)):
                    part = '\'' + part + '\''
                    clean_query = '\'' + clean_query + '\''
                    print('new part: ', part)
                else:
                    print('old part: ', part)

                new_parts += (part + " ")

            clean_query = new_parts.strip()

            # clean_query = '\'' + clean_query + '\''

            logger.debug('cve clean_query: [%s]', clean_query)

            search_tags = "tag" in search_operator or search_operator == ""
            search_findings = "finding" in search_operator or "cve" in search_operator or "id" in search_operator or search_operator == ""
            search_finding_templates = "template" in search_operator or search_operator == ""
            search_tests = "test" in search_operator or search_operator == ""
            search_engagements = "engagement" in search_operator or search_operator == ""
            search_products = "product" in search_operator or search_operator == ""
            search_endpoints = "endpoint" in search_operator or search_operator == ""
            search_languages = "language" in search_operator or search_operator == ""
            search_technologies = "technology" in search_operator or search_operator == ""

            findings = Finding.objects.all()
            tests = Test.objects.all()
            engagements = Engagement.objects.all()
            products = Product.objects.all()
            endpoints = Endpoint.objects.all()
            finding_templates = Finding_Template.objects.all()

            if not request.user.is_staff:
                findings = findings.filter(Q(test__engagement__product__authorized_users__in=[request.user]) | Q(test__engagement__product__prod_type__authorized_users__in=[request.user]))
                tests = tests.filter(Q(engagement__product__authorized_users__in=[request.user]) | Q(engagement__product__prod_type__authorized_users__in=[request.user]))
                engagements = engagements.filter(Q(product__authorized_users__in=[request.user]) | Q(product__prod_type__authorized_users__in=[request.user]))
                products = products.filter(Q(authorized_users__in=[request.user]) | Q(prod_type__authorized_users__in=[request.user]))
                endpoints = endpoints.filter(Q(product__authorized_users__in=[request.user]) | Q(product__prod_type__authorized_users__in=[request.user]))

            # TODO better get findings in their own query and match on id. that would allow filtering on additional fields such cve, prod_id, etc.

            findings_filter = None
            title_words = None
            component_words = None

            tags = clean_query
            # search tags first to avoid errors due to slicing too early
            if search_tags:
                tagged_findings = TaggedItem.objects.get_by_model(findings, tags)[:max_results]
                tagged_finding_templates = TaggedItem.objects.get_by_model(Finding_Template, tags)[:max_results]
                tagged_tests = TaggedItem.objects.get_by_model(tests, tags)[:max_results]
                tagged_engagements = TaggedItem.objects.get_by_model(engagements, tags)[:max_results]
                tagged_products = TaggedItem.objects.get_union_by_model(products, tags)[:max_results]
                tagged_endpoints = TaggedItem.objects.get_by_model(endpoints, tags)[:max_results]
            else:
                tagged_findings = None
                tagged_finding_templates = None
                tagged_tests = None
                tagged_engagements = None
                tagged_products = None
                tagged_endpoints = None

            if search_findings:
                findings_filter = OpenFindingFilter(request.GET, queryset=findings, user=request.user, pid=None, prefix='finding')
                title_words = get_words_for_field(findings_filter.qs, 'title')
                component_words = get_words_for_field(findings_filter.qs, 'component_name')
                findings = findings_filter.qs

                if clean_query:
                    logger.debug('going watson with: %s', clean_query)
                    watson_results = watson.filter(findings_filter.qs, clean_query)[:max_results]
                    findings = findings.filter(id__in=[watson.id for watson in watson_results])

                # prefetch after watson to avoid inavlid query errors due to watson not understanding prefetching
                findings = prefetch_for_findings(findings)
                # some over the top tag displaying happening...
                findings = findings.prefetch_related('test__engagement__product__tagged_items__tag')

                findings = findings[:max_results]
            else:
                findings = None
                findings_filter = None
                component_words = None

                # logger.debug('%s', findings.query)
                # paged_findings = get_page_items(request, findings, 25)

                # findings = prefetch_for_findings(findings)
                # some over the top tag displaying happening...
                # findings = findings.prefetch_related('test__engagement__product__tagged_items__tag')

                # paged_findings.object_list = findings

            # for result in findings:
            #     if False:
            #         logger.debug('findings result: %s', vars(result))

            if search_finding_templates:
                watson_results = watson.filter(finding_templates, clean_query)
                finding_templates = finding_templates.filter(id__in=[watson.id for watson in watson_results])
                finding_templates = finding_templates[:max_results]
            else:
                finding_templates = None

            if search_tests:
                watson_results = watson.filter(tests, clean_query)
                tests = tests.filter(id__in=[watson.id for watson in watson_results])
                tests = tests.prefetch_related('engagement', 'engagement__product', 'test_type', 'tagged_items__tag', 'engagement__tagged_items__tag', 'engagement__product__tagged_items__tag')
                tests = tests[:max_results]
            else:
                tests = None

            if search_engagements:
                watson_results = watson.filter(engagements, clean_query)
                engagements = engagements.filter(id__in=[watson.id for watson in watson_results])
                engagements = engagements.prefetch_related('product', 'product__tagged_items__tag', 'tagged_items__tag')
                engagements = engagements[:max_results]
            else:
                engagements = None

            if search_products:
                watson_results = watson.filter(products, clean_query)
                products = products.filter(id__in=[watson.id for watson in watson_results])
                products = products.prefetch_related('tagged_items__tag')
                products = products[:max_results]
            else:
                products = None

            if search_endpoints:
                endpoints = endpoints.filter(Q(host__icontains=clean_query) | Q(path__icontains=clean_query) | Q(fqdn__icontains=clean_query) | Q(protocol__icontains=clean_query))
                endpoints = endpoints.prefetch_related('product', 'tagged_items__tag', 'product__tagged_items__tag')
                endpoints = endpoints[:max_results]
            else:
                endpoints = None

            if search_languages:
                languages = Languages.objects.filter(language__language__icontains=clean_query)
                languages = languages.prefetch_related('product', 'product__tagged_items__tag')
                languages = languages[:max_results]
            else:
                languages = None

            if search_technologies:
                app_analysis = App_Analysis.objects.filter(name__icontains=clean_query)
                app_analysis = app_analysis[:max_results]
            else:
                app_analysis = None

            # generic = watson.search(clean_query, models=(Finding,)).prefetch_related('object')
            generic = watson.search(clean_query).prefetch_related('object')[:max_results]

            # paging doesn't work well with django_watson
            # paged_generic = get_page_items(request, generic, 25)

            # generic = get_page_items(request, generic, 25)
            # generic = watson.search(original_clean_query)[:50].prefetch_related('object')
            # generic = watson.search("qander document 'CVE-2019-8331'")[:10].prefetch_related('object')
            # generic = watson.search("'CVE-2020-6754'")[:10].prefetch_related('object')
            # generic = watson.search(" 'ISEC-433'")[:10].prefetch_related('object')

            # for result in generic:
            #     if False:
            #         logger.debug('generic result: %s', vars(result))

        else:
            logger.debug('search form invalid')
            logger.debug(form.errors)
            form = SimpleSearchForm()

        add_breadcrumb(title="Simple Search", top_level=True, request=request)

        activetab = 'findings' if findings \
            else 'products' if products \
                else 'engagements' if engagements else \
                    'tests' if tests else \
                         'endpoint' if endpoints else \
                            'generic' if generic else \
                                'tagged'

    response = render(request, 'dojo/simple_search.html', {
        'clean_query': original_clean_query,
        'languages': languages,
        'app_analysis': app_analysis,
        'tests': tests,
        'findings': findings,
        'finding_templates': finding_templates,
        'filtered': findings_filter,
        'title_words': title_words,
        'component_words': component_words,
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
        'form': form,
        'activetab': activetab,
        'show_product_column': True,
        'generic': generic})

    if cookie:
        response.set_cookie("highlight", value=clean_query,
                            max_age=None, expires=None,
                            path='/', secure=True, httponly=False)
    else:
        response.delete_cookie("highlight", path='/')
    return response
