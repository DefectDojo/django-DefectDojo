import logging

from django.shortcuts import render
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
import shlex

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
            original_clean_query = clean_query

            operators, keywords = parse_search_query(clean_query)

            logger.debug('cve clean_query: [%s]', clean_query)

            search_tag = "tag" in operators or not operators
            search_tags = "tags" in operators or not operators
            search_finding_id = "id" in operators.keys()
            search_findings = "finding" in operators.keys() or "cve" in operators.keys() or "id" in operators.keys() or not operators
            # experiment, always search findings even when only supplying a tag or something else
            search_findings = True
            search_finding_templates = "template" in operators.keys() or not operators
            search_tests = "test" in operators.keys() or not operators
            search_engagements = "engagement" in operators.keys() or not operators
            search_products = "product" in operators.keys() or not operators
            search_endpoints = "endpoint" in operators.keys() or not operators
            search_languages = "language" in operators.keys() or not operators
            search_technologies = "technology" in operators.keys() or not operators

            authorized_findings = Finding.objects.all()
            authorized_tests = Test.objects.all()
            authorized_engagements = Engagement.objects.all()
            authorized_products = Product.objects.all()
            authorized_endpoints = Endpoint.objects.all()
            authorized_finding_templates = Finding_Template.objects.all()

            if not request.user.is_staff:
                authorized_findings = authorized_findings.filter(Q(test__engagement__product__authorized_users__in=[request.user]) | Q(test__engagement__product__prod_type__authorized_users__in=[request.user]))
                authorized_tests = authorized_tests.filter(Q(engagement__product__authorized_users__in=[request.user]) | Q(engagement__product__prod_type__authorized_users__in=[request.user]))
                authorized_engagements = authorized_engagements.filter(Q(product__authorized_users__in=[request.user]) | Q(product__prod_type__authorized_users__in=[request.user]))
                authorized_products = authorized_products.filter(Q(authorized_users__in=[request.user]) | Q(prod_type__authorized_users__in=[request.user]))
                authorized_endpoints = authorized_endpoints.filter(Q(product__authorized_users__in=[request.user]) | Q(product__prod_type__authorized_users__in=[request.user]))
                # can't filter templates

            # TODO better get findings in their own query and match on id. that would allow filtering on additional fields such cve, prod_id, etc.

            findings = authorized_findings
            tests = authorized_tests
            engagements = authorized_engagements
            products = authorized_products
            endpoints = authorized_endpoints

            findings_filter = None
            title_words = None
            component_words = None

            keywords_query = ' '.join(keywords)

            if search_findings:
                findings_filter = OpenFindingFilter(request.GET, queryset=authorized_findings, user=request.user, pid=None, prefix='finding')
                # setting initial values for filters is not supported and discouraged: https://django-filter.readthedocs.io/en/stable/guide/tips.html#using-initial-values-as-defaults
                # we could try to modify request.GET before generating the filter, but for now we'll leave it as is

                title_words = get_words_for_field(authorized_findings, 'title')
                component_words = get_words_for_field(authorized_findings, 'component_name')

                findings = apply_tag_filters(findings, operators, findings_filter)
                findings = apply_endpoint_filter(findings, operators, findings_filter)
                findings = apply_cve_filter(findings, operators, findings_filter)

                if keywords_query:
                    logger.debug('going watson with: %s', keywords_query)
                    watson_results = watson.filter(findings_filter.qs, keywords_query)[:max_results]
                    findings = findings.filter(id__in=[watson.id for watson in watson_results])

                # prefetch after watson to avoid inavlid query errors due to watson not understanding prefetching
                findings = prefetch_for_findings(findings)
                # some over the top tag displaying happening...
                findings = findings.prefetch_related('test__engagement__product__tags')

                findings = findings[:max_results]
            else:
                findings = None
                findings_filter = None
                component_words = None

            if search_tag or search_tags:
                Q1, Q2 = Q(), Q()

                if search_tag:  # single tag => contains
                    tag = operators['tag'] if 'tag' in operators else keywords
                    tag = ','.join(tag)  # contains needs a single value
                    Q1 = Q(tags__name__contains=tag)

                if search_tags:  # multiple tags => in
                    tags = operators['tags'] if 'tags' in operators else keywords
                    Q2 = Q(tags__name__in=tags)

            if Q1 or Q2:
                tagged_findings = authorized_findings.filter(Q1 | Q2).distinct()[:max_results]
                tagged_finding_templates = authorized_finding_templates.filter(Q1 | Q2).distinct()[:max_results]
                tagged_tests = authorized_tests.filter(Q1 | Q2).distinct()[:max_results]
                tagged_engagements = authorized_engagements.filter(Q1 | Q2).distinct()[:max_results]
                tagged_products = authorized_products.filter(Q1 | Q2).distinct()[:max_results]
                tagged_endpoints = authorized_endpoints.filter(Q1 | Q2).distinct()[:max_results]
            else:
                tagged_findings = None
                tagged_finding_templates = None
                tagged_tests = None
                tagged_engagements = None
                tagged_products = None
                tagged_endpoints = None

            tagged_results = tagged_findings or tagged_finding_templates or tagged_tests or tagged_engagements or tagged_products or tagged_endpoints

            if search_finding_templates:
                finding_templates = authorized_finding_templates
                finding_templates = apply_tag_filters(finding_templates, operators)

                if keywords_query:
                    watson_results = watson.filter(authorized_finding_templates, keywords_query)
                    finding_templates = finding_templates.filter(id__in=[watson.id for watson in watson_results])

                finding_templates = finding_templates[:max_results]
            else:
                finding_templates = None

            if search_tests:
                tests = authorized_tests
                tests = apply_tag_filters(tests, operators)

                if keywords_query:
                    watson_results = watson.filter(tests, keywords_query)
                    tests = tests.filter(id__in=[watson.id for watson in watson_results])

                tests = tests.prefetch_related('engagement', 'engagement__product', 'test_type', 'tags', 'engagement__tags', 'engagement__product__tags')
                tests = tests[:max_results]
            else:
                tests = None

            if search_engagements:
                engagements = authorized_engagements
                engagements = apply_tag_filters(engagements, operators)

                if keywords_query:
                    watson_results = watson.filter(engagements, keywords_query)
                    engagements = engagements.filter(id__in=[watson.id for watson in watson_results])

                engagements = engagements.prefetch_related('product', 'product__tags', 'tags')
                engagements = engagements[:max_results]
            else:
                engagements = None

            if search_products:
                products = authorized_products
                products = apply_tag_filters(products, operators)

                if keywords_query:
                    watson_results = watson.filter(products, keywords_query)
                    products = products.filter(id__in=[watson.id for watson in watson_results])

                products = products.prefetch_related('tags')
                products = products[:max_results]
            else:
                products = None

            if search_endpoints:
                endpoints = authorized_endpoints
                endpoints = apply_tag_filters(endpoints, operators)

                endpoints = endpoints.filter(Q(host__icontains=keywords_query) | Q(path__icontains=keywords_query) | Q(fqdn__icontains=keywords_query) | Q(protocol__icontains=keywords_query))
                endpoints = endpoints.prefetch_related('product', 'tags', 'product__tags')
                endpoints = endpoints[:max_results]
            else:
                endpoints = None

            if search_languages:
                languages = Languages.objects.filter(language__language__icontains=keywords_query)
                languages = languages.prefetch_related('product', 'product__tags')
                languages = languages[:max_results]
            else:
                languages = None

            if search_technologies:
                app_analysis = App_Analysis.objects.filter(name__icontains=keywords_query)
                app_analysis = app_analysis[:max_results]
            else:
                app_analysis = None

            # generic = watson.search(keywords_query, models=(Finding,)).prefetch_related('object')
            generic = watson.search(keywords_query).prefetch_related('object')[:max_results]

            # paging doesn't work well with django_watson
            # paged_generic = get_page_items(request, generic, 25)

            # generic = get_page_items(request, generic, 25)
            # generic = watson.search(original_clean_query)[:50].prefetch_related('object')
            # generic = watson.search("qander document 'CVE-2019-8331'")[:10].prefetch_related('object')
            # generic = watson.search("'CVE-2020-6754'")[:10].prefetch_related('object')
            # generic = watson.search(" 'ISEC-433'")[:10].prefetch_related('object')

        else:
            logger.debug(form.errors)
            form = SimpleSearchForm()

        add_breadcrumb(title="Simple Search", top_level=True, request=request)

        activetab = 'findings' if findings \
            else 'products' if products \
                else 'engagements' if engagements else \
                    'tests' if tests else \
                         'endpoint' if endpoints else \
                            'tagged' if tagged_results else \
                                'generic'

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
        response.set_cookie("highlight", value=keywords_query,
                            max_age=None, expires=None,
                            path='/', secure=True, httponly=False)
    else:
        response.delete_cookie("highlight", path='/')
    return response

    '''
    query:     some keywords
    operators: {}
    keywords:  ['some', 'keywords']

    query:     some key-word
    operators: {}
    keywords:  ['some', 'key-word']

    query:     keyword with "space inside"
    operators: {}
    keywords:  ['keyword', 'with', 'space inside']

    query:     tag:anchore word tags:php
    operators: {'tag': ['anchore'], 'tags': ['php']}
    keywords:  ['word']

    query:     tags:php,magento
    operators: {'tags': ['php,magento']}
    keywords:  []

    query:     tags:php tags:magento
    operators: {'tags': ['php', 'magento']}
    keywords:  []

    query:     tags:"php, magento"
    operators: {'tags': ['php, magento']}
    keywords:  []

    query:     tags:anchorse some "space inside"
    operators: {'tags': ['anchorse']}
    keywords:  ['some', 'space inside']

    query:     tags:anchore cve:CVE-2020-1234 jquery
    operators: {'tags': ['anchore'], 'cve': ["'CVE-2020-1234'"]}
    keywords:  ['jquery']
    '''


# it's not google grade parsing, but let's do some basic stuff right
def parse_search_query(clean_query):
    operators = {}  # operator:parameter formatted in searchquery, i.e. tag:php
    keywords = []  # just keywords to search on

    query_parts = shlex.split(clean_query)

    for query_part in query_parts:
        if ':' in query_part:
            query_part_split = query_part.split(':')

            operator = query_part_split[0]
            parameter = query_part_split[1].strip()

            if operator not in operators:
                operators[operator] = []

            operators[operator].append(cve_fix(parameter))
        else:
            keywords.append(cve_fix(query_part))

    logger.debug('query:     %s' % clean_query)
    logger.debug('operators: %s' % operators)
    logger.debug('keywords:  %s' % keywords)

    return operators, keywords


def cve_fix(keyword):
    # if the query contains hyphens, django-watson will escape these leading to problems.
    # for cve we make this workaround because we really want to be able to search for CVEs
    # problem still remains for other case, i.e. searching for "valentijn-scholten" will return no results because of the hyphen.
    # see:
    # - https://github.com/etianen/django-watson/issues/223
    # - https://github.com/DefectDojo/django-DefectDojo/issues/1092
    # - https://github.com/DefectDojo/django-DefectDojo/issues/2081

    if bool(cve_pattern.match(keyword)):
        return '\'' + keyword + '\''

    return keyword


def apply_tag_filters(qs, operators, findings_filter=None):
    if 'tag' in operators:
        value = operators['tag']
        value = ','.join(value)  # contains need a single value
        findings = findings.filter(tags__name__contains=value)

    if 'tags' in operators:
        value = operators['tags']
        qs = qs.filter(tags__name__in=value)

    return qs


def apply_endpoint_filter(qs, operators, findings_filter=None):
    if 'endpoint' in operators:
        qs = qs.filter(endpoints__host__contains=','.join(operators['endpoint']))

    return qs


def apply_cve_filter(qs, operators, findings_filter=None):
    if 'cve' in operators:
        value = operators[operator]
        qs = qs.filter(Q(cve=value) | Q(cve__isnull=True))  # only check cve if it's present

    return qs
