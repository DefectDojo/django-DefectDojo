import logging
import re
import csv
from openpyxl import Workbook
from openpyxl.styles import Font
from tempfile import NamedTemporaryFile


from datetime import datetime

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.http import Http404, HttpResponseForbidden, HttpResponse, QueryDict
from django.shortcuts import render, get_object_or_404
from django.utils import timezone

from dojo.filters import ReportFindingFilter, EndpointReportFilter, \
    EndpointFilter
from dojo.forms import ReportOptionsForm
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Dojo_User, Endpoint, Risk_Acceptance
from dojo.reports.widgets import CoverPage, PageBreak, TableOfContents, WYSIWYGContent, FindingList, EndpointList, \
    CustomReportJsonForm, ReportOptions, report_widget_factory
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting, get_period_counts_legacy, Product_Tab, \
    get_words_for_field
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.finding.queries import get_authorized_findings
from dojo.finding.views import get_filtered_findings

logger = logging.getLogger(__name__)


def down(request):
    return render(request, 'disabled.html')


def report_url_resolver(request):
    try:
        url_resolver = request.META['HTTP_X_FORWARDED_PROTO'] + "://" + request.META['HTTP_X_FORWARDED_FOR']
    except:
        hostname = request.META['HTTP_HOST']
        port_index = hostname.find(":")
        if port_index != -1:
            url_resolver = request.scheme + "://" + hostname[:port_index]
        else:
            url_resolver = request.scheme + "://" + hostname
    return url_resolver + ":" + request.META['SERVER_PORT']


def report_builder(request):
    add_breadcrumb(title="Report Builder", top_level=True, request=request)
    findings = get_authorized_findings(Permissions.Finding_View)
    findings = ReportFindingFilter(request.GET, queryset=findings)
    endpoints = Endpoint.objects.filter(finding__active=True,
                                        finding__verified=True,
                                        finding__false_p=False,
                                        finding__duplicate=False,
                                        finding__out_of_scope=False,
                                        ).distinct()

    endpoints = EndpointFilter(request.GET, queryset=endpoints, user=request.user)

    in_use_widgets = [ReportOptions(request=request)]
    available_widgets = [CoverPage(request=request),
                         TableOfContents(request=request),
                         WYSIWYGContent(request=request),
                         FindingList(request=request, findings=findings),
                         EndpointList(request=request, endpoints=endpoints),
                         PageBreak()]
    return render(request,
                  'dojo/report_builder.html',
                  {"available_widgets": available_widgets,
                   "in_use_widgets": in_use_widgets})


def custom_report(request):
    # saving the report
    form = CustomReportJsonForm(request.POST)
    host = report_url_resolver(request)
    if form.is_valid():
        selected_widgets = report_widget_factory(json_data=request.POST['json'], request=request, user=request.user,
                                                 finding_notes=False, finding_images=False, host=host)
        report_format = 'AsciiDoc'
        finding_notes = True
        finding_images = True

        if 'report-options' in selected_widgets:
            options = selected_widgets['report-options']
            report_format = options.report_type
            finding_notes = (options.include_finding_notes == '1')
            finding_images = (options.include_finding_images == '1')

        selected_widgets = report_widget_factory(json_data=request.POST['json'], request=request, user=request.user,
                                                 finding_notes=finding_notes, finding_images=finding_images, host=host)

        if report_format == 'AsciiDoc':
            widgets = list(selected_widgets.values())
            return render(request,
                          'dojo/custom_asciidoc_report.html',
                          {"widgets": widgets,
                           "host": host,
                           "finding_notes": finding_notes,
                           "finding_images": finding_images,
                           "user_id": request.user.id})
        elif report_format == 'HTML':
            widgets = list(selected_widgets.values())
            return render(request,
                          'dojo/custom_html_report.html',
                          {"widgets": widgets,
                           "host": host,
                           "finding_notes": finding_notes,
                           "finding_images": finding_images,
                           "user_id": request.user.id})
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()


def report_findings(request):
    findings = Finding.objects.filter()

    findings = ReportFindingFilter(request.GET, queryset=findings)

    title_words = get_words_for_field(Finding, 'title')
    component_words = get_words_for_field(Finding, 'component_name')

    paged_findings = get_page_items(request, findings.qs.distinct().order_by('numerical_severity'), 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    return render(request,
                  'dojo/report_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                    "component_words": component_words,
                   "title": "finding-list",
                   })


def report_endpoints(request):
    endpoints = Endpoint.objects.filter(finding__active=True,
                                        finding__verified=True,
                                        finding__false_p=False,
                                        finding__duplicate=False,
                                        finding__out_of_scope=False,
                                        ).distinct()

    endpoints = EndpointFilter(request.GET, queryset=endpoints, user=request.user)

    paged_endpoints = get_page_items(request, endpoints.qs, 25)

    return render(request,
                  'dojo/report_endpoints.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "title": "endpoint-list",
                   })


def report_cover_page(request):
    report_title = request.GET.get('title', 'Report')
    report_subtitle = request.GET.get('subtitle', '')
    report_info = request.GET.get('info', '')

    return render(request,
                  'dojo/report_cover_page.html',
                  {'report_title': report_title,
                   'report_subtitle': report_subtitle,
                   'report_info': report_info})


@user_is_authorized(Product_Type, Permissions.Product_Type_View, 'ptid')
def product_type_report(request, ptid):
    product_type = get_object_or_404(Product_Type, id=ptid)
    return generate_report(request, product_type)


@user_is_authorized(Product, Permissions.Product_View, 'pid')
def product_report(request, pid):
    product = get_object_or_404(Product, id=pid)
    return generate_report(request, product)


def product_findings_report(request):
    findings = get_authorized_findings(Permissions.Finding_View)
    return generate_report(request, findings)


@user_is_authorized(Engagement, Permissions.Engagement_View, 'eid')
def engagement_report(request, eid):
    engagement = get_object_or_404(Engagement, id=eid)
    return generate_report(request, engagement)


@user_is_authorized(Test, Permissions.Test_View, 'tid')
def test_report(request, tid):
    test = get_object_or_404(Test, id=tid)
    return generate_report(request, test)


@user_is_authorized(Endpoint, Permissions.Endpoint_View, 'eid')
def endpoint_report(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    return generate_report(request, endpoint, False)


@user_is_authorized(Endpoint, Permissions.Endpoint_View, 'eid')
def endpoint_host_report(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    return generate_report(request, endpoint, True)


@user_is_authorized(Product, Permissions.Product_View, 'pid')
def product_endpoint_report(request, pid):
    user = Dojo_User.objects.get(id=request.user.id)
    product = get_object_or_404(Product.objects.all().prefetch_related('engagement_set__test_set__test_type', 'engagement_set__test_set__environment'), id=pid)
    endpoint_ids = Endpoint.objects.filter(product=product,
                                           finding__active=True,
                                           finding__verified=True,
                                           finding__false_p=False,
                                           finding__duplicate=False,
                                           finding__out_of_scope=False,
                                           ).values_list('id', flat=True)

    endpoints = prefetch_related_endpoints_for_report(Endpoint.objects.filter(id__in=endpoint_ids))
    endpoints = EndpointReportFilter(request.GET, queryset=endpoints)

    paged_endpoints = get_page_items(request, endpoints.qs, 25)
    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_finding_images = int(request.GET.get('include_finding_images', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    include_disclaimer = int(request.GET.get('include_disclaimer', 0))
    disclaimer = get_system_setting('disclaimer')
    if include_disclaimer and len(disclaimer) == 0:
        disclaimer = 'Please configure in System Settings.'
    generate = "_generate" in request.GET
    add_breadcrumb(parent=product, title="Vulnerable Product Endpoints Report", top_level=False, request=request)
    report_form = ReportOptionsForm()

    template = "dojo/product_endpoint_pdf_report.html"
    report_name = "Product Endpoint Report: " + str(product)
    report_title = "Product Endpoint Report"
    report_subtitle = str(product)
    report_info = "Generated By %s on %s" % (
        user.get_full_name(), (timezone.now().strftime("%m/%d/%Y %I:%M%p %Z")))

    try:
        start_date = Finding.objects.filter(endpoints__in=endpoints.qs).order_by('date')[:1][0].date
    except:
        start_date = timezone.now()

    end_date = timezone.now()

    risk_acceptances = Risk_Acceptance.objects.filter(engagement__test__finding__endpoints__in=endpoints.qs)

    accepted_findings = [finding for ra in risk_acceptances
                         for finding in ra.accepted_findings.filter(endpoints__in=endpoints.qs)]

    verified_findings = Finding.objects.filter(endpoints__in=endpoints.qs,
                                               date__range=[start_date, end_date],
                                               false_p=False,
                                               verified=True,
                                               duplicate=False,
                                               out_of_scope=False)

    open_findings = Finding.objects.filter(endpoints__in=endpoints.qs,
                                           false_p=False,
                                           verified=True,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True)

    closed_findings = Finding.objects.filter(endpoints__in=endpoints.qs,
                                             false_p=False,
                                             verified=True,
                                             duplicate=False,
                                             out_of_scope=False,
                                             mitigated__isnull=False)
    if generate:
        report_form = ReportOptionsForm(request.GET)
        if report_format == 'AsciiDoc':
            return render(request,
                          'dojo/asciidoc_report.html',
                          {'product_type': None,
                           'product': product,
                           'accepted_findings': accepted_findings,
                           'open_findings': open_findings,
                           'closed_findings': closed_findings,
                           'verified_findings': verified_findings,
                           'engagement': None,
                           'test': None,
                           'endpoints': endpoints,
                           'endpoint': None,
                           'findings': None,
                           'include_finding_notes': include_finding_notes,
                           'include_finding_images': include_finding_images,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'include_disclaimer': include_disclaimer,
                           'disclaimer': disclaimer,
                           'user': request.user,
                           'title': 'Generate Report',
                           })
        elif report_format == 'HTML':
            return render(request,
                          template,
                          {'product_type': None,
                           'product': product,
                           'engagement': None,
                           'test': None,
                           'endpoint': None,
                           'endpoints': endpoints.qs,
                           'findings': None,
                           'include_finding_notes': include_finding_notes,
                           'include_finding_images': include_finding_images,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'include_disclaimer': include_disclaimer,
                           'disclaimer': disclaimer,
                           'user': request.user,
                           'title': 'Generate Report',
                           })
        else:
            raise Http404()

    product_tab = Product_Tab(product.id, "Product Endpoint Report", tab="endpoints")
    return render(request,
                  'dojo/request_endpoint_report.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "product_tab": product_tab,
                   'report_form': report_form,
                   "name": "Vulnerable Product Endpoints",
                   })


def generate_report(request, obj, host_view=False):
    user = Dojo_User.objects.get(id=request.user.id)
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    endpoints = None
    accepted_findings = None
    open_findings = None
    closed_findings = None
    verified_findings = None
    report_title = None
    report_subtitle = None
    report_info = "Generated By %s on %s" % (
        user.get_full_name(), (timezone.now().strftime("%m/%d/%Y %I:%M%p %Z")))

    if type(obj).__name__ == "Product_Type":
        user_has_permission_or_403(request.user, obj, Permissions.Product_Type_View)
    elif type(obj).__name__ == "Product":
        user_has_permission_or_403(request.user, obj, Permissions.Product_View)
    elif type(obj).__name__ == "Engagement":
        user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
    elif type(obj).__name__ == "Test":
        user_has_permission_or_403(request.user, obj, Permissions.Test_View)
    elif type(obj).__name__ == "Endpoint":
        user_has_permission_or_403(request.user, obj, Permissions.Endpoint_View)
    elif type(obj).__name__ == "QuerySet" or type(obj).__name__ == "CastTaggedQuerySet" or type(obj).__name__ == "TagulousCastTaggedQuerySet":
        # authorization taken care of by only selecting findings from product user is authed to see
        pass
    else:
        if obj is None:
            raise Exception('No object is given to generate report for')
        else:
            raise Exception(f'Report cannot be generated for object of type {type(obj).__name__}')

    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_finding_images = int(request.GET.get('include_finding_images', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    include_disclaimer = int(request.GET.get('include_disclaimer', 0))
    disclaimer = get_system_setting('disclaimer')
    if include_disclaimer and len(disclaimer) == 0:
        disclaimer = 'Please configure in System Settings.'
    generate = "_generate" in request.GET
    report_name = str(obj)
    report_type = type(obj).__name__
    add_breadcrumb(title="Generate Report", top_level=False, request=request)
    if type(obj).__name__ == "Product_Type":
        product_type = obj
        template = "dojo/product_type_pdf_report.html"
        report_name = "Product Type Report: " + str(product_type)
        report_title = "Product Type Report"
        report_subtitle = str(product_type)

        findings = ReportFindingFilter(request.GET, prod_type=product_type, queryset=prefetch_related_findings_for_report(Finding.objects.filter(
            test__engagement__product__prod_type=product_type)))
        products = Product.objects.filter(prod_type=product_type,
                                          engagement__test__finding__in=findings.qs).distinct()
        engagements = Engagement.objects.filter(product__prod_type=product_type,
                                                test__finding__in=findings.qs).distinct()
        tests = Test.objects.filter(engagement__product__prod_type=product_type,
                                    finding__in=findings.qs).distinct()
        if len(findings.qs) > 0:
            start_date = timezone.make_aware(datetime.combine(findings.qs.last().date, datetime.min.time()))
        else:
            start_date = timezone.now()

        end_date = timezone.now()

        r = relativedelta(end_date, start_date)
        months_between = (r.years * 12) + r.months
        # include current month
        months_between += 1

        endpoint_monthly_counts = get_period_counts_legacy(findings.qs.order_by('numerical_severity'), findings.qs.order_by('numerical_severity'), None,
                                                            months_between, start_date,
                                                            relative_delta='months')

        context = {'product_type': product_type,
                   'products': products,
                   'engagements': engagements,
                   'tests': tests,
                   'report_name': report_name,
                   'endpoint_opened_per_month': endpoint_monthly_counts[
                       'opened_per_period'] if endpoint_monthly_counts is not None else [],
                   'endpoint_active_findings': findings.qs.distinct().order_by('numerical_severity'),
                   'findings': findings.qs.distinct().order_by('numerical_severity'),
                   'include_finding_notes': include_finding_notes,
                   'include_finding_images': include_finding_images,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'include_disclaimer': include_disclaimer,
                   'disclaimer': disclaimer,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': report_title,
                   'host': report_url_resolver(request),
                   'user_id': request.user.id}

    elif type(obj).__name__ == "Product":
        product = obj
        template = "dojo/product_pdf_report.html"
        report_name = "Product Report: " + str(product)
        report_title = "Product Report"
        report_subtitle = str(product)
        findings = ReportFindingFilter(request.GET, product=product, queryset=prefetch_related_findings_for_report(Finding.objects.filter(
            test__engagement__product=product)))
        ids = set(finding.id for finding in findings.qs)
        engagements = Engagement.objects.filter(test__finding__id__in=ids).distinct()
        tests = Test.objects.filter(finding__id__in=ids).distinct()
        endpoints = Endpoint.objects.filter(product=product).distinct()
        context = {'product': product,
                   'engagements': engagements,
                   'tests': tests,
                   'report_name': report_name,
                   'findings': findings.qs.distinct().order_by('numerical_severity'),
                   'include_finding_notes': include_finding_notes,
                   'include_finding_images': include_finding_images,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'include_disclaimer': include_disclaimer,
                   'disclaimer': disclaimer,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': report_title,
                   'endpoints': endpoints,
                   'host': report_url_resolver(request),
                   'user_id': request.user.id}

    elif type(obj).__name__ == "Engagement":
        logger.debug('generating report for Engagement')
        engagement = obj
        findings = ReportFindingFilter(request.GET, engagement=engagement,
                                       queryset=prefetch_related_findings_for_report(Finding.objects.filter(test__engagement=engagement)))
        report_name = "Engagement Report: " + str(engagement)
        template = 'dojo/engagement_pdf_report.html'
        report_title = "Engagement Report"
        report_subtitle = str(engagement)

        ids = set(finding.id for finding in findings.qs)
        tests = Test.objects.filter(finding__id__in=ids).distinct()
        endpoints = Endpoint.objects.filter(product=engagement.product).distinct()

        context = {'engagement': engagement,
                   'tests': tests,
                   'report_name': report_name,
                   'findings': findings.qs.distinct().order_by('numerical_severity'),
                   'include_finding_notes': include_finding_notes,
                   'include_finding_images': include_finding_images,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'include_disclaimer': include_disclaimer,
                   'disclaimer': disclaimer,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': report_title,
                   'host': report_url_resolver(request),
                   'user_id': request.user.id,
                   'endpoints': endpoints}

    elif type(obj).__name__ == "Test":
        test = obj
        findings = ReportFindingFilter(request.GET, engagement=test.engagement,
                                       queryset=prefetch_related_findings_for_report(Finding.objects.filter(test=test)))
        template = "dojo/test_pdf_report.html"
        report_name = "Test Report: " + str(test)
        report_title = "Test Report"
        report_subtitle = str(test)

        context = {'test': test,
                   'report_name': report_name,
                   'findings': findings.qs.distinct().order_by('numerical_severity'),
                   'include_finding_notes': include_finding_notes,
                   'include_finding_images': include_finding_images,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'include_disclaimer': include_disclaimer,
                   'disclaimer': disclaimer,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': report_title,
                   'host': report_url_resolver(request),
                   'user_id': request.user.id}

    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        if host_view:
            report_name = "Endpoint Host Report: " + endpoint.host
            endpoints = Endpoint.objects.filter(host=endpoint.host,
                                                product=endpoint.product).distinct()
            report_title = "Endpoint Host Report"
            report_subtitle = endpoint.host
        else:
            report_name = "Endpoint Report: " + str(endpoint)
            endpoints = Endpoint.objects.filter(pk=endpoint.id).distinct()
            report_title = "Endpoint Report"
            report_subtitle = str(endpoint)
        report_type = "Endpoint"
        template = 'dojo/endpoint_pdf_report.html'
        findings = ReportFindingFilter(request.GET,
                                       queryset=prefetch_related_findings_for_report(Finding.objects.filter(endpoints__in=endpoints)))

        context = {'endpoint': endpoint,
                   'endpoints': endpoints,
                   'report_name': report_name,
                   'findings': findings.qs.distinct().order_by('numerical_severity'),
                   'include_finding_notes': include_finding_notes,
                   'include_finding_images': include_finding_images,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'include_disclaimer': include_disclaimer,
                   'disclaimer': disclaimer,
                   'user': user,
                   'team_name': get_system_setting('team_name'),
                   'title': report_title,
                   'host': report_url_resolver(request),
                   'user_id': request.user.id}
    elif type(obj).__name__ == "QuerySet" or type(obj).__name__ == "CastTaggedQuerySet":
        findings = ReportFindingFilter(request.GET,
                                             queryset=prefetch_related_findings_for_report(obj).distinct())
        report_name = 'Finding'
        report_type = 'Finding'
        template = 'dojo/finding_pdf_report.html'
        report_title = "Finding Report"
        report_subtitle = ''

        context = {'findings': findings.qs.distinct().order_by('numerical_severity'),
                   'report_name': report_name,
                   'include_finding_notes': include_finding_notes,
                   'include_finding_images': include_finding_images,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'include_disclaimer': include_disclaimer,
                   'disclaimer': disclaimer,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': report_title,
                   'host': report_url_resolver(request),
                   'user_id': request.user.id}
    else:
        raise Http404()

    report_form = ReportOptionsForm()

    if generate:
        report_form = ReportOptionsForm(request.GET)
        if report_format == 'AsciiDoc':
            return render(request,
                          'dojo/asciidoc_report.html',
                          {'product_type': product_type,
                           'product': product,
                           'engagement': engagement,
                           'test': test,
                           'endpoint': endpoint,
                           'findings': findings.qs.distinct().order_by('numerical_severity'),
                           'include_finding_notes': include_finding_notes,
                           'include_finding_images': include_finding_images,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'include_disclaimer': include_disclaimer,
                           'disclaimer': disclaimer,
                           'user': user,
                           'team_name': settings.TEAM_NAME,
                           'title': report_title,
                           'user_id': request.user.id,
                           'host': report_url_resolver(request),
                           'host_view': host_view,
                           'context': context,
                           })
        elif report_format == 'HTML':
            return render(request,
                          template,
                          {'product_type': product_type,
                           'product': product,
                           'engagement': engagement,
                           'report_name': report_name,
                           'test': test,
                           'endpoint': endpoint,
                           'endpoints': endpoints,
                           'findings': findings.qs.distinct().order_by('numerical_severity'),
                           'include_finding_notes': include_finding_notes,
                           'include_finding_images': include_finding_images,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'include_disclaimer': include_disclaimer,
                           'disclaimer': disclaimer,
                           'user': user,
                           'team_name': settings.TEAM_NAME,
                           'title': report_title,
                           'user_id': request.user.id,
                           'host': "",
                           'host_view': host_view,
                           'context': context,
                           })

        else:
            raise Http404()
    paged_findings = get_page_items(request, findings.qs.distinct().order_by('numerical_severity'), 25)

    product_tab = None
    if engagement:
        product_tab = Product_Tab(engagement.product.id, title="Engagement Report", tab="engagements")
        product_tab.setEngagement(engagement)
    elif test:
        product_tab = Product_Tab(test.engagement.product.id, title="Test Report", tab="engagements")
        product_tab.setEngagement(test.engagement)
    elif product:
        product_tab = Product_Tab(product.id, title="Product Report", tab="findings")
    elif endpoints:
        if host_view:
            product_tab = Product_Tab(endpoint.product.id, title="Endpoint Host Report", tab="endpoints")
        else:
            product_tab = Product_Tab(endpoint.product.id, title="Endpoint Report", tab="endpoints")

    return render(request, 'dojo/request_report.html',
                  {'product_type': product_type,
                   'product': product,
                   'product_tab': product_tab,
                   'engagement': engagement,
                   'test': test,
                   'endpoint': endpoint,
                   'findings': findings,
                   'paged_findings': paged_findings,
                   'report_form': report_form,
                   'host_view': host_view,
                   'context': context,
                   })


def prefetch_related_findings_for_report(findings):
    return findings.prefetch_related('test',
                                     'test__engagement__product',
                                     'test__engagement__product__prod_type',
                                     'risk_acceptance_set',
                                     'risk_acceptance_set__accepted_findings',
                                     'burprawrequestresponse_set',
                                     'endpoints',
                                     'tags',
                                     'notes',
                                     'files',
                                     'reporter',
                                     'mitigated_by'
                                     )


def prefetch_related_endpoints_for_report(endpoints):
    return endpoints.prefetch_related(
                                      'product',
                                      'tags'
                                     )


def generate_quick_report(request, findings, obj=None):
    product = engagement = test = None

    if obj:
        if type(obj).__name__ == "Product":
            product = obj
        elif type(obj).__name__ == "Engagement":
            engagement = obj
        elif type(obj).__name__ == "Test":
            test = obj

    return render(request, 'dojo/finding_pdf_report.html', {
                    'report_name': 'Finding Report',
                    'product': product,
                    'engagement': engagement,
                    'test': test,
                    'findings': findings,
                    'user': request.user,
                    'team_name': settings.TEAM_NAME,
                    'title': 'Finding Report',
                    'user_id': request.user.id,
                  })


def get_list_index(list, index):
    try:
        element = list[index]
    except Exception as e:
        element = None
    return element


def get_findings(request):
    url = request.META.get('QUERY_STRING')
    if not url:
        raise Http404('Please use the report button when viewing findings')
    else:
        if url.startswith('url='):
            url = url[4:]

    views = ['all', 'open', 'inactive', 'verified',
             'closed', 'accepted', 'out_of_scope',
             'false_positive', 'inactive']
    # request.path = url
    obj_name = obj_id = view = query = None
    path_items = list(filter(None, re.split('/|\?', url))) # noqa W605

    try:
        finding_index = path_items.index('finding')
    except ValueError:
        finding_index = -1
    # There is a engagement or product here
    if finding_index > 0:
        # path_items ['product', '1', 'finding', 'closed', 'test__engagement__product=1']
        obj_name = get_list_index(path_items, 0)
        obj_id = get_list_index(path_items, 1)
        view = get_list_index(path_items, 3)
        query = get_list_index(path_items, 4)
        # Try to catch a mix up
        query = query if view in views else view
    # This is findings only. Accomodate view and query
    elif finding_index == 0:
        # path_items ['finding', 'closed', 'title=blah']
        obj_name = get_list_index(path_items, 0)
        view = get_list_index(path_items, 1)
        query = get_list_index(path_items, 2)
        # Try to catch a mix up
        query = query if view in views else view
    # This is a test or engagement only
    elif finding_index == -1:
        # path_items ['test', '1', 'test__engagement__product=1']
        obj_name = get_list_index(path_items, 0)
        obj_id = get_list_index(path_items, 1)
        query = get_list_index(path_items, 2)

    filter_name = None
    if view:
        if view == 'open':
            filter_name = 'Open'
        elif view == 'inactive':
            filter_name = 'Inactive'
        elif view == 'verified':
            filter_name = 'Verified'
        elif view == 'closed':
            filter_name = 'Closed'
        elif view == 'accepted':
            filter_name = 'Accepted'
        elif view == 'out_of_scope':
            filter_name = 'Out of Scope'
        elif view == 'false_positive':
            filter_name = 'False Positive'

    obj = pid = eid = tid = None
    if obj_id:
        if 'product' in obj_name:
            pid = obj_id
            obj = get_object_or_404(Product, id=pid)
            user_has_permission_or_403(request.user, obj, Permissions.Product_View)
        elif 'engagement' in obj_name:
            eid = obj_id
            obj = get_object_or_404(Engagement, id=eid)
            user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        elif 'test' in obj_name:
            tid = obj_id
            obj = get_object_or_404(Test, id=tid)
            user_has_permission_or_403(request.user, obj, Permissions.Test_View)

    request.GET = QueryDict(query)
    findings = get_filtered_findings(request, pid, eid, tid, filter_name).qs

    return findings, obj


def quick_report(request):
    findings, obj = get_findings(request)
    return generate_quick_report(request, findings, obj)


def get_excludes():
    return ['SEVERITIES', 'age', 'github_issue', 'jira_issue', 'objects', 'risk_acceptance',
    'test__engagement__product__authorized_group', 'test__engagement__product__member',
    'test__engagement__product__prod_type__authorized_group', 'test__engagement__product__prod_type__member',
    'unsaved_endpoints']


def get_foreign_keys():
    return ['defect_review_requested_by', 'duplicate_finding', 'finding_group', 'last_reviewed_by',
        'mitigated_by', 'reporter', 'review_requested_by', 'sonarqube_issue', 'test']


def csv_export(request):
    findings, obj = get_findings(request)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=findings.csv'

    writer = csv.writer(response)

    first_row = True
    for finding in findings:
        if first_row:
            fields = []
            for key in dir(finding):
                if key not in get_excludes() and not callable(getattr(finding, key)) and not key.startswith('_'):
                    fields.append(key)
            fields.append('test')
            fields.append('found_by')
            fields.append('engagement_id')
            fields.append('engagement')
            fields.append('product_id')
            fields.append('product')
            fields.append('endpoints')

            writer.writerow(fields)

            first_row = False
        if not first_row:
            fields = []
            for key in dir(finding):
                if key not in get_excludes() and not callable(getattr(finding, key)) and not key.startswith('_'):
                    value = finding.__dict__.get(key)
                    if key in get_foreign_keys() and getattr(finding, key):
                        value = str(getattr(finding, key))
                    if value and isinstance(value, str):
                        value = value.replace('\n', ' NEWLINE ').replace('\r', '')
                    fields.append(value)
            fields.append(finding.test.title)
            fields.append(finding.test.test_type.name)
            fields.append(finding.test.engagement.id)
            fields.append(finding.test.engagement.name)
            fields.append(finding.test.engagement.product.id)
            fields.append(finding.test.engagement.product.name)

            endpoint_value = ''
            num_endpoints = 0
            for endpoint in finding.endpoints.all():
                num_endpoints += 1
                if num_endpoints > 5:
                    endpoint_value += '...'
                    break
                endpoint_value += f'{str(endpoint)}; '
            if endpoint_value.endswith('; '):
                endpoint_value = endpoint_value[:-2]
            fields.append(endpoint_value)

            writer.writerow(fields)

    return response


def excel_export(request):
    findings, obj = get_findings(request)

    workbook = Workbook()
    workbook.iso_dates = True
    worksheet = workbook.active
    worksheet.title = 'Findings'

    font_bold = Font(bold=True)

    row_num = 1
    for finding in findings:
        if row_num == 1:
            col_num = 1
            for key in dir(finding):
                if key not in get_excludes() and not callable(getattr(finding, key)) and not key.startswith('_'):
                    cell = worksheet.cell(row=row_num, column=col_num, value=key)
                    cell.font = font_bold
                    col_num += 1
            cell = worksheet.cell(row=row_num, column=col_num, value='found_by')
            cell.font = font_bold
            col_num += 1
            worksheet.cell(row=row_num, column=col_num, value='engagement_id')
            cell = cell.font = font_bold
            col_num += 1
            cell = worksheet.cell(row=row_num, column=col_num, value='engagement')
            cell.font = font_bold
            col_num += 1
            cell = worksheet.cell(row=row_num, column=col_num, value='product_id')
            cell.font = font_bold
            col_num += 1
            cell = worksheet.cell(row=row_num, column=col_num, value='product')
            cell.font = font_bold
            col_num += 1
            cell = worksheet.cell(row=row_num, column=col_num, value='endpoints')
            cell.font = font_bold

            row_num = 2
        if row_num > 1:
            col_num = 1
            for key in dir(finding):
                if key not in get_excludes() and not callable(getattr(finding, key)) and not key.startswith('_'):
                    value = finding.__dict__.get(key)
                    if key in get_foreign_keys() and getattr(finding, key):
                        value = str(getattr(finding, key))
                    if value and isinstance(value, datetime):
                        value = value.replace(tzinfo=None)
                    worksheet.cell(row=row_num, column=col_num, value=value)
                    col_num += 1
            worksheet.cell(row=row_num, column=col_num, value=finding.test.test_type.name)
            col_num += 1
            worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.id)
            col_num += 1
            worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.name)
            col_num += 1
            worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.product.id)
            col_num += 1
            worksheet.cell(row=row_num, column=col_num, value=finding.test.engagement.product.name)
            col_num += 1

            endpoint_value = ''
            num_endpoints = 0
            for endpoint in finding.endpoints.all():
                num_endpoints += 1
                if num_endpoints > 5:
                    endpoint_value += '...'
                    break
                endpoint_value += f'{str(endpoint)}; \n'
            if endpoint_value.endswith('; \n'):
                endpoint_value = endpoint_value[:-3]
            worksheet.cell(row=row_num, column=col_num, value=endpoint_value)

        row_num += 1

    with NamedTemporaryFile() as tmp:
        workbook.save(tmp.name)
        tmp.seek(0)
        stream = tmp.read()

    response = HttpResponse(
        content=stream,
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = 'attachment; filename=findings.xlsx'
    return response
