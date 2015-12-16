# #  reports
import logging
import mimetypes
import os
import urllib
from datetime import datetime
from math import ceil

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import Http404, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404
from pytz import timezone

from dojo.celery import app
from dojo.filters import ReportFindingFilter, ReportAuthedFindingFilter, EndpointReportFilter, ReportFilter
from dojo.forms import ReportOptionsForm, DeleteReportForm
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Dojo_User, Endpoint, Report, Risk_Acceptance
from dojo.tasks import async_pdf_report
from dojo.utils import get_page_items, add_breadcrumb, get_period_counts
from dojo.endpoint.views import get_endpoint_ids

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
        datefmt='%d/%b/%Y %H:%M:%S',
        filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


def download_report(request, rid):
    report = get_object_or_404(Report, id=rid)
    original_filename = report.file.name
    file_path = report.file.path
    fp = open(file_path, 'rb')
    response = HttpResponse(fp.read())
    fp.close()

    type, encoding = mimetypes.guess_type(original_filename)
    if type is None:
        type = 'application/octet-stream'
    response['Content-Type'] = type
    response['Content-Length'] = str(os.stat(file_path).st_size)
    if encoding is not None:
        response['Content-Encoding'] = encoding

    # To inspect details for the below code, see http://greenbytes.de/tech/tc2231/
    if u'WebKit' in request.META['HTTP_USER_AGENT']:
        # Safari 3.0 and Chrome 2.0 accepts UTF-8 encoded string directly.
        filename_header = 'filename=%s' % original_filename.encode('utf-8')
    elif u'MSIE' in request.META['HTTP_USER_AGENT']:
        # IE does not support internationalized filename at all.
        # It can only recognize internationalized URL, so we do the trick via routing rules.
        filename_header = ''
    else:
        # For others like Firefox, we follow RFC2231 (encoding extension in HTTP headers).
        filename_header = 'filename*=UTF-8\'\'%s' % urllib.quote(original_filename.encode('utf-8'))
    response['Content-Disposition'] = 'attachment; ' + filename_header
    report.status = 'downloaded'
    report.save()
    return response


@user_passes_test(lambda u: u.is_staff)
def delete_report(request, rid):
    report = get_object_or_404(Report, id=rid)

    form = DeleteReportForm(instance=report)

    if request.method == 'POST':
        form = DeleteReportForm(request.POST, instance=report)
        if form.is_valid():
            report.file.delete()
            report.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Report deleted successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('reports'))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Unable to delete Report, please try again.',
                                 extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


def report_status(request, rid):
    report = get_object_or_404(Report, id=rid)
    return JsonResponse({'status': report.status,
                         'id': report.id})


def report_cover_page(request):
    report_title = request.GET.get('title', 'Report')
    report_subtitle = request.GET.get('subtitle', '')
    report_info = request.GET.get('info', '')

    return render(request,
                  'dojo/report_cover_page.html',
                  {'report_title': report_title,
                   'report_subtitle': report_subtitle,
                   'report_info': report_info})


def revoke_report(request, rid):
    report = get_object_or_404(Report, id=rid)

    form = DeleteReportForm(instance=report)

    if request.method == 'POST':
        form = DeleteReportForm(request.POST, instance=report)
        if form.is_valid():
            app.control.revoke(report.task_id, terminate=True)
            report.file.delete()
            report.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Report generation stopped and report deleted successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('reports'))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Unable to stop Report, please try again.',
                                 extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


def reports(request):
    if request.user.is_staff:
        reports = Report.objects.all()
    else:
        reports = Report.objects.filter(requester=request.user)

    reports = ReportFilter(request.GET, queryset=reports)

    paged_reports = get_page_items(request, reports, 25)

    add_breadcrumb(title="Report List", top_level=True, request=request)

    return render(request,
                  'dojo/reports.html',
                  {'report_list': reports,
                   'reports': paged_reports})


def regen_report(request, rid):
    report = get_object_or_404(Report, id=rid)
    return HttpResponseRedirect(report.options + "&regen=" + rid)


@user_passes_test(lambda u: u.is_staff)
def product_type_report(request, ptid):
    product_type = get_object_or_404(Product_Type, id=ptid)
    return generate_report(request, product_type)


def product_report(request, pid):
    product = get_object_or_404(Product, id=pid)
    if request.user.is_staff or request.user in product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied
    return generate_report(request, product)


def product_findings_report(request):
    if request.user.is_staff:
        findings = Finding.objects.filter().distinct()
    else:
        findings = Finding.objects.filter(test__engagement__product__authorized_users__in=[request.user]).distinct()

    return generate_report(request, findings)


@user_passes_test(lambda u: u.is_staff)
def engagement_report(request, eid):
    engagement = get_object_or_404(Engagement, id=eid)
    return generate_report(request, engagement)


@user_passes_test(lambda u: u.is_staff)
def test_report(request, tid):
    test = get_object_or_404(Test, id=tid)
    return generate_report(request, test)


def endpoint_report(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    if request.user.is_staff or request.user in endpoint.product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    return generate_report(request, endpoint)


def product_endpoint_report(request, pid):
    user = Dojo_User.objects.get(id=request.user.id)
    product = get_object_or_404(Product, id=pid)
    endpoints = Endpoint.objects.filter(product=product,
                                        finding__active=True,
                                        finding__verified=True,
                                        finding__false_p=False,
                                        finding__duplicate=False,
                                        finding__out_of_scope=False,
                                        )

    ids = get_endpoint_ids(endpoints)

    endpoints = Endpoint.objects.filter(id__in=ids)

    if request.user.is_staff or request.user in product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    endpoints = EndpointReportFilter(request.GET, queryset=endpoints)

    endpoints = endpoints.qs.order_by('finding__numerical_severity')

    paged_endpoints = get_page_items(request, endpoints, 25)
    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    generate = "_generate" in request.GET
    add_breadcrumb(parent=product, title="Vulnerable Product Endpoints Report", top_level=False, request=request)
    report_form = ReportOptionsForm()

    filename = "product_endpoint_report.pdf"
    template = "dojo/product_endpoint_pdf_report.html"
    report_name = "Product Endpoint Report: " + str(product)
    report_title = "Product Endpoint Report"
    report_subtitle = str(product)
    report_info = "Generated By %s on %s" % (
        user.get_full_name(), (datetime.now(tz=localtz).strftime("%m/%d/%Y %I:%M%p %Z")))

    try:
        start_date = Finding.objects.filter(endpoints__in=endpoints).order_by('date')[:1][0].date
    except:
        start_date = localtz.localize(datetime.today())

    end_date = localtz.localize(datetime.today())

    risk_acceptances = Risk_Acceptance.objects.filter(engagement__test__finding__endpoints__in=endpoints)

    accepted_findings = [finding for ra in risk_acceptances
                         for finding in ra.accepted_findings.filter(endpoints__in=endpoints)]

    verified_findings = Finding.objects.filter(endpoints__in=endpoints,
                                               date__range=[start_date, end_date],
                                               false_p=False,
                                               verified=True,
                                               duplicate=False,
                                               out_of_scope=False)

    open_findings = Finding.objects.filter(endpoints__in=endpoints,
                                           false_p=False,
                                           verified=True,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True)

    closed_findings = Finding.objects.filter(endpoints__in=endpoints,
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
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'user': request.user,
                           'title': 'Generate Report',
                           })
        elif report_format == 'PDF':
            # lets create the report object and send it in to celery task
            if 'regen' in request.GET:
                # we should already have a report object, lets get and use it
                report = get_object_or_404(Report, id=request.GET['regen'])
                report.datetime = datetime.now(tz=localtz)
                report.status = 'requested'
                if report.requester.username != request.user.username:
                    report.requester = request.user
            else:
                report = Report(name="Product Endpoints " + str(product),
                                type="Product Endpoint",
                                format='PDF',
                                requester=request.user,
                                task_id='tbd',
                                options=request.path + "?" + request.GET.urlencode())
            report.save()
            async_pdf_report.delay(report=report,
                                   template=template,
                                   filename=filename,
                                   report_title=report_title,
                                   report_subtitle=report_subtitle,
                                   report_info=report_info,
                                   context={'product': product,
                                            'endpoints': endpoints,
                                            'accepted_findings': accepted_findings,
                                            'open_findings': open_findings,
                                            'closed_findings': closed_findings,
                                            'verified_findings': verified_findings,
                                            'report_name': report_name,
                                            'include_finding_notes': include_finding_notes,
                                            'include_executive_summary': include_executive_summary,
                                            'include_table_of_contents': include_table_of_contents,
                                            'user': user,
                                            'team_name': settings.TEAM_NAME,
                                            'title': 'Generate Report',
                                            'host': request.scheme + "://" + request.META['HTTP_HOST']},
                                   uri=request.build_absolute_uri(report.get_url()))
            messages.add_message(request, messages.SUCCESS,
                                 'Your report is building, you will receive an email when it is ready.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('reports'))
        else:
            raise Http404()

    return render(request,
                  'dojo/request_endpoint_report.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   'report_form': report_form,
                   "name": "Vulnerable Product Endpoints",
                   })


def generate_report(request, obj):
    user = Dojo_User.objects.get(id=request.user.id)
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    endpoint_all_findings = None
    endpoint_monthly_counts = None
    endpoint_active_findings = None
    accepted_findings = None
    open_findings = None
    closed_findings = None
    verified_findings = None
    report_title = None
    report_subtitle = None
    report_info = "Generated By %s on %s" % (
        user.get_full_name(), (datetime.now(tz=localtz).strftime("%m/%d/%Y %I:%M%p %Z")))

    if type(obj).__name__ == "Product":
        if request.user.is_staff or request.user in obj.authorized_users.all():
            pass  # user is authorized for this product
        else:
            raise PermissionDenied
    elif type(obj).__name__ == "Endpoint":
        if request.user.is_staff or request.user in obj.product.authorized_users.all():
            pass  # user is authorized for this product
        else:
            raise PermissionDenied
    elif type(obj).__name__ == "QuerySet":
        # authorization taken care of by only selecting findings from product user is authed to see
        pass
    else:
        if not request.user.is_staff:
            raise PermissionDenied

    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    generate = "_generate" in request.GET
    report_name = str(obj)
    report_type = type(obj).__name__
    add_breadcrumb(title="Generate Report", top_level=False, request=request)
    if type(obj).__name__ == "Product_Type":
        product_type = obj
        filename = "product_type_finding_report.pdf"
        template = "dojo/product_type_pdf_report.html"
        report_name = "Product Type Report: " + str(product_type)
        report_title = "Product Type Report"
        report_subtitle = str(product_type)

        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(
                test__engagement__product__prod_type=product_type).distinct().prefetch_related('test',
                                                                                               'test__engagement__product',
                                                                                               'test__engagement__product__prod_type'))
        products = Product.objects.filter(prod_type=product_type,
                                          engagement__test__finding__in=findings.qs).distinct()
        engagements = Engagement.objects.filter(product__prod_type=product_type,
                                                test__finding__in=findings.qs).distinct()
        tests = Test.objects.filter(engagement__product__prod_type=product_type,
                                    finding__in=findings.qs).distinct()
        if findings:
            start_date = localtz.localize(datetime.combine(findings.qs.last().date, datetime.min.time()))
        else:
            start_date = localtz.localize(datetime.today())
        end_date = localtz.localize(datetime.today())

        r = relativedelta(end_date, start_date)
        months_between = (r.years * 12) + r.months
        # include current month
        months_between += 1

        endpoint_monthly_counts = get_period_counts(findings.qs, findings.qs, None,
                                                    months_between, start_date,
                                                    relative_delta='months')

        context = {'product_type': product_type,
                   'products': products,
                   'engagements': engagements,
                   'tests': tests,
                   'report_name': report_name,
                   'endpoint_opened_per_month': endpoint_monthly_counts[
                       'opened_per_period'] if endpoint_monthly_counts is not None else [],
                   'endpoint_active_findings': findings.qs,
                   'findings': findings.qs,
                   'include_finding_notes': include_finding_notes,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': 'Generate Report',
                   'host': request.scheme + "://" + request.META['HTTP_HOST']}

    elif type(obj).__name__ == "Product":
        product = obj
        filename = "product_finding_report.pdf"
        template = "dojo/product_pdf_report.html"
        report_name = "Product Report: " + str(product)
        report_title = "Product Report"
        report_subtitle = str(product)
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(
                test__engagement__product=product).distinct().prefetch_related('test',
                                                                               'test__engagement__product',
                                                                               'test__engagement__product__prod_type'))
        ids = set(finding.id for finding in findings)
        engagements = Engagement.objects.filter(test__finding__id__in=ids).distinct()
        tests = Test.objects.filter(finding__id__in=ids).distinct()

        context = {'product': product,
                   'engagements': engagements,
                   'tests': tests,
                   'report_name': report_name,
                   'findings': findings.qs,
                   'include_finding_notes': include_finding_notes,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': 'Generate Report',
                   'host': request.scheme + "://" + request.META['HTTP_HOST']}

    elif type(obj).__name__ == "Engagement":
        engagement = obj
        findings = ReportFindingFilter(request.GET,
                                       queryset=Finding.objects.filter(test__engagement=engagement,
                                                                       ).prefetch_related('test',
                                                                                          'test__engagement__product',
                                                                                          'test__engagement__product__prod_type').distinct())
        report_name = "Engagement Report: " + str(engagement)
        filename = "engagement_finding_report.pdf"
        template = 'dojo/engagement_pdf_report.html'
        report_title = "Engagement Report"
        report_subtitle = str(engagement)

        ids = set(finding.id for finding in findings)
        tests = Test.objects.filter(finding__id__in=ids).distinct()

        context = {'engagement': engagement,
                   'tests': tests,
                   'report_name': report_name,
                   'findings': findings.qs,
                   'include_finding_notes': include_finding_notes,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': 'Generate Report',
                   'host': request.scheme + "://" + request.META['HTTP_HOST']}

    elif type(obj).__name__ == "Test":
        test = obj
        findings = ReportFindingFilter(request.GET,
                                       queryset=Finding.objects.filter(test=test).prefetch_related('test',
                                                                                                   'test__engagement__product',
                                                                                                   'test__engagement__product__prod_type').distinct())
        filename = "test_finding_report.pdf"
        template = "dojo/test_pdf_report.html"
        report_name = "Test Report: " + str(test)
        report_title = "Test Report"
        report_subtitle = str(test)

        context = {'test': test,
                   'report_name': report_name,
                   'findings': findings.qs,
                   'include_finding_notes': include_finding_notes,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': 'Generate Report',
                   'host': request.scheme + "://" + request.META['HTTP_HOST']}

    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        host = endpoint.host_no_port
        report_name = "Endpoint Report: " + host
        report_type = "Endpoint"
        endpoints = Endpoint.objects.filter(host__regex="^" + host + ":?",
                                            product=endpoint.product).distinct()
        filename = "endpoint_finding_report.pdf"
        template = 'dojo/endpoint_pdf_report.html'
        report_title = "Endpoint Report"
        report_subtitle = host
        findings = ReportFindingFilter(request.GET,
                                       queryset=Finding.objects.filter(endpoints__in=endpoints,
                                                                       ).prefetch_related('test',
                                                                                          'test__engagement__product',
                                                                                          'test__engagement__product__prod_type').distinct())

        context = {'endpoint': endpoint,
                   'endpoints': endpoints,
                   'report_name': report_name,
                   'findings': findings.qs,
                   'include_finding_notes': include_finding_notes,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': 'Generate Report',
                   'host': request.scheme + "://" + request.META['HTTP_HOST']}
    elif type(obj).__name__ == "QuerySet":
        findings = ReportAuthedFindingFilter(request.GET,
                                             queryset=obj.prefetch_related('test',
                                                                           'test__engagement__product',
                                                                           'test__engagement__product__prod_type').distinct(),
                                             user=request.user)
        filename = "finding_report.pdf"
        report_name = 'Finding'
        report_type = 'Finding'
        template = 'dojo/finding_pdf_report.html'
        report_title = "Finding Report"
        report_subtitle = ''

        context = {'findings': findings.qs,
                   'report_name': report_name,
                   'include_finding_notes': include_finding_notes,
                   'include_executive_summary': include_executive_summary,
                   'include_table_of_contents': include_table_of_contents,
                   'user': user,
                   'team_name': settings.TEAM_NAME,
                   'title': 'Generate Report',
                   'host': request.scheme + "://" + request.META['HTTP_HOST']}
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
                           'findings': findings.qs,
                           'include_finding_notes': include_finding_notes,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'user': user,
                           'team_name': settings.TEAM_NAME,
                           'title': 'Generate Report',
                           })

        elif report_format == 'PDF':
            if 'regen' in request.GET:
                # we should already have a report object, lets get and use it
                report = get_object_or_404(Report, id=request.GET['regen'])
                report.datetime = datetime.now(tz=localtz)
                report.status = 'requested'
                if report.requester.username != request.user.username:
                    report.requester = request.user
            else:
                # lets create the report object and send it in to celery task
                report = Report(name=report_name,
                                type=report_type,
                                format='PDF',
                                requester=request.user,
                                task_id='tbd',
                                options=request.path + "?" + request.GET.urlencode())
            report.save()
            async_pdf_report.delay(report=report,
                                   template=template,
                                   filename=filename,
                                   report_title=report_title,
                                   report_subtitle=report_subtitle,
                                   report_info=report_info,
                                   context=context,
                                   uri=request.build_absolute_uri(report.get_url()))
            messages.add_message(request, messages.SUCCESS,
                                 'Your report is building, you will receive an email when it is ready.',
                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('reports'))
        else:
            raise Http404()
    paged_findings = get_page_items(request, findings, 25)
    return render(request, 'dojo/request_report.html',
                  {'product_type': product_type,
                   'product': product,
                   'engagement': engagement,
                   'test': test,
                   'endpoint': endpoint,
                   'findings': findings,
                   'paged_findings': paged_findings,
                   'report_form': report_form,
                   })
