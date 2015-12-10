# #  reports
import logging
import mimetypes
import os
import urllib
from datetime import datetime
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
    Dojo_User, Endpoint, Report
from dojo.tasks import async_pdf_report
from dojo.utils import get_page_items, add_breadcrumb

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
    from dojo.endpoint.views import get_endpoint_ids
    product = get_object_or_404(Product, id=pid)
    endpoints = Endpoint.objects.filter(product=product,
                                        finding__active=True,
                                        finding__verified=True,
                                        )

    if request.user.is_staff or request.user in product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    endpoints = EndpointReportFilter(request.GET, queryset=endpoints)
    ids = get_endpoint_ids(endpoints)
    endpoints = EndpointReportFilter(request.GET, queryset=Endpoint.objects.filter(product=product,
                                                                                   finding__active=True,
                                                                                   finding__verified=True,
                                                                                   finding__false_p=False,
                                                                                   finding__duplicate=False,
                                                                                   finding__out_of_scope=False,
                                                                                   id__in=ids).distinct())
    paged_endpoints = get_page_items(request, endpoints, 25)
    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    generate = "_generate" in request.GET
    add_breadcrumb(parent=product, title="Vulnerable Product Endpoints Report", top_level=False, request=request)
    report_form = ReportOptionsForm()
    if generate:
        report_form = ReportOptionsForm(request.GET)
        if report_format == 'AsciiDoc':
            return render(request,
                          'dojo/asciidoc_report.html',
                          {'product_type': None,
                           'product': product,
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
            endpoint_ids = [endpoint.id for endpoint in endpoints]
            endpoints = Endpoint.objects.filter(id__in=endpoint_ids)
            # lets create the report object and send it in to celery task
            if 'regen' in request.GET:
                # we should already have a report object, lets get and use it
                report = get_object_or_404(Report, id=request.GET['regen'])
                report.datetime = datetime.now(tz=localtz)
                report.status = 'requested'
            else:
                report = Report(name="Product Endpoints " + str(product),
                                type="Product Endpoint",
                                format='PDF',
                                requester=request.user,
                                task_id='tbd',
                                options=request.path + "?" + request.GET.urlencode())
            report.save()
            x = async_pdf_report.delay(report=report,
                                       filename="product_endpoint_report.pdf",
                                       context={'product_type': None,
                                                'product': product,
                                                'engagement': None,
                                                'test': None,
                                                'endpoints': endpoints,
                                                'endpoint': None,
                                                'findings': None,
                                                'include_finding_notes': include_finding_notes,
                                                'include_executive_summary': include_executive_summary,
                                                'include_table_of_contents': include_table_of_contents,
                                                'user': request.user,
                                                'title': 'Generate Report'},
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
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    user = Dojo_User.objects.get(id=request.user.id)

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
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(
            test__engagement__product__prod_type=product_type).distinct())
        filename = "product_type_finding_report.pdf"
    elif type(obj).__name__ == "Product":
        product = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(test__engagement__product=product,
                                                                                    ).distinct())
        filename = "product_finding_report.pdf"
    elif type(obj).__name__ == "Engagement":
        engagement = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(test__engagement=engagement,
                                                                                    ).distinct())
        filename = "engagement_finding_report.pdf"
    elif type(obj).__name__ == "Test":
        test = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(test=test).distinct())
        filename = "test_finding_report.pdf"
    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        host = endpoint.host_no_port
        report_name = host
        endpoints = Endpoint.objects.filter(host__regex="^" + host + ":?",
                                            product=endpoint.product).distinct()

        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(endpoints__in=endpoints,
                                                                                    ).distinct())
        filename = "endpoint_finding_report.pdf"
    elif type(obj).__name__ == "QuerySet":
        findings = ReportAuthedFindingFilter(request.GET, queryset=obj.distinct(), user=request.user)
        filename = "finding_report.pdf"
        report_name = 'Finding'
        report_type = 'Finding'
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
                           'findings': findings,
                           'include_finding_notes': include_finding_notes,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'user': user,
                           'title': 'Generate Report',
                           })
        elif report_format == 'PDF':
            finding_ids = [finding.id for finding in findings]
            findings = Finding.objects.filter(id__in=finding_ids)
            if 'regen' in request.GET:
                # we should already have a report object, lets get and use it
                report = get_object_or_404(Report, id=request.GET['regen'])
                report.datetime = datetime.now(tz=localtz)
                report.status = 'requested'
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
                                   filename=filename,
                                   context={'product_type': product_type,
                                            'product': product,
                                            'engagement': engagement,
                                            'test': test,
                                            'endpoint': endpoint,
                                            'findings': findings,
                                            'include_finding_notes': include_finding_notes,
                                            'include_executive_summary': include_executive_summary,
                                            'include_table_of_contents': include_table_of_contents,
                                            'user': user,
                                            'title': 'Generate Report'},
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
