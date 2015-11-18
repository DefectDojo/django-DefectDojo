# #  reports
import logging
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.shortcuts import render, get_object_or_404
from easy_pdf.rendering import render_to_pdf_response
from pytz import timezone
from dojo.filters import ReportFindingFilter, ReportAuthedFindingFilter, EndpointReportFilter
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Dojo_User, Endpoint
from dojo.utils import get_page_items, add_breadcrumb

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


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
    if generate:
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
            if len(endpoints) <= 50:
                return render_to_pdf_response(request,
                                              'dojo/pdf_report.html',
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
                                               'title': 'Generate Report', },
                                              filename='product_endpoint_report', )
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'PDF reports are limited to endpoint counts of 50 or less. Please use the '
                                     'filters below to reduce the number of endpoints.',
                                     extra_tags='alert-danger')
        else:
            raise Http404()

    return render(request,
                  'dojo/request_endpoint_report.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
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
        endpoints = Endpoint.objects.filter(host__regex="^" + host + ":?",
                                            product=endpoint.product).distinct()

        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(endpoints__in=endpoints,
                                                                                    ).distinct())
        filename = "endpoint_finding_report.pdf"
    elif type(obj).__name__ == "QuerySet":
        findings = ReportAuthedFindingFilter(request.GET, queryset=obj.distinct(), user=request.user)
        filename = "finding_report.pdf"
    else:
        raise Http404()
    if generate:
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
            if len(findings) <= 150:
                return render_to_pdf_response(request,
                                              'dojo/pdf_report.html',
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
                                               'title': 'Generate Report'},
                                              filename=filename, )
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'PDF reports are limited to finding counts of 150 or less. Please use the '
                                     'filters below to reduce the number of findings.',
                                     extra_tags='alert-danger')
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
                   })
