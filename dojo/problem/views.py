from collections import OrderedDict

from django.http import HttpRequest
from django.shortcuts import get_object_or_404, render
from django.views import View
from django.db.models import Count, Q
from django.core.paginator import Paginator

from dojo.utils import add_breadcrumb
from dojo.models import Problem, Finding, Endpoint

import logging
logger = logging.getLogger(__name__)

class ListProblems(View):
    filter_name = "All"

    def get_template(self):
        return "dojo/problems_list.html"

    def get_engagement_id(self):
        return getattr(self, "engagement_id", None)

    def get_problem_id(self):
        return getattr(self, "problem_id", None)

    def add_breadcrumbs(self, request: HttpRequest, context: dict):
        if "endpoints" in request.GET:
            endpoint_ids = request.GET.getlist("endpoints", [])
            if len(endpoint_ids) == 1 and endpoint_ids[0]:
                endpoint_id = endpoint_ids[0]
                endpoint = get_object_or_404(Endpoint, id=endpoint_id)
                context["filter_name"] = "Vulnerable Endpoints"
                context["custom_breadcrumb"] = OrderedDict([
                    ("Endpoints", reverse("vulnerable_endpoints")),
                    (endpoint, reverse("view_endpoint", args=(endpoint.id,))),
                ])
        elif not self.get_engagement_id() and not self.get_problem_id():
            add_breadcrumb(title="Problems", top_level=not len(request.GET), request=request)

        return request, context

    def get_problems(self, request: HttpRequest):
        queryset = Problem.objects.all().annotate(
            findings_count=Count('findings'),
            total_script_ids=Count('findings__vuln_id_from_tool', distinct=True)
        ).distinct()
        order_field = request.GET.get('o')
        return queryset.order_by(order_field) if order_field else queryset.order_by("id")

    def paginate_queryset(self, queryset, request: HttpRequest):
        page_size = request.GET.get('page_size', 25)  # Default is 25
        paginator = Paginator(queryset, page_size)
        page_number = request.GET.get('page')
        return paginator.get_page(page_number)

    def get(self, request: HttpRequest):
        problems = self.get_problems(request)
        paginated_problems = self.paginate_queryset(problems, request)

        context = {
            "filter_name": self.filter_name,
            "problems": paginated_problems,
        }

        request, context = self.add_breadcrumbs(request, context)
        return render(request, self.get_template(), context)


class ListOpenProblems(ListProblems):
    filter_name = "Open"

    def get_problems(self, request: HttpRequest):
        queryset = Problem.objects.filter(
            findings__active=True
        ).annotate(
            findings_count=Count('findings'),
            total_script_ids=Count('findings__vuln_id_from_tool', distinct=True)
        ).distinct()
        order_field = request.GET.get('o')
        return queryset.order_by(order_field) if order_field else queryset.order_by("id")


class ListClosedProblems(ListProblems):
    filter_name = "Closed"

    def get_problems(self, request: HttpRequest):
        queryset = Problem.objects.annotate(
            active_findings=Count('findings', filter=Q(findings__active=True))
        ).filter(active_findings=0).annotate(
            findings_count=Count('findings'),
            total_script_ids=Count('findings__vuln_id_from_tool', distinct=True)
        ).distinct()
        order_field = request.GET.get('o')
        return queryset.order_by(order_field) if order_field else queryset.order_by("id")



class ProblemFindings(ListProblems):
    def get_template(self):
        return "dojo/problem_findings.html"

    def get_findings(self, request: HttpRequest):
        problem = Problem.objects.get(pk=self.problem_id)
        queryset = problem.findings.all()
        order_field = request.GET.get('o')
        return problem.name, queryset.order_by(order_field) if order_field else queryset.order_by("id")

    def get(self, request: HttpRequest, problem_id: int):
        self.problem_id = problem_id
        problem_name, findings = self.get_findings(request)
        paginated_findings = self.paginate_queryset(findings, request)

        context = {
            "problem": problem_name,
            "findings": paginated_findings,
        }

        request, context = self.add_breadcrumbs(request, context)
        return render(request, self.get_template(), context)
