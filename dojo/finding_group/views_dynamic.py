import logging

from django.core.paginator import Paginator
from django.http import HttpRequest
from django.shortcuts import render
from django.views import View

from dojo.authorization.roles_permissions import Permissions
from dojo.filters import DynamicFindingGroupsFilter, DynamicFindingGroupsFindingsFilter
from dojo.finding_group.redis import (
    GroupMode,
    get_user_mode,
    load_or_rebuild_finding_groups,
    set_user_mode,
)
from dojo.forms import FindingBulkUpdateForm
from dojo.models import Finding, Global_Role
from dojo.product.queries import get_authorized_products
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


def paginate_queryset(queryset, request: HttpRequest):
    page_size = request.GET.get("page_size", 25)  # Default is 25
    paginator = Paginator(queryset, page_size)
    page_number = request.GET.get("page")
    return paginator.get_page(page_number)


class ListDynamicFindingGroups(View):
    filter_name = "All"

    def get_template(self):
        return "dojo/finding_groups_dynamic_list.html"

    def order_field(self, request: HttpRequest, finding_groups_findings_list):
        order_field = request.GET.get("o")
        if order_field:
            reverse_order = order_field.startswith("-")
            if reverse_order:
                order_field = order_field[1:]
            if order_field == "name":
                finding_groups_findings_list = sorted(finding_groups_findings_list, key=lambda x: x.name, reverse=reverse_order)
            elif order_field == "findings_count":
                finding_groups_findings_list = sorted(finding_groups_findings_list, key=lambda x: len(x.finding_ids), reverse=reverse_order)
        return finding_groups_findings_list

    def filters(self, request: HttpRequest):
        name_filter = request.GET.get("name", "").lower()
        min_severity_filter = request.GET.get("severity")
        engagement_filter = request.GET.getlist("engagement")
        product_filter = request.GET.getlist("product")
        return name_filter, min_severity_filter, engagement_filter, product_filter

    def filter_finding_group(self, finding_group, request: HttpRequest):
        name_filter, min_severity_filter, engagement_filter, product_filter = self.filters(request)
        add_finding_group = True
        if product_filter:
            finding_group.finding_ids = set(finding_group.finding_ids) & set(
                Finding.objects.filter(test__engagement__product__id__in=product_filter).values_list("id", flat=True),
            )
        if engagement_filter:
            finding_group.finding_ids = set(finding_group.finding_ids) & set(
                Finding.objects.filter(test__engagement__id__in=engagement_filter).values_list("id", flat=True),
            )
        finding_group.reconfig_finding_group()
        if name_filter and name_filter not in finding_group.name.lower():
            add_finding_group = False
        if min_severity_filter and Finding.get_number_severity(finding_group.severity) < Finding.get_number_severity(min_severity_filter):
            add_finding_group = False
        if not finding_group.finding_ids:
            add_finding_group = False
        return add_finding_group

    def get_findings(self, products):
        finding_group_fids = {
            fid for finding_group in self.finding_groups_map.values() for fid in finding_group.finding_ids
        }
        filters = {"id__in": finding_group_fids}
        if products:
            filters["test__engagement__product__in"] = products
        user_findings_qs = Finding.objects.filter(**filters)
        user_fids = set(user_findings_qs.values_list("id", flat=True))
        active_fids = set(
            user_findings_qs.filter(active=True).values_list("id", flat=True),
        )
        return user_fids, active_fids

    def get_finding_groups(self, request: HttpRequest, products=None):
        """
        Retrieve all dynamic finding groups for the current user.

        Steps:
        1. Retrieve finding IDs relevant for the user (optionally filtered by products).
        2. Iterate over all finding groups in self.finding_groups_map.
        3. For each group:
        - Restrict the group's findings to those the user can see.
        - Apply additional filters based on the request.
        - No additional filtering for active findings.
        4. Append groups that pass all filters to the result list.
        5. Order the resulting list according to the request via order_field and return.
        """
        user_fids, _ = self.get_findings(products)
        list_finding_group = []
        for finding_group in self.finding_groups_map.values():
            finding_group.finding_ids = set(finding_group.finding_ids) & user_fids
            if self.filter_finding_group(finding_group, request):
                list_finding_group.append(finding_group)
        return self.order_field(request, list_finding_group)

    def get(self, request: HttpRequest):
        global_role = Global_Role.objects.filter(user=request.user).first()
        products = get_authorized_products(Permissions.Product_View)
        mode_str = request.GET.get("mode", None)
        user_id = request.user.id
        if mode_str:
            try:
                mode = GroupMode(mode_str)
                set_user_mode(user_id, mode)
            except ValueError:
                if mode_str is not None:
                    logger.warning(f"Invalid mode: {mode_str}")
                mode = get_user_mode(user_id)
        else:
            mode = get_user_mode(user_id)
        self.finding_groups_map = load_or_rebuild_finding_groups(mode=mode) if mode else {}
        if request.user.is_superuser or (global_role and global_role.role):
            finding_groups = self.get_finding_groups(request)
        elif products.exists():
            finding_groups = self.get_finding_groups(request, products)
        paginated_finding_groups = paginate_queryset(finding_groups, request)

        context = {
            "filter_name": self.filter_name,
            "mode": mode.value if mode else None,
            "filtered": DynamicFindingGroupsFilter(request.GET),
            "finding_groups": paginated_finding_groups,
        }

        add_breadcrumb(title="Dynamic Finding Group", top_level=not len(request.GET), request=request)
        return render(request, self.get_template(), context)


class ListOpenDynamicFindingGroups(ListDynamicFindingGroups):
    filter_name = "Open"

    def get_finding_groups(self, request: HttpRequest, products=None):
        """
        Retrieve dynamic finding groups containing at least one active finding.

        Steps:
        1. Retrieve finding IDs relevant for the user and the active subset.
        2. Iterate over all finding groups in self.finding_groups_map.
        3. For each group:
        - Restrict the group's findings to those the user can see.
        - Apply additional filters based on the request.
        - Keep only groups with at least one active finding.
        4. Append groups that pass all filters to the result list.
        5. Order the resulting list according to the request via order_field and return.
        """
        user_fids, active_fids = self.get_findings(products)
        list_finding_group = []
        for finding_group in self.finding_groups_map.values():
            finding_group.finding_ids = set(finding_group.finding_ids) & user_fids
            if self.filter_finding_group(finding_group, request):
                if finding_group.finding_ids & active_fids:
                    list_finding_group.append(finding_group)
        return self.order_field(request, list_finding_group)


class ListClosedDynamicFindingGroups(ListDynamicFindingGroups):
    filter_name = "Closed"

    def get_finding_groups(self, request: HttpRequest, products=None):
        """
        Retrieve dynamic finding groups containing no active findings.

        Steps:
        1. Retrieve finding IDs relevant for the user and the active subset.
        2. Iterate over all finding groups in self.finding_groups_map.
        3. For each group:
        - Restrict the group's findings to those the user can see.
        - Apply additional filters based on the request.
        - Keep only groups with no active findings.
        4. Append groups that pass all filters to the result list.
        5. Order the resulting list according to the request via order_field and return.
        """
        user_fids, active_fids = self.get_findings(products)
        list_finding_group = []
        for finding_group in self.finding_groups_map.values():
            finding_group.finding_ids = set(finding_group.finding_ids) & user_fids
            if self.filter_finding_group(finding_group, request):
                if not (finding_group.finding_ids & active_fids):
                    list_finding_group.append(finding_group)
        return self.order_field(request, list_finding_group)


class DynamicFindingGroupsFindings(View):
    def get_template(self):
        return "dojo/finding_group_dynamic_findings.html"

    def order_field(self, request: HttpRequest, finding_groups_findings_list):
        order_field = request.GET.get("o")
        if order_field:
            reverse_order = order_field.startswith("-")
            if reverse_order:
                order_field = order_field[1:]
            if order_field == "title":
                finding_groups_findings_list = sorted(finding_groups_findings_list, key=lambda x: x.title, reverse=reverse_order)
            elif order_field == "found_by":
                finding_groups_findings_list = sorted(finding_groups_findings_list, key=lambda x: x.found_by.count(), reverse=reverse_order)
        return finding_groups_findings_list

    def filters(self, request: HttpRequest):
        name_filter = request.GET.get("name", "").lower()
        severity_filter = request.GET.getlist("severity")
        vuln_id_from_tool_filter = request.GET.get("vuln_id_from_tool")
        reporter_filter = request.GET.getlist("reporter")
        active_filter = request.GET.get("active")
        engagement_filter = request.GET.getlist("engagement")
        product_filter = request.GET.getlist("product")
        return name_filter, severity_filter, vuln_id_from_tool_filter, reporter_filter, active_filter, engagement_filter, product_filter

    def filter_findings(self, findings, request: HttpRequest):
        name_filter, severity_filter, vuln_id_from_tool_filter, reporter_filter, active_filter, engagement_filter, product_filter = self.filters(request)
        filter_kwargs = {}
        if name_filter:
            filter_kwargs["title__icontains"] = name_filter
        if severity_filter:
            filter_kwargs["severity__in"] = severity_filter
        if vuln_id_from_tool_filter:
            filter_kwargs["vuln_id_from_tool__icontains"] = vuln_id_from_tool_filter
        if reporter_filter:
            filter_kwargs["reporter__id__in"] = reporter_filter
        if active_filter:
            filter_kwargs["active"] = (active_filter == "Yes")
        if engagement_filter:
            filter_kwargs["test__engagement__id__in"] = engagement_filter
        if product_filter:
            filter_kwargs["test__engagement__product__id__in"] = product_filter
        return findings.filter(**filter_kwargs)

    def get_findings(self, request: HttpRequest, products=None):
        finding_group = self.finding_groups_map.get(self.finding_group_id)

        # When the finding_group not exists
        if not finding_group:
            return None, []

        list_findings = finding_group.finding_ids
        if products:
            findings = Finding.objects.filter(id__in=list_findings, test__engagement__product__in=products)
        else:
            findings = Finding.objects.filter(id__in=list_findings)
        findings = self.filter_findings(findings, request)
        return finding_group.name, self.order_field(request, findings)

    def get(self, request: HttpRequest, finding_group_id: int):
        self.finding_group_id = finding_group_id
        global_role = Global_Role.objects.filter(user=request.user).first()
        products = get_authorized_products(Permissions.Product_View)
        mode = get_user_mode(request.user.id)
        self.finding_groups_map = load_or_rebuild_finding_groups(mode=mode) if mode else {}
        if request.user.is_superuser or (global_role and global_role.role):
            finding_group_name, findings = self.get_findings(request)
        elif products.exists():
            finding_group_name, findings = self.get_findings(request, products)
        else:
            finding_group_name = None
        paginated_findings = paginate_queryset(findings, request)

        context = {
            "finding_group": finding_group_name,
            "filtered": DynamicFindingGroupsFindingsFilter(request.GET),
            "finding_group_id": self.finding_group_id,
            "findings": paginated_findings,
            "bulk_edit_form": FindingBulkUpdateForm(request.GET),
        }

        add_breadcrumb(title="Dynamic Finding Group Findings", top_level=not len(request.GET), request=request)
        return render(request, self.get_template(), context)
