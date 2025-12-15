import logging

from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.paginator import Page, Paginator
from django.db.models import Count, Min, Q, QuerySet, Subquery
from django.db.utils import DEFAULT_DB_ALIAS
from django.http import HttpRequest
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls.base import reverse
from django.views import View
from django.views.decorators.http import require_POST

import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import (
    FindingFilter,
    FindingFilterWithoutObjectLookups,
    FindingGroupsFilter,
)
from dojo.finding.queries import prefetch_for_findings
from dojo.forms import DeleteFindingGroupForm, EditFindingGroupForm, FindingBulkUpdateForm
from dojo.models import Engagement, Finding, Finding_Group, GITHUB_PKey, Global_Role, Product
from dojo.product.queries import get_authorized_products
from dojo.utils import Product_Tab, add_breadcrumb, get_page_items, get_setting, get_system_setting, get_words_for_field

logger = logging.getLogger(__name__)


@user_is_authorized(Finding_Group, Permissions.Finding_Group_View, "fgid")
def view_finding_group(request, fgid):
    finding_group = get_object_or_404(Finding_Group, pk=fgid)
    findings = finding_group.findings.all()
    edit_finding_group_form = EditFindingGroupForm(instance=finding_group)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    finding_filter_class = FindingFilterWithoutObjectLookups if filter_string_matching else FindingFilter

    show_product_column = True
    custom_breadcrumb = None
    product_tab = None
    jira_project = None
    github_config = None
    if finding_group.test.engagement.product.id:
        pid = finding_group.test.engagement.product.id
        product = get_object_or_404(Product, id=pid)
        user_has_permission_or_403(request.user, product, Permissions.Product_View)
        product_tab = Product_Tab(product, title="Findings", tab="findings")
        jira_project = jira_helper.get_jira_project(product)
        github_config = GITHUB_PKey.objects.filter(product=pid).first()
        findings_filter = finding_filter_class(request.GET, findings, user=request.user, pid=pid)
    elif finding_group.test.engagement.id:
        eid = finding_group.test.engagement.id
        engagement = get_object_or_404(Engagement, id=eid)
        user_has_permission_or_403(request.user, engagement, Permissions.Engagement_View)
        product_tab = Product_Tab(engagement.product, title=engagement.name, tab="engagements")
        jira_project = jira_helper.get_jira_project(engagement)
        github_config = GITHUB_PKey.objects.filter(product__engagement=eid).first()
        findings_filter = finding_filter_class(request.GET, findings, user=request.user, eid=eid)

    title_words = get_words_for_field(Finding, "title")
    component_words = get_words_for_field(Finding, "component_name")

    paged_findings = get_page_items(request, findings_filter.qs, 25)
    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list, "all")

    bulk_edit_form = FindingBulkUpdateForm(request.GET)

    if github_config:
        github_config = github_config.git_conf_id

    filter_name = finding_group.name

    if request.method == "POST":
        edit_finding_group_form = EditFindingGroupForm(request.POST, instance=finding_group)
        if edit_finding_group_form.is_valid():
            finding_group.name = edit_finding_group_form.cleaned_data.get("name", "")
            push_to_jira = edit_finding_group_form.cleaned_data.get("push_to_jira")
            jira_issue = edit_finding_group_form.cleaned_data.get("jira_issue")

            if jira_issue:
                # See if the submitted issue was a issue key or the full URL
                jira_project = jira_helper.get_jira_project(finding_group)
                if not jira_project or not jira_project.jira_instance:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Cannot process JIRA issue: JIRA instance is not configured or has been deleted.",
                        extra_tags="alert-danger",
                    )
                    return render(request, "dojo/edit_finding_group.html", {"form": edit_finding_group_form, "finding_group": finding_group})
                jira_instance = jira_project.jira_instance
                jira_issue = jira_issue.removeprefix(jira_instance.url + "/browse/")

                if finding_group.has_jira_issue and jira_issue != jira_helper.get_jira_key(finding_group):
                    jira_helper.unlink_jira(request, finding_group)
                    jira_helper.finding_group_link_jira(request, finding_group, jira_issue)
                elif not finding_group.has_jira_issue:
                    jira_helper.finding_group_link_jira(request, finding_group, jira_issue)
            elif push_to_jira:
                jira_helper.push_to_jira(finding_group, sync=True)

            finding_group.save()
            return HttpResponseRedirect(reverse("view_test", args=(finding_group.test.id,)))

    add_breadcrumb(title=finding_group.name, top_level=not len(request.GET), request=request)
    return render(request, "dojo/view_finding_group.html", {
        "show_product_column": show_product_column,
        "product_tab": product_tab,
        "findings": paged_findings,
        "filtered": findings_filter,
        "title_words": title_words,
        "component_words": component_words,
        "custom_breadcrumb": custom_breadcrumb,
        "filter_name": filter_name,
        "jira_project": jira_project,
        "bulk_edit_form": bulk_edit_form,
        "edit_finding_group_form": edit_finding_group_form,
    })


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Delete, "fgid")
@require_POST
def delete_finding_group(request, fgid):
    finding_group = get_object_or_404(Finding_Group, pk=fgid)
    form = DeleteFindingGroupForm(instance=finding_group)

    if request.method == "POST":
        if "id" in request.POST and str(finding_group.id) == request.POST["id"]:
            form = DeleteFindingGroupForm(request.POST, instance=finding_group)
            if form.is_valid():
                finding_group.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     "Finding Group and relationships removed.",
                                     extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_test", args=(finding_group.test.id,)))

    rels = ["Previewing the relationships has been disabled.", ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([finding_group])
        rels = collector.nested()
    product_tab = Product_Tab(finding_group.test.engagement.product, title="Product", tab="settings")

    return render(request, "dojo/delete_finding_group.html", {
        "finding_group": finding_group,
        "form": form,
        "product_tab": product_tab,
        "rels": rels,
    })


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, "fgid")
@require_POST
def unlink_jira(request, fgid):
    logger.debug("/finding_group/%s/jira/unlink", fgid)
    group = get_object_or_404(Finding_Group, id=fgid)
    logger.info("trying to unlink a linked jira issue from %d:%s", group.id, group.name)
    if group.has_jira_issue:
        try:
            jira_helper.unlink_jira(request, group)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Link to JIRA issue succesfully deleted",
                extra_tags="alert-success")

            return JsonResponse({"result": "OK"})
        except Exception:
            logger.exception("Link to JIRA could not be deleted")
            messages.add_message(
                request,
                messages.ERROR,
                "Link to JIRA could not be deleted, see alerts for details",
                extra_tags="alert-danger")

            return HttpResponse(status=500)
    else:
        messages.add_message(
            request,
            messages.ERROR,
            "Link to JIRA not found",
            extra_tags="alert-danger")
        return HttpResponse(status=400)


@user_is_authorized(Finding_Group, Permissions.Finding_Group_Edit, "fgid")
@require_POST
def push_to_jira(request, fgid):
    logger.debug("/finding_group/%s/jira/push", fgid)
    group = get_object_or_404(Finding_Group, id=fgid)
    try:
        logger.info("trying to push %d:%s to JIRA to create or update JIRA issue", group.id, group.name)
        logger.debug("pushing to jira from group.push_to-jira()")

        # it may look like success here, but the push_to_jira are swallowing exceptions
        # but cant't change too much now without having a test suite, so leave as is for now with the addition warning message to check alerts for background errors.
        if jira_helper.push_to_jira(group, sync=True):
            messages.add_message(
                request,
                messages.SUCCESS,
                message="Action queued to create or update linked JIRA issue, check alerts for background errors.",
                extra_tags="alert-success")
        else:
            messages.add_message(
                request,
                messages.SUCCESS,
                "Push to JIRA failed, check alerts on the top right for errors",
                extra_tags="alert-danger")

        return JsonResponse({"result": "OK"})
    except Exception:
        logger.exception("Error pushing to JIRA")
        messages.add_message(
            request,
            messages.ERROR,
            "Error pushing to JIRA",
            extra_tags="alert-danger")
        return HttpResponse(status=500)


class ListFindingGroups(View):
    filter_name: str = "All"

    SEVERITY_ORDER = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0,
    }

    def get_template(self) -> str:
        return "dojo/finding_groups_list.html"

    def order_field(self, request: HttpRequest, group_findings_queryset: QuerySet[Finding_Group]) -> QuerySet[Finding_Group]:
        order_field_param: str | None = request.GET.get("o")
        if order_field_param:
            reverse_order = order_field_param.startswith("-")
            order_field_param = order_field_param[1:] if reverse_order else order_field_param
            if order_field_param in {"name", "creator", "findings_count", "sla_deadline"}:
                prefix = "-" if reverse_order else ""
                return group_findings_queryset.order_by(f"{prefix}{order_field_param}")
        return group_findings_queryset.order_by("id")

    def filters(self, request: HttpRequest) -> tuple[str, str | None, list[str], list[str]]:
        name_filter: str = request.GET.get("name", "").lower()
        min_severity_filter: str | None = request.GET.get("severity")
        engagement_filter: list[str] = request.GET.getlist("engagement")
        product_filter: list[str] = request.GET.getlist("product")
        return name_filter, min_severity_filter, engagement_filter, product_filter

    def filter_check(self, request: HttpRequest) -> Q:
        name_filter, min_severity_filter, engagement_filter, product_filter = self.filters(request)
        q_objects = Q()
        if name_filter:
            q_objects &= Q(name__icontains=name_filter)
        if product_filter:
            q_objects &= Q(findings__test__engagement__product__id__in=product_filter)
        if engagement_filter:
            q_objects &= Q(findings__test__engagement__id__in=engagement_filter)
        if min_severity_filter:
            min_severity_order_value = self.SEVERITY_ORDER.get(min_severity_filter, -1)
            valid_severities_for_filter = [
                sev for sev, order in self.SEVERITY_ORDER.items() if order >= min_severity_order_value
            ]
            q_objects &= Q(findings__severity__in=valid_severities_for_filter)
        return q_objects

    def get_findings(self, products: QuerySet[Product] | None) -> tuple[QuerySet[Finding], QuerySet[Finding]]:
        filters: dict = {}
        if products:
            filters["test__engagement__product__in"] = products
        user_findings_qs = Finding.objects.filter(**filters)
        return user_findings_qs, user_findings_qs.filter(active=True)

    def get_finding_groups(self, request: HttpRequest, products: QuerySet[Product] | None = None) -> QuerySet[Finding_Group]:
        finding_groups_queryset = Finding_Group.objects.all()
        if products is not None:
            user_findings, _ = self.get_findings(products)
            finding_groups_queryset = finding_groups_queryset.filter(findings__id__in=Subquery(user_findings.values("id"))).distinct()
        request_filters_q = self.filter_check(request)
        finding_groups_queryset = finding_groups_queryset.filter(request_filters_q).distinct()
        finding_groups_queryset = finding_groups_queryset.annotate(
            findings_count=Count("findings", distinct=True),
            sla_deadline=Min("findings__sla_expiration_date"),
        )
        return self.order_field(request, finding_groups_queryset)

    def paginate_queryset(self, queryset: QuerySet[Finding_Group], request: HttpRequest) -> Page:
        page_size = int(request.GET.get("page_size", 25))
        paginator = Paginator(queryset, page_size)
        page_number = request.GET.get("page")
        return paginator.get_page(page_number)

    def get(self, request: HttpRequest) -> HttpResponse:
        global_role = Global_Role.objects.filter(user=request.user).first()
        products = get_authorized_products(Permissions.Product_View)
        if request.user.is_superuser or (global_role and global_role.role):
            finding_groups = self.get_finding_groups(request)
        elif products.exists():
            finding_groups = self.get_finding_groups(request, products)
        else:
            finding_groups = Finding_Group.objects.none()

        paginated_finding_groups = self.paginate_queryset(finding_groups, request)

        context = {
            "filter_name": self.filter_name,
            "filtered": FindingGroupsFilter(request.GET),
            "finding_groups": paginated_finding_groups,
        }

        add_breadcrumb(title="Finding Group", top_level=not request.GET, request=request)
        return render(request, self.get_template(), context)


class ListOpenFindingGroups(ListFindingGroups):
    filter_name: str = "Open"

    def get_finding_groups(self, request: HttpRequest, products: QuerySet[Product] | None = None) -> QuerySet[Finding_Group]:
        finding_groups_queryset = super().get_finding_groups(request, products)
        _, active_findings = self.get_findings(products)
        return finding_groups_queryset.filter(findings__id__in=Subquery(active_findings.values("id"))).distinct()


class ListClosedFindingGroups(ListFindingGroups):
    filter_name: str = "Closed"

    def get_finding_groups(self, request: HttpRequest, products: QuerySet[Product] | None = None) -> QuerySet[Finding_Group]:
        finding_groups_queryset = super().get_finding_groups(request, products)
        _, active_findings = self.get_findings(products)
        return finding_groups_queryset.exclude(findings__id__in=Subquery(active_findings.values("id"))).distinct()
