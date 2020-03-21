from django import http
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import DeleteView, DetailView, TemplateView, View

from ..mixins import DojoViewMixin, SuccessRedirectBackViewMixin
from ..models import Engagement, Finding, Test
from ..utils import dict2querydict
from ..views import DojoFilterView
from .builders import BUILDER_REGISTRY
from .filters import (
    EngagementFilterSet,
    FindingFilterSet,
    ProductFilterSet,
    ReportNGFilterSet,
    TestFilterSet,
)
from .forms import ReportNGBuilderControlForm
from .models import ReportNG


def _filter_form_data(*forms, exclude=None):
    """Returns key/raw value data pairs for fields that passed validation.

    The inputs have to be Form objects. When the same key is present in multiple
    forms, the later value overwrites the previous one.

    An eventual prefix is stripped from keys.

    Keys passed in the exclude list won't appear in the resulting dict.
    By default, these are excluded: page, page_size, panel_open
    """
    if exclude is None:
        exclude = ("page", "page_size", "panel_open")

    data = {}
    for form in forms:
        prefix = form.prefix
        if not form.is_bound:
            # No entries at all
            continue
        # Ensure cleaned_data is available
        form.is_valid()

        for key, value in form.data.lists():
            if prefix is not None:
                if not key.startswith("%s-" % prefix):
                    # Skip key/value pair
                    continue
                key = key[len(prefix) + 1 :]
            if key in form.cleaned_data and key not in exclude:
                data[key] = value

    return data


def _structure_prefixed(qdict, strip_prefix=False):
    """Splits a QueryDict up into a dict with QueryDicts, indexed by prefix.

    If strip_prefix is set, the keys inside the QueryDict objects will
    have their prefix removed.
    Keys without prefix (containing no "-") are grouped under "other".
    """
    structured = {}
    for key, values in qdict.lists():
        if "-" in key:
            prefix, suffix = key.split("-", 1)
            if strip_prefix:
                key = suffix
        else:
            prefix, suffix = "other", key
        if prefix not in structured:
            structured[prefix] = http.QueryDict("", mutable=True)
        structured[prefix].setlist(key, values)
    return structured


class ReportNGBuilderView(DojoViewMixin, TemplateView):
    model = ReportNG
    permission_type = "add"
    template_name = "dojo/reportng_builder/builder.html"

    def get_title(self):
        return "{} - ReportNG Builder".format(self.builder.name)

    def dispatch(self, request, builder_code, *args, **kwargs):
        try:
            self.builder = BUILDER_REGISTRY[builder_code]
        except KeyError:
            raise http.Http404("No such builder")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, draft_pk=None, *args, **kwargs):
        # Make query data available in a method-independent format
        if request.method == "GET":
            data = _structure_prefixed(request.GET)
        else:
            data = _structure_prefixed(request.POST)

        draft = None
        if draft_pk is not None:
            draft = get_object_or_404(
                ReportNG.objects.for_user(request),
                pk=draft_pk,
                builder_code=self.builder.code,
            )
            if request.method == "GET":
                # Preload the forms with data from this draft
                data["b"] = dict2querydict(draft.builder_config, prefix="b")
                for prefix, _data in draft.content_criteria.items():
                    data[prefix] = dict2querydict(_data, prefix=prefix)

        control_form = ReportNGBuilderControlForm(data=data.get("c"), prefix="c")
        current_step = 1
        if control_form.is_bound:
            control_form.is_valid()
            current_step = control_form.cleaned_data.get("step", current_step)

        builder_config_form = self.builder.get_config_form(
            request.user, data=data.get("b"), prefix="b"
        )

        # Initialize each filter restricted to the items selected by
        # the previous one.

        # The queryset doesn't need to be restricted for the root filter.
        products_filter = ProductFilterSet(
            data=data.get("p"), request=request, prefix="p"
        )
        engagements_filter = EngagementFilterSet(
            data=data.get("e"),
            request=request,
            prefix="e",
            queryset=Engagement.objects.filter(product__in=products_filter.ticked_qs),
        )
        tests_filter = TestFilterSet(
            data=data.get("t"),
            request=request,
            prefix="t",
            queryset=Test.objects.filter(engagement__in=engagements_filter.ticked_qs),
        )
        findings_filter = FindingFilterSet(
            data=data.get("f"),
            request=request,
            prefix="f",
            queryset=Finding.objects.filter(test__in=tests_filter.ticked_qs),
        )

        if request.method == "POST" and builder_config_form.is_valid():
            build = control_form.cleaned_data.get("build", False)
            save_draft = control_form.cleaned_data.get("save_draft", False)
            overwrite_draft = control_form.cleaned_data.get("overwrite_draft", False)
            # Was a report loaded which really is a draft?
            draft_loaded = draft and draft.status == ReportNG.STATUS_DRAFT
            if build or save_draft:
                content_criteria = {
                    "p": _filter_form_data(
                        products_filter.form, products_filter.meta_form
                    ),
                    "e": _filter_form_data(
                        engagements_filter.form, engagements_filter.meta_form
                    ),
                    "t": _filter_form_data(tests_filter.form, tests_filter.meta_form),
                    "f": _filter_form_data(
                        findings_filter.form, findings_filter.meta_form
                    ),
                }
                if build:
                    status = ReportNG.STATUS_REQUESTED
                else:
                    status = ReportNG.STATUS_DRAFT
                if draft_loaded and overwrite_draft:
                    # Change existing draft
                    if not request.user.has_perm(draft.get_perm("change"), draft):
                        raise PermissionDenied
                    draft.title = builder_config_form.cleaned_data["title"]
                    draft.builder_config = _filter_form_data(builder_config_form)
                    draft.content_criteria = content_criteria
                    draft.status = status
                    draft.save()
                    report = draft
                else:
                    # Create new ReportNG object
                    report = ReportNG.objects.create(
                        title=builder_config_form.cleaned_data["title"],
                        builder_code=self.builder.code,
                        builder_config=_filter_form_data(builder_config_form),
                        content_criteria=content_criteria,
                        requester=request.user,
                        status=status,
                    )
                if build:
                    report.products.set(products_filter.ticked_qs, clear=True)
                    report.engagements.set(engagements_filter.ticked_qs, clear=True)
                    report.tests.set(tests_filter.ticked_qs, clear=True)
                    report.findings.set(findings_filter.ticked_qs, clear=True)
                    self.builder.dispatch(report)
                    return redirect("reportng_detail", pk=report.pk)
                else:
                    # Draft saved
                    return redirect(
                        "reportng_builder",
                        builder_code=self.builder.code,
                        draft_pk=report.pk,
                    )

        context = self.get_context_data(**kwargs)
        context.update(
            {
                "builder": self.builder,
                "draft": draft,
                "control_form": control_form,
                "current_step": current_step,
                "builder_config_form": builder_config_form,
                "products_filter": products_filter,
                "engagements_filter": engagements_filter,
                "tests_filter": tests_filter,
                "findings_filter": findings_filter,
            }
        )
        return self.render_to_response(context)

    # Same logic for POST
    post = get


class ReportNGFilterView(DojoViewMixin, DojoFilterView):
    filterset_class = ReportNGFilterSet

    def get_context_data(self, **kwargs):
        """Adds BUILDER_REGISTRY to context for displaying available implementations."""
        context = super().get_context_data(**kwargs)
        context["BUILDER_REGISTRY"] = BUILDER_REGISTRY
        return context


class ReportNGDetailView(View):
    def get(self, request, pk):
        return redirect(reverse("reportng_filter") + "?pk={}".format(pk))


class ReportNGDownloadView(DojoViewMixin, DetailView):
    model = ReportNG

    def get(self, request, pk):
        report = self.get_object()
        if not report.is_downloadable:
            raise http.Http404
        response = http.FileResponse(report.file, as_attachment=True)
        if report.status == ReportNG.STATUS_READY:
            report.status = ReportNG.STATUS_DOWNLOADED
            report.save()
        return response


class ReportNGDeleteView(DojoViewMixin, SuccessRedirectBackViewMixin, DeleteView):
    model = ReportNG
