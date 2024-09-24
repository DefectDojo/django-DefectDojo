from dojo.utils import get_page_items, add_breadcrumb
from django.shortcuts import render
from django.contrib import messages
from django.http.response import HttpResponseRedirect
from django.urls import reverse
from dojo.engine_tools.models import FindingExclusion
from dojo.engine_tools.filters import FindingExclusionFilter
from dojo.engine_tools.forms import CreateFindingExclusionForm


# @user_is_configuration_authorized("dojo.view_engagement_survey")
def finding_exclusion(request):
    finding_exclusions = FindingExclusion.objects.all()
    finding_exclusions = FindingExclusionFilter(request.GET,
                                                queryset=finding_exclusions)
    paged_finding_exclusion = get_page_items(request,
                                             finding_exclusions.qs,
                                             25)

    add_breadcrumb(title="FindingExclusion", top_level=True, request=request)
    return render(request, "dojo/view_finding_exclusion.html", {
        "exclusions": paged_finding_exclusion,
        "filtered": finding_exclusions,
        "name": "FindingExclusion",
    })


def create_finding_exclusion(request):
    form = CreateFindingExclusionForm()
    finding_exclusion = None

    if request.method == "POST":
        form = CreateFindingExclusionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Exclusion successfully created.",
                extra_tags="alert-success")
            return HttpResponseRedirect(reverse("finding_exclusion"))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Please correct any errors displayed below.",
                extra_tags="alert-danger")

    add_breadcrumb(title="Create Exclusion",
                   top_level=False,
                   request=request)

    return render(request, "dojo/create_finding_exclusion.html", {
        "finding_exclusion": finding_exclusion,
        "form": form,
        "name": "Create finding exclusion",
    })
