import logging
import mimetypes
import pathlib

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect, StreamingHttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.finding.helper import NOT_ACCEPTED_FINDINGS_QUERY
from dojo.forms import (
    AddFindingsRiskAcceptanceForm,
    EditRiskAcceptanceForm,
    NoteForm,
    ReplaceRiskAcceptanceProofForm,
    RiskAcceptanceForm,
)
from dojo.models import Finding, Notes, Product, Risk_Acceptance
from dojo.risk_acceptance.helper import prefetch_for_expiration
from dojo.utils import (
    FileIterWrapper,
    Product_Tab,
    get_page_items,
    get_return_url,
    get_system_setting,
    redirect_to_return_url_or_else,
)

logger = logging.getLogger(__name__)


@user_is_authorized(Product, Permissions.Risk_Acceptance, "pid")
def add_risk_acceptance(request, pid, fid=None):
    product = get_object_or_404(Product, id=pid)
    finding = None
    if fid:
        finding = get_object_or_404(Finding, id=fid)

    if not product.enable_full_risk_acceptance:
        raise PermissionDenied

    if request.method == "POST":
        form = RiskAcceptanceForm(request.POST, request.FILES)
        if form.is_valid():
            # first capture notes param as it cannot be saved directly as m2m
            notes = None
            if form.cleaned_data["notes"]:
                notes = Notes(
                    entry=form.cleaned_data["notes"],
                    author=request.user,
                    date=timezone.now())
                notes.save()

            del form.cleaned_data["notes"]

            try:
                # we sometimes see a weird exception here, but are unable to reproduce.
                # we add some logging in case it happens
                risk_acceptance = form.save(commit=False)
                risk_acceptance.product = product
                risk_acceptance.save()
            except Exception:
                logger.debug(vars(request.POST))
                logger.error(vars(form))
                logger.exception("Creation of Risk Acc. is not possible")
                raise

            # attach note to risk acceptance object now in database
            if notes:
                risk_acceptance.notes.add(notes)

            findings = form.cleaned_data["accepted_findings"]

            risk_acceptance = ra_helper.add_findings_to_risk_acceptance(request.user, risk_acceptance, findings)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Risk acceptance saved.",
                extra_tags="alert-success")

            return redirect_to_return_url_or_else(request, reverse("view_product", args=(pid, )))
    else:
        risk_acceptance_title_suggestion = f"Accept: {finding}" if finding else "Risk Acceptance"
        form = RiskAcceptanceForm(initial={"owner": request.user, "name": risk_acceptance_title_suggestion})

    finding_choices = Finding.objects.filter(duplicate=False, test__engagement__product=product).filter(NOT_ACCEPTED_FINDINGS_QUERY).order_by("title")

    form.fields["accepted_findings"].queryset = finding_choices
    if fid:
        form.fields["accepted_findings"].initial = {fid}
    product_tab = Product_Tab(product, title="Risk Acceptance", tab="risk_acceptance")

    return render(request, "dojo/add_risk_acceptance.html", {
                  "product": product,
                  "product_tab": product_tab,
                  "form": form,
                  })


@user_is_authorized(Risk_Acceptance, Permissions.Risk_Acceptance, "raid")
def view_risk_acceptance(request, raid):
    return view_edit_risk_acceptance(request, raid=raid, edit_mode=False)


@user_is_authorized(Risk_Acceptance, Permissions.Risk_Acceptance, "raid")
def edit_risk_acceptance(request, raid):
    return view_edit_risk_acceptance(request, raid=raid, edit_mode=True)


# will only be called by view_risk_acceptance and edit_risk_acceptance
def view_edit_risk_acceptance(request, raid, *, edit_mode=False):
    risk_acceptance = get_object_or_404(Risk_Acceptance, pk=raid)
    product = risk_acceptance.product

    if edit_mode and not product.enable_full_risk_acceptance:
        raise PermissionDenied

    risk_acceptance_form = None
    errors = False

    if request.method == "POST":
        # deleting before instantiating the form otherwise django messes up and we end up with an empty path value
        if len(request.FILES) > 0:
            logger.debug("new proof uploaded")
            risk_acceptance.path.delete()

        if "decision" in request.POST:
            old_expiration_date = risk_acceptance.expiration_date
            risk_acceptance_form = EditRiskAcceptanceForm(request.POST, request.FILES, instance=risk_acceptance)
            errors = errors or not risk_acceptance_form.is_valid()
            if not errors:
                logger.debug(f"path: {risk_acceptance_form.cleaned_data['path']}")

                risk_acceptance_form.save()

                if risk_acceptance.expiration_date != old_expiration_date:
                    # risk acceptance was changed, check if risk acceptance needs to be reinstated and findings made accepted again
                    ra_helper.reinstate(risk_acceptance, old_expiration_date)

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Risk Acceptance saved successfully.",
                    extra_tags="alert-success")

        if "entry" in request.POST:
            note_form = NoteForm(request.POST)
            errors = errors or not note_form.is_valid()
            if not errors:
                new_note = note_form.save(commit=False)
                new_note.author = request.user
                new_note.date = timezone.now()
                new_note.save()
                risk_acceptance.notes.add(new_note)
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Note added successfully.",
                    extra_tags="alert-success")

        if "delete_note" in request.POST:
            note = get_object_or_404(Notes, pk=request.POST["delete_note_id"])
            if note.author.username == request.user.username:
                risk_acceptance.notes.remove(note)
                note.delete()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Note deleted successfully.",
                    extra_tags="alert-success")
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Since you are not the note's author, it was not deleted.",
                    extra_tags="alert-danger")

        if "remove_finding" in request.POST:
            finding = get_object_or_404(
                Finding, pk=request.POST["remove_finding_id"])

            ra_helper.remove_finding_from_risk_acceptance(request.user, risk_acceptance, finding)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding removed successfully from risk acceptance.",
                extra_tags="alert-success")

        if "replace_file" in request.POST:
            replace_form = ReplaceRiskAcceptanceProofForm(
                request.POST, request.FILES, instance=risk_acceptance)

            errors = errors or not replace_form.is_valid()
            if not errors:
                replace_form.save()

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "New Proof uploaded successfully.",
                    extra_tags="alert-success")
            else:
                logger.error(replace_form.errors)

        if "add_findings" in request.POST:
            add_findings_form = AddFindingsRiskAcceptanceForm(
                request.POST, request.FILES, instance=risk_acceptance)
            errors = errors or not add_findings_form.is_valid()
            if not errors:
                findings = add_findings_form.cleaned_data["accepted_findings"]

                ra_helper.add_findings_to_risk_acceptance(request.user, risk_acceptance, findings)

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    f"Finding{'s' if len(findings) > 1 else ''} added successfully.",
                    extra_tags="alert-success")
        if not errors:
            logger.debug("redirecting to return_url")
            return redirect_to_return_url_or_else(request, reverse("view_risk_acceptance", args=(raid,)))
        logger.error("errors found")

    elif edit_mode:
        risk_acceptance_form = EditRiskAcceptanceForm(instance=risk_acceptance)

    note_form = NoteForm()
    replace_form = ReplaceRiskAcceptanceProofForm(instance=risk_acceptance)
    add_findings_form = AddFindingsRiskAcceptanceForm(instance=risk_acceptance)

    accepted_findings = risk_acceptance.accepted_findings.order_by("numerical_severity")
    fpage = get_page_items(request, accepted_findings, 15)

    unaccepted_findings = Finding.objects.filter(test__engagement__product=product, risk_accepted=False) \
        .exclude(id__in=accepted_findings).order_by("title")
    add_fpage = get_page_items(request, unaccepted_findings, 25, "apage")
    # on this page we need to add unaccepted findings as possible findings to add as accepted

    add_findings_form.fields[
        "accepted_findings"].queryset = add_fpage.object_list

    add_findings_form.fields["accepted_findings"].widget.request = request
    add_findings_form.fields["accepted_findings"].widget.findings = unaccepted_findings
    add_findings_form.fields["accepted_findings"].widget.page_number = add_fpage.number

    product_tab = Product_Tab(product, title="Risk Acceptance", tab="risk_acceptance")
    return render(
        request, "dojo/view_risk_acceptance.html", {
            "risk_acceptance": risk_acceptance,
            "product": product,
            "product_tab": product_tab,
            "accepted_findings": fpage,
            "notes": risk_acceptance.notes.all(),
            "edit_mode": edit_mode,
            "risk_acceptance_form": risk_acceptance_form,
            "note_form": note_form,
            "replace_form": replace_form,
            "add_findings_form": add_findings_form,
            "request": request,
            "add_findings": add_fpage,
            "return_url": get_return_url(request),
            "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
        })


@user_is_authorized(Risk_Acceptance, Permissions.Risk_Acceptance, "raid")
def expire_risk_acceptance(request, raid):
    risk_acceptance = get_object_or_404(prefetch_for_expiration(Risk_Acceptance.objects.all()), pk=raid)

    ra_helper.expire_now(risk_acceptance)

    return redirect_to_return_url_or_else(request, reverse("view_risk_acceptance", args=(raid,)))


@user_is_authorized(Risk_Acceptance, Permissions.Risk_Acceptance, "raid")
def reinstate_risk_acceptance(request, raid):
    risk_acceptance = get_object_or_404(prefetch_for_expiration(Risk_Acceptance.objects.all()), pk=raid)
    product = risk_acceptance.product

    if not product.enable_full_risk_acceptance:
        raise PermissionDenied

    ra_helper.reinstate(risk_acceptance, risk_acceptance.expiration_date)

    return redirect_to_return_url_or_else(request, reverse("view_risk_acceptance", args=(raid,)))


@user_is_authorized(Risk_Acceptance, Permissions.Risk_Acceptance, "raid")
def delete_risk_acceptance(request, raid):
    risk_acceptance = get_object_or_404(Risk_Acceptance, pk=raid)
    product = risk_acceptance.product

    ra_helper.delete(product, risk_acceptance)

    messages.add_message(
        request,
        messages.SUCCESS,
        "Risk acceptance deleted successfully.",
        extra_tags="alert-success")
    return HttpResponseRedirect(reverse("view_product", args=(product.id, )))


@user_is_authorized(Risk_Acceptance, Permissions.Risk_Acceptance, "raid")
def download_risk_acceptance(request, raid):
    mimetypes.init()
    risk_acceptance = get_object_or_404(Risk_Acceptance, pk=raid)
    response = StreamingHttpResponse(
        FileIterWrapper(
            (pathlib.Path(settings.MEDIA_ROOT) / risk_acceptance.path.name).open(mode="rb")))
    response["Content-Disposition"] = f'attachment; filename="{risk_acceptance.filename()}"'
    mimetype, _encoding = mimetypes.guess_type(risk_acceptance.path.name)
    response["Content-Type"] = mimetype
    return response
