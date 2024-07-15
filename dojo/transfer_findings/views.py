from django.views import View
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.views.generic.edit import DeleteView
from django.http import HttpResponse, HttpRequest
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, render
from dojo.authorization.roles_permissions import Permissions
from dojo.utils import redirect_to_return_url_or_else
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.transfer_findings.forms import DeleteTransferFindingForm
from dojo.models import TransferFinding
from dojo.transfer_findings import helper as helper_tf


class TransferFindingDeleteView(View):
    def get_transfer_finding(self, transfer_finding_id: int):
        return get_object_or_404(TransferFinding, id=transfer_finding_id)

    def process_form(self, request: HttpRequest, transfer_finding: TransferFinding, context: dict):
        if context["form"].is_valid():
            transfer_finding.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Transfer-Findig deleted successfully.",
                extra_tags="alert-success",
            )
            return request, True

        messages.add_message(
            request,
            messages.ERROR,
            "Unable to delete Transfer-Finding, please try again.",
            extra_tags="alert-danger",
        )
        return request, False
    
    def post(self, request: HttpRequest):
        transfer_finding_id = request.POST["id"]
        transfer_finding = get_object_or_404(TransferFinding, id=transfer_finding_id)
        user_has_permission_or_403(request.user, transfer_finding, Permissions.Transfer_Finding_Delete)
        context = {
            "form": DeleteTransferFindingForm(request.POST, instance=transfer_finding),
        }
        if helper_tf.delete_transfer_finding_finding(transfer_finding):
            request, success = self.process_form(request, transfer_finding, context)
            if success:
                return redirect_to_return_url_or_else(request, reverse("view_transfer_finding", args=(transfer_finding.destination_product.id,)))
            raise PermissionDenied
        else:
            raise InterruptedError

