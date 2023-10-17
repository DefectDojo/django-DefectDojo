# #  tests
from django.db.models.query import Prefetch
from dojo.engagement.queries import get_authorized_engagements
from dojo.importers.utils import construct_imported_message
import logging
import operator
import base64
from datetime import datetime
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.urls import reverse, Resolver404
from django.db.models import Q, QuerySet, Count
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from django.utils import timezone
from django.utils.translation import gettext as _
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS

from dojo.filters import TemplateFindingFilter, FindingFilter, TestImportFilter
from dojo.forms import NoteForm, TestForm, \
    DeleteTestForm, AddFindingForm, TypedNoteForm, \
    ReImportScanForm, JIRAFindingForm, JIRAImportScanForm, \
    FindingBulkUpdateForm, CopyTestForm
from dojo.models import IMPORT_UNTOUCHED_FINDING, Finding, Finding_Group, Test, Note_Type, BurpRawRequestResponse, Endpoint, Stub_Finding, \
    Finding_Template, Cred_Mapping, Test_Import, Product_API_Scan_Configuration, Test_Import_Finding_Action

from dojo.tools.factory import get_choices_sorted, get_scan_types_sorted
from dojo.utils import add_error_message_to_response, add_field_errors_to_response, add_success_message_to_response, get_page_items, get_page_items_and_count, add_breadcrumb, get_cal_event, process_notifications, get_system_setting, \
    Product_Tab, is_scan_file_too_large, get_words_for_field, get_setting, async_delete, redirect_to_return_url_or_else, calculate_grade
from dojo.notifications.helper import create_notification
from dojo.finding.views import find_available_notetypes
from functools import reduce
import dojo.jira_link.helper as jira_helper
import dojo.finding.helper as finding_helper
from django.views.decorators.vary import vary_on_cookie
from django.views import View
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.test.queries import get_authorized_tests
from dojo.user.queries import get_authorized_users
from dojo.importers.reimporter.reimporter import DojoDefaultReImporter as ReImporter


logger = logging.getLogger(__name__)
parse_logger = logging.getLogger('dojo')
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def prefetch_for_findings(findings):
    prefetched_findings = findings
    if isinstance(findings, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_findings = prefetched_findings.select_related('reporter')
        prefetched_findings = prefetched_findings.prefetch_related('jira_issue__jira_project__jira_instance')
        prefetched_findings = prefetched_findings.prefetch_related('test__test_type')
        prefetched_findings = prefetched_findings.prefetch_related('test__engagement__jira_project__jira_instance')
        prefetched_findings = prefetched_findings.prefetch_related('test__engagement__product__jira_project_set__jira_instance')
        prefetched_findings = prefetched_findings.prefetch_related('found_by')
        prefetched_findings = prefetched_findings.prefetch_related('risk_acceptance_set')
        # we could try to prefetch only the latest note with SubQuery and OuterRef, but I'm getting that MySql doesn't support limits in subqueries.
        prefetched_findings = prefetched_findings.prefetch_related('notes')
        prefetched_findings = prefetched_findings.prefetch_related('tags')
        # filter out noop reimport actions from finding status history
        prefetched_findings = prefetched_findings.prefetch_related(Prefetch('test_import_finding_action_set',
                                                                            queryset=Test_Import_Finding_Action.objects.exclude(action=IMPORT_UNTOUCHED_FINDING)))

        prefetched_findings = prefetched_findings.prefetch_related('endpoints')
        prefetched_findings = prefetched_findings.prefetch_related('status_finding')
        prefetched_findings = prefetched_findings.annotate(active_endpoint_count=Count('status_finding__id', filter=Q(status_finding__mitigated=False)))
        prefetched_findings = prefetched_findings.annotate(mitigated_endpoint_count=Count('status_finding__id', filter=Q(status_finding__mitigated=True)))
        prefetched_findings = prefetched_findings.prefetch_related('finding_group_set__jira_issue')
        prefetched_findings = prefetched_findings.prefetch_related('duplicate_finding')
        prefetched_findings = prefetched_findings.prefetch_related('vulnerability_id_set')
    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetched_findings


class ViewTest(View):
    def get_test(self, test_id: int):
        test_prefetched = get_authorized_tests(Permissions.Test_View)
        test_prefetched = test_prefetched.annotate(total_reimport_count=Count('test_import__id', distinct=True))
        return get_object_or_404(test_prefetched, pk=test_id)

    def get_test_import_data(self, request: HttpRequest, test: Test):
        test_imports = Test_Import.objects.filter(test=test)
        test_import_filter = TestImportFilter(request.GET, test_imports)

        paged_test_imports = get_page_items_and_count(request, test_import_filter.qs, 5, prefix="test_imports")
        paged_test_imports.object_list = paged_test_imports.object_list.prefetch_related("test_import_finding_action_set")

        return {
            "paged_test_imports": paged_test_imports,
            "test_import_filter": test_import_filter,
        }

    def get_stub_findings(self, request: HttpRequest, test: Test):
        stub_findings = Stub_Finding.objects.filter(test=test)
        paged_stub_findings = get_page_items(request, stub_findings, 25)

        return {
            "stub_findings": paged_stub_findings,
        }

    def get_findings(self, request: HttpRequest, test: Test):
        findings = Finding.objects.filter(test=test).order_by("numerical_severity")
        findings = FindingFilter(request.GET, queryset=findings)
        paged_findings = get_page_items_and_count(request, prefetch_for_findings(findings.qs), 25, prefix='findings')

        return {
            "findings": paged_findings,
            "filtered": findings,
        }

    def get_note_form(self, request: HttpRequest):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {}

        return NoteForm(*args, **kwargs)

    def get_typed_note_form(self, request: HttpRequest, context: dict):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "available_note_types": context.get("available_note_types")
        }

        return TypedNoteForm(*args, **kwargs)

    def get_form(self, request: HttpRequest, context: dict):
        return (
            self.get_typed_note_form(request, context)
            if context.get("note_type_activation", 0)
            else self.get_note_form(request)
        )

    def get_initial_context(self, request: HttpRequest, test: Test):
        # Set up the product tab
        product_tab = Product_Tab(test.engagement.product, title=_("Test"), tab="engagements")
        product_tab.setEngagement(test.engagement)
        # Set up the notes and associated info to generate the form with
        notes = test.notes.all()
        note_type_activation = Note_Type.objects.filter(is_active=True).count()
        available_note_types = None
        if note_type_activation:
            available_note_types = find_available_notetypes(notes)
        # Set the current context
        context = {
            "test": test,
            "prod": test.engagement.product,
            "product_tab": product_tab,
            "title_words": get_words_for_field(Finding, 'title'),
            "component_words": get_words_for_field(Finding, 'component_name'),
            "notes": notes,
            "note_type_activation": note_type_activation,
            "available_note_types": available_note_types,
            "files": test.files.all(),
            "person": request.user.username,
            "request": request,
            "show_re_upload": any(test.test_type.name in code for code in get_choices_sorted()),
            "creds": Cred_Mapping.objects.filter(engagement=test.engagement).select_related("cred_id").order_by("cred_id"),
            "cred_test": Cred_Mapping.objects.filter(test=test).select_related("cred_id").order_by("cred_id"),
            "jira_project": jira_helper.get_jira_project(test),
            "bulk_edit_form": FindingBulkUpdateForm(request.GET),
            'finding_groups': test.finding_group_set.all().prefetch_related("findings", "jira_issue", "creator", "findings__vulnerability_id_set"),
            'finding_group_by_options': Finding_Group.GROUP_BY_OPTIONS,

        }
        # Set the form using the context, and then update the context
        form = self.get_form(request, context)
        context["form"] = form
        # Add some of the related objects
        context |= self.get_findings(request, test)
        context |= self.get_stub_findings(request, test)
        context |= self.get_test_import_data(request, test)

        return context

    def process_form(self, request: HttpRequest, test: Test, context: dict):
        if context["form"].is_valid():
            # Save the note
            new_note = context["form"].save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            test.notes.add(new_note)
            # Make a notification for this actions
            url = request.build_absolute_uri(reverse("view_test", args=(test.id,)))
            title = f"Test: {test.test_type.name} on {test.engagement.product.name}"
            process_notifications(request, new_note, url, title)
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Note added successfully.'),
                extra_tags='alert-success')

            return request, True
        return request, False

    def get_template(self):
        return "dojo/view_test.html"

    def get(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Test_View)
        # Quick perms check to determine if the user has access to add a note to the test
        user_has_permission_or_403(request.user, test, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Test_View)
        # Quick perms check to determine if the user has access to add a note to the test
        user_has_permission_or_403(request.user, test, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Determine the validity of the form
        request, success = self.process_form(request, test, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_test", args=(test_id,)))
        # Render the form
        return render(request, self.get_template(), context)


# def prefetch_for_test_imports(test_imports):
#     prefetched_test_imports = test_imports
#     if isinstance(test_imports, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
#         #could we make this dynamic, i.e for action_type in IMPORT_ACTIONS: prefetch
#         prefetched_test_imports = prefetched_test_imports.annotate(created_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_CREATED_FINDING)))
#         prefetched_test_imports = prefetched_test_imports.annotate(closed_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_CLOSED_FINDING)))
#         prefetched_test_imports = prefetched_test_imports.annotate(reactivated_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_REACTIVATED_FINDING)))
#         prefetched_test_imports = prefetched_test_imports.annotate(updated_findings_count=Count('findings', filter=Q(test_import_finding_action__action=IMPORT_UNTOUCHED_FINDING)))

#     return prefetch_for_test_imports


@user_is_authorized(Test, Permissions.Test_Edit, 'tid')
def edit_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    form = TestForm(instance=test)
    if request.method == 'POST':
        form = TestForm(request.POST, instance=test)
        if form.is_valid():
            new_test = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Test saved.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(test.engagement.id,)))

    form.initial['target_start'] = test.target_start.date()
    form.initial['target_end'] = test.target_end.date()
    form.initial['description'] = test.description

    product_tab = Product_Tab(test.engagement.product, title=_("Edit Test"), tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, 'dojo/edit_test.html',
                  {'test': test,
                   'product_tab': product_tab,
                   'form': form,
                   })


@user_is_authorized(Test, Permissions.Test_Delete, 'tid')
def delete_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    eng = test.engagement
    form = DeleteTestForm(instance=test)

    if request.method == 'POST':
        if 'id' in request.POST and str(test.id) == request.POST['id']:
            form = DeleteTestForm(request.POST, instance=test)
            if form.is_valid():
                product = test.engagement.product
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(test)
                    message = _('Test and relationships will be removed in the background.')
                else:
                    message = _('Test and relationships removed.')
                    test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title=_('Deletion of %(title)s') % {"title": test.title},
                                    product=product,
                                    description=_('The test "%(title)s" was deleted by %(user)s') % {"title": test.title, "user": request.user},
                                    url=request.build_absolute_uri(reverse('view_engagement', args=(eng.id, ))),
                                    recipients=[test.engagement.lead],
                                    icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))

    rels = ['Previewing the relationships has been disabled.', '']
    display_preview = get_setting('DELETE_PREVIEW')
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([test])
        rels = collector.nested()

    product_tab = Product_Tab(test.engagement.product, title=_("Delete Test"), tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, 'dojo/delete_test.html',
                  {'test': test,
                   'product_tab': product_tab,
                   'form': form,
                   'rels': rels,
                   'deletable_objects': rels,
                   })


@user_is_authorized(Test, Permissions.Test_Edit, 'tid')
def copy_test(request, tid):
    test = get_object_or_404(Test, id=tid)
    product = test.engagement.product
    engagement_list = get_authorized_engagements(Permissions.Engagement_Edit).filter(product=product)
    form = CopyTestForm(engagements=engagement_list)

    if request.method == 'POST':
        form = CopyTestForm(request.POST, engagements=engagement_list)
        if form.is_valid():
            engagement = form.cleaned_data.get('engagement')
            product = test.engagement.product
            test_copy = test.copy(engagement=engagement)
            calculate_grade(product)
            messages.add_message(
                request,
                messages.SUCCESS,
                'Test Copied successfully.',
                extra_tags='alert-success')
            create_notification(event='other',
                                title='Copying of %s' % test.title,
                                description='The test "%s" was copied by %s to %s' % (test.title, request.user, engagement.name),
                                product=product,
                                url=request.build_absolute_uri(reverse('view_test', args=(test_copy.id,))),
                                recipients=[test.engagement.lead],
                                icon="exclamation-triangle")
            return redirect_to_return_url_or_else(request, reverse('view_engagement', args=(engagement.id, )))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to copy test, please try again.',
                extra_tags='alert-danger')

    product_tab = Product_Tab(product, title="Copy Test", tab="engagements")
    return render(request, 'dojo/copy_object.html', {
        'source': test,
        'source_label': 'Test',
        'destination_label': 'Engagement',
        'product_tab': product_tab,
        'form': form,
    })


@cache_page(60 * 5)  # cache for 5 minutes
@vary_on_cookie
def test_calendar(request):

    if not get_system_setting('enable_calendar'):
        raise Resolver404()

    if 'lead' not in request.GET or '0' in request.GET.getlist('lead'):
        tests = get_authorized_tests(Permissions.Test_View)
    else:
        filters = []
        leads = request.GET.getlist('lead', '')
        if '-1' in request.GET.getlist('lead'):
            leads.remove('-1')
            filters.append(Q(lead__isnull=True))
        filters.append(Q(lead__in=leads))
        tests = get_authorized_tests(Permissions.Test_View).filter(reduce(operator.or_, filters))

    tests = tests.prefetch_related('test_type', 'lead', 'engagement__product')

    add_breadcrumb(title=_("Test Calendar"), top_level=True, request=request)
    return render(request, 'dojo/calendar.html', {
        'caltype': 'tests',
        'leads': request.GET.getlist('lead', ''),
        'tests': tests,
        'users': get_authorized_users(Permissions.Test_View)})


@user_is_authorized(Test, Permissions.Test_View, 'tid')
def test_ics(request, tid):
    test = get_object_or_404(Test, id=tid)
    start_date = datetime.combine(test.target_start, datetime.min.time())
    end_date = datetime.combine(test.target_end, datetime.max.time())
    uid = "dojo_test_%d_%d_%d" % (test.id, test.engagement.id, test.engagement.product.id)
    cal = get_cal_event(start_date,
                        end_date,
                        _("Test: %(test_type_name)s (%(product_name)s)") % {
                            'test_type_name': test.test_type.name,
                            'product_name': test.engagement.product.name
                        },
                        _("Set aside for test %(test_type_name)s, on product %(product_name)s. Additional detail can be found at %(detail_url)s") % {
                            'test_type_name': test.test_type.name,
                            'product_name': test.engagement.product.name,
                            'detail_url': request.build_absolute_uri((reverse("view_test", args=(test.id,))))
                        },
                        uid)
    output = cal.serialize()
    response = HttpResponse(content=output)
    response['Content-Type'] = 'text/calendar'
    response['Content-Disposition'] = 'attachment; filename=%s.ics' % test.test_type.name
    return response


class AddFindingView(View):
    def get_test(self, test_id: int):
        return get_object_or_404(Test, id=test_id)

    def get_initial_context(self, request: HttpRequest, test: Test):
        # Get the finding form first since it is used in another place
        finding_form = self.get_finding_form(request, test)
        product_tab = Product_Tab(test.engagement.product, title=_("Add Finding"), tab="engagements")
        product_tab.setEngagement(test.engagement)
        return {
            "form": finding_form,
            "product_tab": product_tab,
            "temp": False,
            'test': test,
            "tid": test.id,
            "pid": test.engagement.product.id,
            "form_error": False,
            "jform": self.get_jira_form(request, test, finding_form=finding_form),
        }

    def get_finding_form(self, request: HttpRequest, test: Test):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "initial": {'date': timezone.now().date(), 'verified': True},
            "req_resp": None,
            "product": test.engagement.product,
        }
        # Remove the initial state on post
        if request.method == "POST":
            kwargs.pop("initial")

        return AddFindingForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, test: Test, finding_form: AddFindingForm = None):
        # Determine if jira should be used
        if (jira_project := jira_helper.get_jira_project(test)) is not None:
            # Set up the args for the form
            args = [request.POST] if request.method == "POST" else []
            # Set the initial form args
            kwargs = {
                "push_all": jira_helper.is_push_all_issues(test),
                "prefix": "jiraform",
                "jira_project": jira_project,
                "finding_form": finding_form,
            }

            return JIRAFindingForm(*args, **kwargs)
        return None

    def validate_status_change(self, request: HttpRequest, context: dict):
        if ((context["form"]['active'].value() is False or
             context["form"]['false_p'].value()) and
             context["form"]['duplicate'].value() is False):

            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _('Can not set a finding as inactive without adding all mandatory notes'),
                    code='inactive_without_mandatory_notes')
                error_false_p = ValidationError(
                    _('Can not set a finding as false positive without adding all mandatory notes'),
                    code='false_p_without_mandatory_notes')
                if context["form"]['active'].value() is False:
                    context["form"].add_error('active', error_inactive)
                if context["form"]['false_p'].value():
                    context["form"].add_error('false_p', error_false_p)
                messages.add_message(
                    request,
                    messages.ERROR,
                    _('Can not set a finding as inactive or false positive without adding all mandatory notes'),
                    extra_tags='alert-danger')

        return request

    def process_finding_form(self, request: HttpRequest, test: Test, context: dict):
        finding = None
        if context["form"].is_valid():
            finding = context["form"].save(commit=False)
            finding.test = test
            finding.reporter = request.user
            finding.numerical_severity = Finding.get_numerical_severity(finding.severity)
            finding.tags = context["form"].cleaned_data['tags']
            finding.save()
            # Save and add new endpoints
            finding_helper.add_endpoints(finding, context["form"])
            # Save the finding at the end and return
            finding.save()

            return finding, request, True
        else:
            add_error_message_to_response("The form has errors, please correct them below.")
            add_field_errors_to_response(context["form"])

        return finding, request, False

    def process_jira_form(self, request: HttpRequest, finding: Finding, context: dict):
        # Capture case if the jira not being enabled
        if context["jform"] is None:
            return request, True, False

        if context["jform"] and context["jform"].is_valid():
            # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
            # push_to_jira = jira_helper.is_push_to_jira(finding, jform.cleaned_data.get('push_to_jira'))
            push_to_jira = jira_helper.is_push_all_issues(finding) or context["jform"].cleaned_data.get('push_to_jira')
            jira_message = None
            # if the jira issue key was changed, update database
            new_jira_issue_key = context["jform"].cleaned_data.get('jira_issue')
            if finding.has_jira_issue:
                jira_issue = finding.jira_issue
                # everything in DD around JIRA integration is based on the internal id of the issue in JIRA
                # instead of on the public jira issue key.
                # I have no idea why, but it means we have to retrieve the issue from JIRA to get the internal JIRA id.
                # we can assume the issue exist, which is already checked in the validation of the jform
                if not new_jira_issue_key:
                    jira_helper.finding_unlink_jira(request, finding)
                    jira_message = 'Link to JIRA issue removed successfully.'

                elif new_jira_issue_key != finding.jira_issue.jira_key:
                    jira_helper.finding_unlink_jira(request, finding)
                    jira_helper.finding_link_jira(request, finding, new_jira_issue_key)
                    jira_message = 'Changed JIRA link successfully.'
            else:
                logger.debug('finding has no jira issue yet')
                if new_jira_issue_key:
                    logger.debug('finding has no jira issue yet, but jira issue specified in request. trying to link.')
                    jira_helper.finding_link_jira(request, finding, new_jira_issue_key)
                    jira_message = 'Linked a JIRA issue successfully.'
            # Determine if a message should be added
            if jira_message:
                messages.add_message(
                    request, messages.SUCCESS, jira_message, extra_tags="alert-success"
                )

            return request, True, push_to_jira
        else:
            add_field_errors_to_response(context["jform"])

        return request, False, False

    def process_forms(self, request: HttpRequest, test: Test, context: dict):
        form_success_list = []
        finding = None
        # Set vars for the completed forms
        # Validate finding mitigation
        request = self.validate_status_change(request, context)
        # Check the validity of the form overall
        finding, request, success = self.process_finding_form(request, test, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, finding, context)
        form_success_list.append(success)
        # Determine if all forms were successful
        all_forms_valid = all(form_success_list)
        # Check the validity of all the forms
        if all_forms_valid:
            # if we're removing the "duplicate" in the edit finding screen
            finding_helper.save_vulnerability_ids(finding, context["form"].cleaned_data["vulnerability_ids"].split())
            # Push things to jira if needed
            finding.save(push_to_jira=push_to_jira)
            # Save the burp req resp
            if "request" in context["form"].cleaned_data or "response" in context["form"].cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    finding=finding,
                    burpRequestBase64=base64.b64encode(context["form"].cleaned_data["request"].encode()),
                    burpResponseBase64=base64.b64encode(context["form"].cleaned_data["response"].encode()),
                )
                burp_rr.clean()
                burp_rr.save()
            # Create a notification
            create_notification(
                event='other',
                title=_('Addition of %(title)s') % {'title': finding.title},
                finding=finding,
                description=_('Finding "%(title)s" was added by %(user)s') % {
                    'title': finding.title, 'user': request.user
                },
                url=reverse("view_finding", args=(finding.id,)),
                icon="exclamation-triangle")
            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Finding added successfully.'),
                extra_tags='alert-success')

        return finding, request, all_forms_valid

    def get_template(self):
        return "dojo/add_findings.html"

    def get(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Finding_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, test_id: int):
        # Get the initial objects
        test = self.get_test(test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, test, Permissions.Finding_Add)
        # Set up the initial context
        context = self.get_initial_context(request, test)
        # Process the form
        _, request, success = self.process_forms(request, test, context)
        # Handle the case of a successful form
        if success:
            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_findings', args=(test.id,)))
        else:
            context["form_error"] = True
        # Render the form
        return render(request, self.get_template(), context)


@user_is_authorized(Test, Permissions.Finding_Add, 'tid')
def add_temp_finding(request, tid, fid):
    jform = None
    test = get_object_or_404(Test, id=tid)
    finding = get_object_or_404(Finding_Template, id=fid)
    findings = Finding_Template.objects.all()
    push_all_jira_issues = jira_helper.is_push_all_issues(finding)

    if request.method == 'POST':

        form = AddFindingForm(request.POST, req_resp=None, product=test.engagement.product)
        if jira_helper.get_jira_project(test):
            jform = JIRAFindingForm(push_all=jira_helper.is_push_all_issues(test), prefix='jiraform', jira_project=jira_helper.get_jira_project(test), finding_form=form)
            logger.debug('jform valid: %s', jform.is_valid())

        if (form['active'].value() is False or form['false_p'].value()) and form['duplicate'].value() is False:
            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _('Can not set a finding as inactive without adding all mandatory notes'),
                    code='not_active_or_false_p_true')
                error_false_p = ValidationError(
                    _('Can not set a finding as false positive without adding all mandatory notes'),
                    code='not_active_or_false_p_true')
                if form['active'].value() is False:
                    form.add_error('active', error_inactive)
                if form['false_p'].value():
                    form.add_error('false_p', error_false_p)
                messages.add_message(request,
                                     messages.ERROR,
                                     _('Can not set a finding as inactive or false positive without adding all mandatory notes'),
                                     extra_tags='alert-danger')
        if form.is_valid():
            finding.last_used = timezone.now()
            finding.save()
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)

            new_finding.tags = form.cleaned_data['tags']
            new_finding.date = form.cleaned_data['date'] or datetime.today()

            finding_helper.update_finding_status(new_finding, request.user)

            new_finding.save(dedupe_option=False)

            # Save and add new endpoints
            finding_helper.add_endpoints(new_finding, form)

            new_finding.save()
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(request.POST, prefix='jiraform', instance=new_finding, push_all=push_all_jira_issues, jira_project=jira_helper.get_jira_project(test), finding_form=form)
                if jform.is_valid():
                    if jform.cleaned_data.get('push_to_jira'):
                        jira_helper.push_to_jira(new_finding)
                else:
                    add_error_message_to_response('jira form validation failed: %s' % jform.errors)
            if 'request' in form.cleaned_data or 'response' in form.cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    finding=new_finding,
                    burpRequestBase64=base64.b64encode(form.cleaned_data.get('request', '').encode("utf-8")),
                    burpResponseBase64=base64.b64encode(form.cleaned_data.get('response', '').encode("utf-8")),
                )
                burp_rr.clean()
                burp_rr.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Finding from template added successfully.'),
                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 _('The form has errors, please correct them below.'),
                                 extra_tags='alert-danger')

    else:
        form = AddFindingForm(req_resp=None, product=test.engagement.product, initial={'active': False,
                                    'date': timezone.now().date(),
                                    'verified': False,
                                    'false_p': False,
                                    'duplicate': False,
                                    'out_of_scope': False,
                                    'title': finding.title,
                                    'description': finding.description,
                                    'cwe': finding.cwe,
                                    'severity': finding.severity,
                                    'mitigation': finding.mitigation,
                                    'impact': finding.impact,
                                    'references': finding.references,
                                    'numerical_severity': finding.numerical_severity})

        if jira_helper.get_jira_project(test):
            jform = JIRAFindingForm(push_all=jira_helper.is_push_all_issues(test), prefix='jiraform', jira_project=jira_helper.get_jira_project(test), finding_form=form)

    # logger.debug('form valid: %s', form.is_valid())
    # logger.debug('jform valid: %s', jform.is_valid())
    # logger.debug('form errors: %s', form.errors)
    # logger.debug('jform errors: %s', jform.errors)
    # logger.debug('jform errors: %s', vars(jform))

    product_tab = Product_Tab(test.engagement.product, title=_("Add Finding"), tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, 'dojo/add_findings.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'jform': jform,
                   'findings': findings,
                   'temp': True,
                   'fid': finding.id,
                   'tid': test.id,
                   'test': test,
                   })


@user_is_authorized(Test, Permissions.Test_View, 'tid')
def search(request, tid):
    test = get_object_or_404(Test, id=tid)
    templates = Finding_Template.objects.all()
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = get_words_for_field(Finding_Template, 'title')

    add_breadcrumb(parent=test, title=_("Add From Template"), top_level=False, request=request)
    return render(request, 'dojo/templates.html',
                  {'templates': paged_templates,
                   'filtered': templates,
                   'title_words': title_words,
                   'tid': tid,
                   'add_from_template': True,
                   })


@user_is_authorized(Test, Permissions.Import_Scan_Result, 'tid')
def re_import_scan_results(request, tid):
    additional_message = _("When re-uploading a scan, any findings not found in original scan will be updated as "
                           "mitigated.  The process attempts to identify the differences, however manual verification "
                           "is highly recommended.")
    test = get_object_or_404(Test, id=tid)
    # by default we keep a trace of the scan_type used to create the test
    # if it's not here, we use the "name" of the test type
    # this feature exists to provide custom label for tests for some parsers
    if test.scan_type:
        scan_type = test.scan_type
    else:
        scan_type = test.test_type.name
    engagement = test.engagement
    form = ReImportScanForm(test=test)
    jform = None
    jira_project = jira_helper.get_jira_project(test)
    push_all_jira_issues = jira_helper.is_push_all_issues(test)

    # Decide if we need to present the Push to JIRA form
    if get_system_setting('enable_jira') and jira_project:
        jform = JIRAImportScanForm(push_all=push_all_jira_issues, prefix='jiraform')

    if request.method == "POST":
        form = ReImportScanForm(request.POST, request.FILES, test=test)
        if jira_project:
            jform = JIRAImportScanForm(request.POST, push_all=push_all_jira_issues, prefix='jiraform')
        if form.is_valid() and (jform is None or jform.is_valid()):
            scan_date = form.cleaned_data['scan_date']

            minimum_severity = form.cleaned_data['minimum_severity']
            scan = request.FILES.get('file', None)
            activeChoice = form.cleaned_data.get('active', None)
            verifiedChoice = form.cleaned_data.get('verified', None)
            do_not_reactivate = form.cleaned_data['do_not_reactivate']
            tags = form.cleaned_data['tags']
            version = form.cleaned_data.get('version', None)
            branch_tag = form.cleaned_data.get('branch_tag', None)
            build_id = form.cleaned_data.get('build_id', None)
            commit_hash = form.cleaned_data.get('commit_hash', None)
            api_scan_configuration = form.cleaned_data.get('api_scan_configuration', None)
            service = form.cleaned_data.get('service', None)

            endpoints_to_add = None  # not available on reimport UI

            close_old_findings = form.cleaned_data.get('close_old_findings', True)

            group_by = form.cleaned_data.get('group_by', None)
            create_finding_groups_for_all_findings = form.cleaned_data.get('create_finding_groups_for_all_findings')

            active = None
            if activeChoice:
                if activeChoice == 'force_to_true':
                    active = True
                elif activeChoice == 'force_to_false':
                    active = False
            verified = None
            if verifiedChoice:
                if verifiedChoice == 'force_to_true':
                    verified = True
                elif verifiedChoice == 'force_to_false':
                    verified = False

            # Tags are replaced, same behaviour as with django-tagging
            test.tags = tags
            test.version = version
            if scan and is_scan_file_too_large(scan):
                messages.add_message(request,
                                     messages.ERROR,
                                     _("Report file is too large. Maximum supported size is %(size)d MB") % {'size': settings.SCAN_FILE_MAX_SIZE},
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('re_import_scan_results', args=(test.id,)))

            push_to_jira = push_all_jira_issues or (jform and jform.cleaned_data.get('push_to_jira'))
            error = False
            finding_count, new_finding_count, closed_finding_count, reactivated_finding_count, untouched_finding_count = 0, 0, 0, 0, 0
            reimporter = ReImporter()
            try:
                test, finding_count, new_finding_count, closed_finding_count, reactivated_finding_count, untouched_finding_count, test_import = \
                    reimporter.reimport_scan(scan, scan_type, test, active=active, verified=verified,
                                                tags=None, minimum_severity=minimum_severity,
                                                endpoints_to_add=endpoints_to_add, scan_date=scan_date,
                                                version=version, branch_tag=branch_tag, build_id=build_id,
                                                commit_hash=commit_hash, push_to_jira=push_to_jira,
                                                close_old_findings=close_old_findings, group_by=group_by,
                                                api_scan_configuration=api_scan_configuration, service=service, do_not_reactivate=do_not_reactivate,
                                                create_finding_groups_for_all_findings=create_finding_groups_for_all_findings)
            except Exception as e:
                logger.exception(e)
                add_error_message_to_response('An exception error occurred during the report import:%s' % str(e))
                error = True

            if not error:
                message = construct_imported_message(scan_type, finding_count, new_finding_count=new_finding_count,
                                                        closed_finding_count=closed_finding_count,
                                                        reactivated_finding_count=reactivated_finding_count,
                                                        untouched_finding_count=untouched_finding_count)
                add_success_message_to_response(message)

            return HttpResponseRedirect(reverse('view_test', args=(test.id,)))

    product_tab = Product_Tab(engagement.product, title=_("Re-upload a %(scan_type)s") % {"scan_type": scan_type}, tab="engagements")
    product_tab.setEngagement(engagement)
    form.fields['endpoints'].queryset = Endpoint.objects.filter(product__id=product_tab.product.id)
    form.initial['api_scan_configuration'] = test.api_scan_configuration
    form.fields['api_scan_configuration'].queryset = Product_API_Scan_Configuration.objects.filter(product__id=product_tab.product.id)
    return render(request,
                  'dojo/import_scan_results.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'eid': engagement.id,
                   'additional_message': additional_message,
                   'jform': jform,
                   'scan_types': get_scan_types_sorted(),
                   })
