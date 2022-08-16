# #  tests
from django.db.models.query import Prefetch
from dojo.engagement.queries import get_authorized_engagements
from dojo.importers.utils import construct_imported_message
import logging
import operator
import json
import httplib2
import base64
from datetime import datetime
import googleapiclient.discovery
from google.oauth2 import service_account
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.urls import reverse, Resolver404
from django.db.models import Q, QuerySet, Count
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from django.utils import timezone
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS

from dojo.filters import TemplateFindingFilter, FindingFilter, TestImportFilter
from dojo.forms import NoteForm, TestForm, \
    DeleteTestForm, AddFindingForm, TypedNoteForm, \
    ReImportScanForm, JIRAFindingForm, JIRAImportScanForm, \
    FindingBulkUpdateForm, CopyTestForm
from dojo.models import IMPORT_UNTOUCHED_FINDING, Finding, Finding_Group, Test, Note_Type, BurpRawRequestResponse, Endpoint, Stub_Finding, \
    Finding_Template, Cred_Mapping, System_Settings, Test_Import, Product_API_Scan_Configuration, Test_Import_Finding_Action

from dojo.tools.factory import get_choices_sorted, get_scan_types_sorted
from dojo.utils import add_error_message_to_response, add_field_errors_to_response, add_success_message_to_response, get_page_items, get_page_items_and_count, add_breadcrumb, get_cal_event, process_notifications, get_system_setting, \
    Product_Tab, is_scan_file_too_large, get_words_for_field, get_setting, async_delete, redirect_to_return_url_or_else, calculate_grade
from dojo.notifications.helper import create_notification
from dojo.finding.views import find_available_notetypes
from functools import reduce
import dojo.jira_link.helper as jira_helper
import dojo.finding.helper as finding_helper
from django.views.decorators.vary import vary_on_cookie
from django.views.decorators.debug import sensitive_variables
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.test.queries import get_authorized_tests
from dojo.user.queries import get_authorized_users
from dojo.importers.reimporter.reimporter import DojoDefaultReImporter as ReImporter


logger = logging.getLogger(__name__)
parse_logger = logging.getLogger('dojo')
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


@sensitive_variables('service_account_info', 'credentials')
@user_is_authorized(Test, Permissions.Test_View, 'tid')
def view_test(request, tid):
    test_prefetched = get_authorized_tests(Permissions.Test_View)
    test_prefetched = test_prefetched.annotate(total_reimport_count=Count('test_import__id', distinct=True))
    # tests_prefetched = test_prefetched.prefetch_related(Prefetch('test_import_set', queryset=Test_Import.objects.filter(~Q(findings_affected=None))))
    # tests_prefetched = test_prefetched.prefetch_related('test_import_set')
    # test_prefetched = test_prefetched.prefetch_related('test_import_set__test_import_finding_action_set')

    test = get_object_or_404(test_prefetched, pk=tid)
    # test = get_object_or_404(Test, pk=tid)

    prod = test.engagement.product
    notes = test.notes.all()
    note_type_activation = Note_Type.objects.filter(is_active=True).count()
    if note_type_activation:
        available_note_types = find_available_notetypes(notes)
    files = test.files.all()
    person = request.user.username
    findings = Finding.objects.filter(test=test).order_by('numerical_severity')
    findings = FindingFilter(request.GET, queryset=findings)
    stub_findings = Stub_Finding.objects.filter(test=test)
    cred_test = Cred_Mapping.objects.filter(test=test).select_related('cred_id').order_by('cred_id')
    creds = Cred_Mapping.objects.filter(engagement=test.engagement).select_related('cred_id').order_by('cred_id')
    system_settings = get_object_or_404(System_Settings, id=1)
    if request.method == 'POST':
        user_has_permission_or_403(request.user, test, Permissions.Note_Add)
        if note_type_activation:
            form = TypedNoteForm(request.POST, available_note_types=available_note_types)
        else:
            form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            test.notes.add(new_note)
            if note_type_activation:
                form = TypedNoteForm(available_note_types=available_note_types)
            else:
                form = NoteForm()
            url = request.build_absolute_uri(reverse("view_test", args=(test.id,)))
            title = "Test: %s on %s" % (test.test_type.name, test.engagement.product.name)
            process_notifications(request, new_note, url, title)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')
    else:
        if note_type_activation:
            form = TypedNoteForm(available_note_types=available_note_types)
        else:
            form = NoteForm()

    title_words = get_words_for_field(Finding, 'title')
    component_words = get_words_for_field(Finding, 'component_name')

    # test_imports = test.test_import_set.all()
    test_imports = Test_Import.objects.filter(test=test)
    test_import_filter = TestImportFilter(request.GET, test_imports)

    paged_test_imports = get_page_items_and_count(request, test_import_filter.qs, 5, prefix='test_imports')
    paged_test_imports.object_list = paged_test_imports.object_list.prefetch_related('test_import_finding_action_set')

    paged_findings = get_page_items_and_count(request, prefetch_for_findings(findings.qs), 25, prefix='findings')
    paged_stub_findings = get_page_items(request, stub_findings, 25)
    show_re_upload = any(test.test_type.name in code for code in get_choices_sorted())

    product_tab = Product_Tab(prod, title="Test", tab="engagements")
    product_tab.setEngagement(test.engagement)
    jira_project = jira_helper.get_jira_project(test)

    finding_groups = test.finding_group_set.all().prefetch_related('findings', 'jira_issue', 'creator', 'findings__vulnerability_id_set')

    bulk_edit_form = FindingBulkUpdateForm(request.GET)

    google_sheets_enabled = system_settings.enable_google_sheets
    sheet_url = None
    if google_sheets_enabled and system_settings.credentials:
        spreadsheet_name = test.engagement.product.name + "-" + test.engagement.name + "-" + str(test.id)
        system_settings = get_object_or_404(System_Settings, id=1)
        service_account_info = json.loads(system_settings.credentials)
        SCOPES = ['https://www.googleapis.com/auth/drive']
        credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=SCOPES)
        try:
            drive_service = googleapiclient.discovery.build('drive', 'v3', credentials=credentials, cache_discovery=False)
            folder_id = system_settings.drive_folder_ID
            gs_files = drive_service.files().list(q="mimeType='application/vnd.google-apps.spreadsheet' and parents in '%s' and name='%s'" % (folder_id, spreadsheet_name),
                                                  spaces='drive',
                                                  pageSize=10,
                                                  fields='files(id, name)').execute()

        except googleapiclient.errors.HttpError:
            messages.add_message(
                request,
                messages.ERROR,
                "There is a problem with the Google Sheets Sync Configuration. Contact your system admin to solve the issue. Until fixed, the Google Sheets Sync feature cannot be used.",
                extra_tags="alert-danger",
            )
            google_sheets_enabled = False
        except httplib2.ServerNotFoundError:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to reach the Google Sheet API.",
                extra_tags="alert-danger",
            )
        else:
            spreadsheets = gs_files.get('files')
            if len(spreadsheets) == 1:
                spreadsheetId = spreadsheets[0].get('id')
                sheet_url = 'https://docs.google.com/spreadsheets/d/' + spreadsheetId
    return render(request, 'dojo/view_test.html',
                  {'test': test,
                   'prod': prod,
                   'product_tab': product_tab,
                   'findings': paged_findings,
                   'filtered': findings,
                   'stub_findings': paged_stub_findings,
                   'title_words': title_words,
                   'component_words': component_words,
                   'form': form,
                   'notes': notes,
                   'files': files,
                   'person': person,
                   'request': request,
                   'show_re_upload': show_re_upload,
                   'creds': creds,
                   'cred_test': cred_test,
                   'jira_project': jira_project,
                   'show_export': google_sheets_enabled and system_settings.credentials,
                   'sheet_url': sheet_url,
                   'bulk_edit_form': bulk_edit_form,
                   'paged_test_imports': paged_test_imports,
                   'test_import_filter': test_import_filter,
                   'finding_groups': finding_groups,
                   'finding_group_by_options': Finding_Group.GROUP_BY_OPTIONS,
                   })


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
        prefetched_findings = prefetched_findings.prefetch_related('endpoint_status')
        prefetched_findings = prefetched_findings.prefetch_related('endpoint_status__endpoint')
        prefetched_findings = prefetched_findings.annotate(active_endpoint_count=Count('endpoint_status__id', filter=Q(endpoint_status__mitigated=False)))
        prefetched_findings = prefetched_findings.annotate(mitigated_endpoint_count=Count('endpoint_status__id', filter=Q(endpoint_status__mitigated=True)))
        prefetched_findings = prefetched_findings.prefetch_related('finding_group_set__jira_issue')
        prefetched_findings = prefetched_findings.prefetch_related('duplicate_finding')
        prefetched_findings = prefetched_findings.prefetch_related('vulnerability_id_set')
    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetched_findings


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
                                 'Test saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(test.engagement.id,)))

    form.initial['target_start'] = test.target_start.date()
    form.initial['target_end'] = test.target_end.date()
    form.initial['description'] = test.description

    product_tab = Product_Tab(test.engagement.product, title="Edit Test", tab="engagements")
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
                    message = 'Test and relationships will be removed in the background.'
                else:
                    message = 'Test and relationships removed.'
                    test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title='Deletion of %s' % test.title,
                                    product=product,
                                    description='The test "%s" was deleted by %s' % (test.title, request.user),
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

    product_tab = Product_Tab(test.engagement.product, title="Delete Test", tab="engagements")
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

    add_breadcrumb(title="Test Calendar", top_level=True, request=request)
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
                        "Test: %s (%s)" % (test.test_type.name, test.engagement.product.name),
                        "Set aside for test %s, on product %s.  Additional detail can be found at %s" % (
                            test.test_type.name, test.engagement.product.name,
                            request.build_absolute_uri((reverse("view_test", args=(test.id,))))),
                        uid)
    output = cal.serialize()
    response = HttpResponse(content=output)
    response['Content-Type'] = 'text/calendar'
    response['Content-Disposition'] = 'attachment; filename=%s.ics' % test.test_type.name
    return response


@user_is_authorized(Test, Permissions.Finding_Add, 'tid')
def add_findings(request, tid):
    test = Test.objects.get(id=tid)
    form_error = False
    jform = None
    form = AddFindingForm(initial={'date': timezone.now().date()}, req_resp=None, product=test.engagement.product)
    push_all_jira_issues = jira_helper.is_push_all_issues(test)
    use_jira = jira_helper.get_jira_project(test) is not None

    if request.method == 'POST':
        form = AddFindingForm(request.POST, req_resp=None, product=test.engagement.product)
        if (form['active'].value() is False or form['false_p'].value()) and form['duplicate'].value() is False:
            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError('Can not set a finding as inactive without adding all mandatory notes',
                                        code='inactive_without_mandatory_notes')
                error_false_p = ValidationError('Can not set a finding as false positive without adding all mandatory notes',
                                        code='false_p_without_mandatory_notes')
                if form['active'].value() is False:
                    form.add_error('active', error_inactive)
                if form['false_p'].value():
                    form.add_error('false_p', error_false_p)
                messages.add_message(request,
                                     messages.ERROR,
                                     'Can not set a finding as inactive or false positive without adding all mandatory notes',
                                     extra_tags='alert-danger')
        if use_jira:
            jform = JIRAFindingForm(request.POST, prefix='jiraform', push_all=push_all_jira_issues, jira_project=jira_helper.get_jira_project(test), finding_form=form)

        if form.is_valid() and (jform is None or jform.is_valid()):
            if jform:
                logger.debug('jform.jira_issue: %s', jform.cleaned_data.get('jira_issue'))
                logger.debug('jform.push_to_jira: %s', jform.cleaned_data.get('push_to_jira'))

            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            new_finding.tags = form.cleaned_data['tags']
            new_finding.save(dedupe_option=False, push_to_jira=False)

            # Save and add new endpoints
            finding_helper.add_endpoints(new_finding, form)

            # Push to jira?
            push_to_jira = False
            jira_message = None
            if jform and jform.is_valid():
                # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
                # push_to_jira = jira_helper.is_push_to_jira(new_finding, jform.cleaned_data.get('push_to_jira'))
                push_to_jira = push_all_jira_issues or jform.cleaned_data.get('push_to_jira')

                # if the jira issue key was changed, update database
                new_jira_issue_key = jform.cleaned_data.get('jira_issue')
                if new_finding.has_jira_issue:
                    jira_issue = new_finding.jira_issue

                    # everything in DD around JIRA integration is based on the internal id of the issue in JIRA
                    # instead of on the public jira issue key.
                    # I have no idea why, but it means we have to retrieve the issue from JIRA to get the internal JIRA id.
                    # we can assume the issue exist, which is already checked in the validation of the jform

                    if not new_jira_issue_key:
                        jira_helper.finding_unlink_jira(request, new_finding)
                        jira_message = 'Link to JIRA issue removed successfully.'

                    elif new_jira_issue_key != new_finding.jira_issue.jira_key:
                        jira_helper.finding_unlink_jira(request, new_finding)
                        jira_helper.finding_link_jira(request, new_finding, new_jira_issue_key)
                        jira_message = 'Changed JIRA link successfully.'
                else:
                    logger.debug('finding has no jira issue yet')
                    if new_jira_issue_key:
                        logger.debug('finding has no jira issue yet, but jira issue specified in request. trying to link.')
                        jira_helper.finding_link_jira(request, new_finding, new_jira_issue_key)
                        jira_message = 'Linked a JIRA issue successfully.'

            finding_helper.save_vulnerability_ids(new_finding, form.cleaned_data['vulnerability_ids'].split())

            new_finding.save(false_history=True, push_to_jira=push_to_jira)
            create_notification(event='other',
                                title='Addition of %s' % new_finding.title,
                                finding=new_finding,
                                description='Finding "%s" was added by %s' % (new_finding.title, request.user),
                                url=request.build_absolute_uri(reverse('view_finding', args=(new_finding.id,))),
                                icon="exclamation-triangle")

            if 'request' in form.cleaned_data or 'response' in form.cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    finding=new_finding,
                    burpRequestBase64=base64.b64encode(form.cleaned_data['request'].encode()),
                    burpResponseBase64=base64.b64encode(form.cleaned_data['response'].encode()),
                )
                burp_rr.clean()
                burp_rr.save()

            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_findings', args=(test.id,)))
        else:
            form_error = True
            add_error_message_to_response('The form has errors, please correct them below.')
            add_field_errors_to_response(jform)
            add_field_errors_to_response(form)

    else:
        if use_jira:
            jform = JIRAFindingForm(push_all=jira_helper.is_push_all_issues(test), prefix='jiraform', jira_project=jira_helper.get_jira_project(test), finding_form=form)

    product_tab = Product_Tab(test.engagement.product, title="Add Finding", tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, 'dojo/add_findings.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'test': test,
                   'temp': False,
                   'tid': tid,
                   'form_error': form_error,
                   'jform': jform,
                   })


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
                error_inactive = ValidationError('Can not set a finding as inactive without adding all mandatory notes',
                                        code='not_active_or_false_p_true')
                error_false_p = ValidationError('Can not set a finding as false positive without adding all mandatory notes',
                                        code='not_active_or_false_p_true')
                if form['active'].value() is False:
                    form.add_error('active', error_inactive)
                if form['false_p'].value():
                    form.add_error('false_p', error_false_p)
                messages.add_message(request,
                                     messages.ERROR,
                                     'Can not set a finding as inactive or false positive without adding all mandatory notes',
                                     extra_tags='alert-danger')
        if form.is_valid():
            finding.last_used = timezone.now()
            finding.save()
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            new_finding.date = form.cleaned_data['date'] or datetime.today()
            finding_helper.update_finding_status(new_finding, request.user)

            new_finding.save(dedupe_option=False, false_history=False)

            # Save and add new endpoints
            finding_helper.add_endpoints(new_finding, form)

            new_finding.save(false_history=True)
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(request.POST, prefix='jiraform', instance=new_finding, push_all=push_all_jira_issues, jira_project=jira_helper.get_jira_project(test), finding_form=form)
                if jform.is_valid():
                    if jform.cleaned_data.get('push_to_jira'):
                        jira_helper.push_to_jira(new_finding)
                else:
                    add_error_message_to_response('jira form validation failed: %s' % jform.errors)

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding from template added successfully.',
                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'The form has errors, please correct them below.',
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

    product_tab = Product_Tab(test.engagement.product, title="Add Finding", tab="engagements")
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

    add_breadcrumb(parent=test, title="Add From Template", top_level=False, request=request)
    return render(request, 'dojo/templates.html',
                  {'templates': paged_templates,
                   'filtered': templates,
                   'title_words': title_words,
                   'tid': tid,
                   'add_from_template': True,
                   })


@user_is_authorized(Test, Permissions.Import_Scan_Result, 'tid')
def re_import_scan_results(request, tid):
    additional_message = "When re-uploading a scan, any findings not found in original scan will be updated as " \
                         "mitigated.  The process attempts to identify the differences, however manual verification " \
                         "is highly recommended."
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
            active = form.cleaned_data['active']
            verified = form.cleaned_data['verified']
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

            # Tags are replaced, same behaviour as with django-tagging
            test.tags = tags
            test.version = version
            if scan and is_scan_file_too_large(scan):
                messages.add_message(request,
                                     messages.ERROR,
                                     "Report file is too large. Maximum supported size is {} MB".format(settings.SCAN_FILE_MAX_SIZE),
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('re_import_scan_results', args=(test.id,)))

            push_to_jira = push_all_jira_issues or (jform and jform.cleaned_data.get('push_to_jira'))
            error = False
            finding_count, new_finding_count, closed_finding_count, reactivated_finding_count, untouched_finding_count = 0, 0, 0, 0, 0
            reimporter = ReImporter()
            try:
                test, finding_count, new_finding_count, closed_finding_count, reactivated_finding_count, untouched_finding_count, _ = \
                    reimporter.reimport_scan(scan, scan_type, test, active=active, verified=verified,
                                                tags=None, minimum_severity=minimum_severity,
                                                endpoints_to_add=endpoints_to_add, scan_date=scan_date,
                                                version=version, branch_tag=branch_tag, build_id=build_id,
                                                commit_hash=commit_hash, push_to_jira=push_to_jira,
                                                close_old_findings=close_old_findings, group_by=group_by,
                                                api_scan_configuration=api_scan_configuration, service=service)
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

    product_tab = Product_Tab(engagement.product, title="Re-upload a %s" % scan_type, tab="engagements")
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
