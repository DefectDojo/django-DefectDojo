# #  tests

import logging
import operator
from datetime import datetime

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.db.models import Q
from django.http import HttpResponseRedirect, Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from django.utils import timezone
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from tagging.models import Tag

from dojo.filters import TemplateFindingFilter
from dojo.forms import NoteForm, TestForm, FindingForm, \
    DeleteTestForm, AddFindingForm, \
    ImportScanForm, ReImportScanForm, FindingBulkUpdateForm, JIRAFindingForm
from dojo.models import Product, Finding, Test, Notes, Note_Type, BurpRawRequestResponse, Endpoint, Stub_Finding, Finding_Template, JIRA_PKey, Cred_Mapping, Dojo_User, JIRA_Issue
from dojo.tools.factory import import_parser_factory
from dojo.utils import get_page_items, add_breadcrumb, get_cal_event, message, process_notifications, get_system_setting, create_notification, Product_Tab, calculate_grade, log_jira_alert
from dojo.tasks import add_issue_task, update_issue_task
from functools import reduce

logger = logging.getLogger(__name__)


def view_test(request, tid):
    test = Test.objects.get(id=tid)
    prod = test.engagement.product
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    tags = Tag.objects.usage_for_model(Finding)
    if not auth:
        # will render 403
        raise PermissionDenied
    notes = test.notes.all()
    person = request.user.username
    findings = Finding.objects.filter(test=test).order_by('numerical_severity')
    stub_findings = Stub_Finding.objects.filter(test=test)
    cred_test = Cred_Mapping.objects.filter(test=test).select_related('cred_id').order_by('cred_id')
    creds = Cred_Mapping.objects.filter(engagement=test.engagement).select_related('cred_id').order_by('cred_id')

    if request.method == 'POST' and request.user.is_staff:
        form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            test.notes.add(new_note)
            form = NoteForm()
            url = request.build_absolute_uri(reverse("view_test", args=(test.id,)))
            title = "Test: %s on %s" % (test.test_type.name, test.engagement.product.name)
            process_notifications(request, new_note, url, title)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')
    else:
        form = NoteForm()

    fpage = get_page_items(request, findings, 25)
    sfpage = get_page_items(request, stub_findings, 25)
    show_re_upload = any(test.test_type.name in code for code in ImportScanForm.SCAN_TYPE_CHOICES)

    product_tab = Product_Tab(prod.id, title="Test", tab="engagements")
    product_tab.setEngagement(test.engagement)
    jira_config = JIRA_PKey.objects.filter(product=prod.id).first()
    if jira_config:
        jira_config = jira_config.conf_id
    return render(request, 'dojo/view_test.html',
                  {'test': test,
                   'product_tab': product_tab,
                   'findings': fpage,
                   'findings_count': findings.count(),
                   'stub_findings': sfpage,
                   'form': form,
                   'notes': notes,
                   'person': person,
                   'request': request,
                   'show_re_upload': show_re_upload,
                   'creds': creds,
                   'cred_test': cred_test,
                   'tag_input': tags,
                   'jira_config': jira_config,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    form = TestForm(instance=test)
    if request.method == 'POST':
        form = TestForm(request.POST, instance=test)
        if form.is_valid():
            new_test = form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_test.tags = t
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(test.engagement.id,)))

    form.initial['target_start'] = test.target_start.date()
    form.initial['target_end'] = test.target_end.date()
    form.initial['tags'] = [tag.name for tag in test.tags]

    product_tab = Product_Tab(test.engagement.product.id, title="Edit Test", tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, 'dojo/edit_test.html',
                  {'test': test,
                   'product_tab': product_tab,
                   'form': form,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    eng = test.engagement
    form = DeleteTestForm(instance=test)

    if request.method == 'POST':
        if 'id' in request.POST and str(test.id) == request.POST['id']:
            form = DeleteTestForm(request.POST, instance=test)
            if form.is_valid():
                del test.tags
                test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Test and relationships removed.',
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title='Deletion of %s' % test.title,
                                    description='The test "%s" was deleted by %s' % (test.title, request.user),
                                    url=request.build_absolute_uri(reverse('view_engagement', args=(eng.id, ))),
                                    recipients=[test.engagement.lead],
                                    icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([test])
    rels = collector.nested()

    product_tab = Product_Tab(test.engagement.product.id, title="Delete Test", tab="engagements")
    product_tab.setEngagement(test.engagement)
    return render(request, 'dojo/delete_test.html',
                  {'test': test,
                   'product_tab': product_tab,
                   'form': form,
                   'rels': rels,
                   'deletable_objects': rels,
                   })


@user_passes_test(lambda u: u.is_staff)
@cache_page(60 * 5)  # cache for 5 minutes
def test_calendar(request):
    if 'lead' not in request.GET or '0' in request.GET.getlist('lead'):
        tests = Test.objects.all()
    else:
        filters = []
        leads = request.GET.getlist('lead', '')
        if '-1' in request.GET.getlist('lead'):
            leads.remove('-1')
            filters.append(Q(lead__isnull=True))
        filters.append(Q(lead__in=leads))
        tests = Test.objects.filter(reduce(operator.or_, filters))
    add_breadcrumb(title="Test Calendar", top_level=True, request=request)
    return render(request, 'dojo/calendar.html', {
        'caltype': 'tests',
        'leads': request.GET.getlist('lead', ''),
        'tests': tests,
        'users': Dojo_User.objects.all()})


@user_passes_test(lambda u: u.is_staff)
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


@user_passes_test(lambda u: u.is_staff)
def add_findings(request, tid):
    test = Test.objects.get(id=tid)
    form_error = False
    enabled = False
    jform = None
    form = AddFindingForm(initial={'date': timezone.now().date()})

    if get_system_setting('enable_jira') and JIRA_PKey.objects.filter(product=test.engagement.product).count() != 0:
        enabled = JIRA_PKey.objects.get(product=test.engagement.product).push_all_issues
        jform = JIRAFindingForm(enabled=enabled, prefix='jiraform')
    else:
        jform = None

    if request.method == 'POST':
        form = AddFindingForm(request.POST)
        if form['active'].value() is False or form['verified'].value() is False and 'jiraform-push_to_jira' in request.POST:
            error = ValidationError('Findings must be active and verified to be pushed to JIRA',
                                    code='not_active_or_verified')
            if form['active'].value() is False:
                form.add_error('active', error)
            if form['verified'].value() is False:
                form.add_error('verified', error)
            messages.add_message(request,
                                 messages.ERROR,
                                 'Findings must be active and verified to be pushed to JIRA',
                                 extra_tags='alert-danger')
        if form['severity'].value() == 'Info' and 'jiraform-push_to_jira' in request.POST:
            error = ValidationError('Findings with Informational severity cannot be pushed to JIRA.',
                                    code='info-severity-to-jira')

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
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = timezone.now()
                new_finding.mitigated_by = request.user
            create_template = new_finding.is_template
            # always false now since this will be deprecated soon in favor of new Finding_Template model
            new_finding.is_template = False
            new_finding.save(dedupe_option=False)
            new_finding.endpoints.set(form.cleaned_data['endpoints'])
            new_finding.save(false_history=True)
            create_notification(event='other',
                                title='Addition of %s' % new_finding.title,
                                description='Finding "%s" was added by %s' % (new_finding.title, request.user),
                                url=request.build_absolute_uri(reverse('view_finding', args=(new_finding.id,))),
                                icon="exclamation-triangle")
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(request.POST, prefix='jiraform', enabled=enabled)
                if jform.is_valid():
                    add_issue_task.delay(new_finding, jform.cleaned_data.get('push_to_jira'))
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Finding added successfully.',
                                     extra_tags='alert-success')
            if create_template:
                templates = Finding_Template.objects.filter(title=new_finding.title)
                if len(templates) > 0:
                    messages.add_message(request,
                                         messages.ERROR,
                                         'A finding template was not created.  A template with this title already '
                                         'exists.',
                                         extra_tags='alert-danger')
                else:
                    template = Finding_Template(title=new_finding.title,
                                                cwe=new_finding.cwe,
                                                severity=new_finding.severity,
                                                description=new_finding.description,
                                                mitigation=new_finding.mitigation,
                                                impact=new_finding.impact,
                                                references=new_finding.references,
                                                numerical_severity=new_finding.numerical_severity)
                    template.save()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A finding template was also created.',
                                         extra_tags='alert-success')
            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_findings', args=(test.id,)))
        else:
            if 'endpoints' in form.cleaned_data:
                form.fields['endpoints'].queryset = form.cleaned_data['endpoints']
            else:
                form.fields['endpoints'].queryset = Endpoint.objects.none()
            form_error = True
            messages.add_message(request,
                                 messages.ERROR,
                                 'The form has errors, please correct them below.',
                                 extra_tags='alert-danger')
    product_tab = Product_Tab(test.engagement.product.id, title="Add Finding", tab="engagements")
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


@user_passes_test(lambda u: u.is_staff)
def add_temp_finding(request, tid, fid):
    jform = None
    test = get_object_or_404(Test, id=tid)
    finding = get_object_or_404(Finding_Template, id=fid)
    findings = Finding_Template.objects.all()

    if request.method == 'POST':
        form = FindingForm(request.POST, template=True)
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
            new_finding.date = datetime.today()
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = timezone.now()
                new_finding.mitigated_by = request.user

            create_template = new_finding.is_template
            # is template always False now in favor of new model Finding_Template
            # no further action needed here since this is already adding from template.
            new_finding.is_template = False
            new_finding.save(dedupe_option=False, false_history=False)
            new_finding.endpoints.set(form.cleaned_data['endpoints'])
            new_finding.save(false_history=True)
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_finding.tags = t
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(request.POST, prefix='jiraform', enabled=True)
                if jform.is_valid():
                    add_issue_task.delay(new_finding, jform.cleaned_data.get('push_to_jira'))
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding from template added successfully.',
                                 extra_tags='alert-success')

            if create_template:
                templates = Finding_Template.objects.filter(title=new_finding.title)
                if len(templates) > 0:
                    messages.add_message(request,
                                         messages.ERROR,
                                         'A finding template was not created.  A template with this title already '
                                         'exists.',
                                         extra_tags='alert-danger')
                else:
                    template = Finding_Template(title=new_finding.title,
                                                cwe=new_finding.cwe,
                                                severity=new_finding.severity,
                                                description=new_finding.description,
                                                mitigation=new_finding.mitigation,
                                                impact=new_finding.impact,
                                                references=new_finding.references,
                                                numerical_severity=new_finding.numerical_severity)
                    template.save()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A finding template was also created.',
                                         extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'The form has errors, please correct them below.',
                                 extra_tags='alert-danger')
    else:
        form = FindingForm(template=True, initial={'active': False,
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
                                    'numerical_severity': finding.numerical_severity,
                                    'tags': [tag.name for tag in finding.tags]})
        if get_system_setting('enable_jira'):
            enabled = JIRA_PKey.objects.get(product=test.engagement.product).push_all_issues
            jform = JIRAFindingForm(enabled=enabled, prefix='jiraform')
        else:
            jform = None

    product_tab = Product_Tab(test.engagement.product.id, title="Add Finding", tab="engagements")
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


def search(request, tid):
    test = get_object_or_404(Test, id=tid)
    templates = Finding_Template.objects.all()
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)
    title_words = [word
                   for finding in templates.qs
                   for word in finding.title.split() if len(word) > 2]

    title_words = sorted(set(title_words))
    add_breadcrumb(parent=test, title="Add From Template", top_level=False, request=request)
    return render(request, 'dojo/templates.html',
                  {'templates': paged_templates,
                   'filtered': templates,
                   'title_words': title_words,
                   'tid': tid,
                   'add_from_template': True,
                   })


@user_passes_test(lambda u: u.is_staff)
def finding_bulk_update(request, tid):
    test = get_object_or_404(Test, id=tid)
    form = FindingBulkUpdateForm(request.POST)

    if request.method == "POST":
        finding_to_update = request.POST.getlist('finding_to_update')
        if request.POST.get('delete_bulk_findings') and finding_to_update:
            finds = Finding.objects.filter(test=test, id__in=finding_to_update)
            product = Product.objects.get(engagement__test=test)
            finds.delete()
            calculate_grade(product)
        else:
            if form.is_valid() and finding_to_update:
                finding_to_update = request.POST.getlist('finding_to_update')
                finds = Finding.objects.filter(test=test, id__in=finding_to_update)
                if form.cleaned_data['severity']:
                    finds.update(severity=form.cleaned_data['severity'],
                                 numerical_severity=Finding.get_numerical_severity(form.cleaned_data['severity']),
                                 last_reviewed=timezone.now(),
                                 last_reviewed_by=request.user)
                if form.cleaned_data['status']:
                    finds.update(active=form.cleaned_data['active'],
                                 verified=form.cleaned_data['verified'],
                                 false_p=form.cleaned_data['false_p'],
                                 out_of_scope=form.cleaned_data['out_of_scope'],
                                 is_Mitigated=form.cleaned_data['is_Mitigated'],
                                 last_reviewed=timezone.now(),
                                 last_reviewed_by=request.user)
                if form.cleaned_data['tags']:
                    for finding in finds:
                        tags = request.POST.getlist('tags')
                        ts = ", ".join(tags)
                        finding.tags = ts

                # Update the grade as bulk edits don't go through save
                if form.cleaned_data['severity'] or form.cleaned_data['status']:
                    calculate_grade(test.engagement.product)

                for finding in finds:
                    from dojo.tasks import async_tool_issue_updater
                    async_tool_issue_updater.delay(finding)

                    if JIRA_PKey.objects.filter(product=finding.test.engagement.product).count() == 0:
                        log_jira_alert('Finding cannot be pushed to jira as there is no jira configuration for this product.', finding)
                    else:
                        old_status = finding.status()
                        if form.cleaned_data['push_to_jira']:
                            if JIRA_Issue.objects.filter(finding=finding).exists():
                                update_issue_task.delay(finding, old_status, True)
                            else:
                                add_issue_task.delay(finding, True)

                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Bulk edit of findings was successful.  Check to make sure it is what you intended.',
                                     extra_tags='alert-success')
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to process bulk update. Required fields were not selected.',
                                     extra_tags='alert-danger')

    return HttpResponseRedirect(reverse('view_test', args=(test.id,)))


@user_passes_test(lambda u: u.is_staff)
def re_import_scan_results(request, tid):
    additional_message = "When re-uploading a scan, any findings not found in original scan will be updated as " \
                         "mitigated.  The process attempts to identify the differences, however manual verification " \
                         "is highly recommended."
    t = get_object_or_404(Test, id=tid)
    scan_type = t.test_type.name
    engagement = t.engagement
    form = ReImportScanForm()

    form.initial['tags'] = [tag.name for tag in t.tags]
    if request.method == "POST":
        form = ReImportScanForm(request.POST, request.FILES)
        if form.is_valid():
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            file = request.FILES['file']
            scan_type = t.test_type.name
            active = form.cleaned_data['active']
            verified = form.cleaned_data['verified']
            tags = request.POST.getlist('tags')
            ts = ", ".join(tags)
            t.tags = ts
            try:
                parser = import_parser_factory(file, t, active, verified)
            except ValueError:
                raise Http404()

            try:
                items = parser.items
                original_items = t.finding_set.all().values_list("id", flat=True)
                new_items = []
                mitigated_count = 0
                finding_count = 0
                finding_added_count = 0
                reactivated_count = 0
                for item in items:
                    sev = item.severity
                    if sev == 'Information' or sev == 'Informational':
                        sev = 'Info'
                        item.severity = sev

                    if Finding.SEVERITIES[sev] > Finding.SEVERITIES[min_sev]:
                        continue

                    if scan_type == 'Veracode Scan' or scan_type == 'Arachni Scan':
                        find = Finding.objects.filter(title=item.title,
                                                      test__id=t.id,
                                                      severity=sev,
                                                      numerical_severity=Finding.get_numerical_severity(sev),
                                                      description=item.description
                                                      )
                    else:
                        find = Finding.objects.filter(title=item.title,
                                                      test__id=t.id,
                                                      severity=sev,
                                                      numerical_severity=Finding.get_numerical_severity(sev),
                                                      )

                    if len(find) == 1:
                        find = find[0]
                        if find.mitigated:
                            # it was once fixed, but now back
                            find.mitigated = None
                            find.mitigated_by = None
                            find.active = True
                            find.verified = verified
                            find.save()
                            note = Notes(entry="Re-activated by %s re-upload." % scan_type,
                                         author=request.user)
                            note.save()
                            find.notes.add(note)
                            reactivated_count += 1
                        new_items.append(find.id)
                    else:
                        item.test = t
                        item.date = scan_date
                        item.reporter = request.user
                        item.last_reviewed = timezone.now()
                        item.last_reviewed_by = request.user
                        item.verified = verified
                        item.active = active
                        item.save(dedupe_option=False)
                        finding_added_count += 1
                        new_items.append(item.id)
                        find = item

                        if hasattr(item, 'unsaved_req_resp') and len(item.unsaved_req_resp) > 0:
                            for req_resp in item.unsaved_req_resp:
                                if scan_type == "Arachni Scan":
                                    burp_rr = BurpRawRequestResponse(
                                        finding=item,
                                        burpRequestBase64=req_resp["req"],
                                        burpResponseBase64=req_resp["resp"],
                                    )
                                else:
                                    burp_rr = BurpRawRequestResponse(
                                        finding=item,
                                        burpRequestBase64=req_resp["req"].encode("utf-8"),
                                        burpResponseBase64=req_resp["resp"].encode("utf-8"),
                                    )
                                burp_rr.clean()
                                burp_rr.save()

                        if item.unsaved_request is not None and item.unsaved_response is not None:
                            burp_rr = BurpRawRequestResponse(finding=find,
                                                             burpRequestBase64=item.unsaved_request.encode("utf-8"),
                                                             burpResponseBase64=item.unsaved_response.encode("utf-8"),
                                                             )
                            burp_rr.clean()
                            burp_rr.save()
                    if find:
                        finding_count += 1
                        for endpoint in item.unsaved_endpoints:
                            ep, created = Endpoint.objects.get_or_create(protocol=endpoint.protocol,
                                                                         host=endpoint.host,
                                                                         path=endpoint.path,
                                                                         query=endpoint.query,
                                                                         fragment=endpoint.fragment,
                                                                         product=t.engagement.product)
                            find.endpoints.add(ep)

                        if item.unsaved_tags is not None:
                            find.tags = item.unsaved_tags

                    find.save()
                # calculate the difference
                to_mitigate = set(original_items) - set(new_items)
                for finding_id in to_mitigate:
                    finding = Finding.objects.get(id=finding_id)
                    finding.mitigated = datetime.combine(scan_date, timezone.now().time())
                    finding.mitigated_by = request.user
                    finding.active = False
                    finding.save()
                    note = Notes(entry="Mitigated by %s re-upload." % scan_type,
                                 author=request.user)
                    note.save()
                    finding.notes.add(note)
                    mitigated_count += 1
                messages.add_message(request,
                                     messages.SUCCESS,
                                     '%s processed, a total of ' % scan_type + message(finding_count, 'finding',
                                                                                       'processed'),
                                     extra_tags='alert-success')
                if finding_added_count > 0:
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A total of ' + message(finding_added_count, 'finding',
                                                                 'added') + ', that are new to scan.',
                                         extra_tags='alert-success')
                if reactivated_count > 0:
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A total of ' + message(reactivated_count, 'finding',
                                                                 'reactivated') + ', that are back in scan results.',
                                         extra_tags='alert-success')
                if mitigated_count > 0:
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A total of ' + message(mitigated_count, 'finding',
                                                                 'mitigated') + '. Please manually verify each one.',
                                         extra_tags='alert-success')

                create_notification(event='results_added', title=str(finding_count) + " findings for " + engagement.product.name, finding_count=finding_count, test=t, engagement=engagement, url=reverse('view_test', args=(t.id,)))

                return HttpResponseRedirect(reverse('view_test', args=(t.id,)))
            except SyntaxError:
                messages.add_message(request,
                                     messages.ERROR,
                                     'There appears to be an error in the XML report, please check and try again.',
                                     extra_tags='alert-danger')

    product_tab = Product_Tab(engagement.product.id, title="Re-upload a %s" % scan_type, tab="engagements")
    product_tab.setEngagement(engagement)
    return render(request,
                  'dojo/import_scan_results.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'eid': engagement.id,
                   'additional_message': additional_message,
                   })
