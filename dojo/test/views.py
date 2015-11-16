# #  tests

import logging
from datetime import datetime

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponseForbidden, Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from pytz import timezone

from dojo.forms import NoteForm, TestForm, FindingForm, \
    DeleteTestForm, AddFindingForm, \
    ImportScanForm, ReImportScanForm
from dojo.models import Finding, Test, \
    Notes, \
    BurpRawRequestResponse, Endpoint
from dojo.tools.factory import import_parser_factory
from dojo.utils import get_page_items, add_breadcrumb, get_cal_event, template_search_helper, message

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def view_test(request, tid):
    test = Test.objects.get(id=tid)
    notes = test.notes.all()
    person = request.user.username
    findings = Finding.objects.filter(test=test)
    if request.method == 'POST':
        form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            test.notes.add(new_note)
            form = NoteForm()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')
    else:
        form = NoteForm()

    fpage = get_page_items(request, findings, 25)
    show_re_upload = any(test.test_type.name in code for code in ImportScanForm.SCAN_TYPE_CHOICES)

    add_breadcrumb(parent=test, top_level=False, request=request)
    return render(request, 'dojo/view_test.html',
                  {'test': test, 'findings': fpage,
                   'form': form, 'notes': notes,
                   'person': person, 'request': request, "show_re_upload": show_re_upload,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    form = TestForm(instance=test)
    if request.method == 'POST':
        form = TestForm(request.POST, instance=test)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test saved.',
                                 extra_tags='alert-success')

    form.initial['target_start'] = test.target_start.date()
    form.initial['target_end'] = test.target_end.date()

    add_breadcrumb(parent=test, title="Edit", top_level=False, request=request)
    return render(request, 'dojo/edit_test.html',
                  {'test': test,
                   'form': form,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    eng = test.engagement
    form = DeleteTestForm(instance=test)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([test])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(test.id) == request.POST['id']:
            form = DeleteTestForm(request.POST, instance=test)
            if form.is_valid():
                test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Test and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))

    add_breadcrumb(parent=test, title="Delete", top_level=False, request=request)
    return render(request, 'dojo/delete_test.html',
                  {'test': test,
                   'form': form,
                   'rels': rels,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_test_note(request, tid, nid):
    note = Notes.objects.get(id=nid)
    test = Test.objects.get(id=tid)
    if note.author == request.user:
        test.notes.remove(note)
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Note removed.',
                             extra_tags='alert-success')
        return view_test(request, tid)
    return HttpResponseForbidden()


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
    findings = Finding.objects.filter(is_template=True).distinct()
    form_error = False
    form = AddFindingForm()
    if request.method == 'POST':
        form = AddFindingForm(request.POST)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = datetime.now(tz=localtz)
                new_finding.mitigated_by = request.user

            new_finding.save()
            new_finding.endpoints = form.cleaned_data['endpoints']
            new_finding.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding added successfully.',
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
    add_breadcrumb(parent=test, title="Add Finding", top_level=False, request=request)
    return render(request, 'dojo/add_findings.html',
                  {'form': form,
                   'findings': findings,
                   'test': test,
                   'temp': False,
                   'tid': tid,
                   'form_error': form_error,
                   })


@user_passes_test(lambda u: u.is_staff)
def add_temp_finding(request, tid, fid):
    test = get_object_or_404(Test, id=tid)
    finding = get_object_or_404(Finding, id=fid)
    findings = Finding.objects.all()
    if request.method == 'POST':
        form = FindingForm(request.POST)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            new_finding.date = datetime.today()
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = datetime.now(tz=localtz)
                new_finding.mitigated_by = request.user

            new_finding.save()
            new_finding.endpoints = form.cleaned_data['endpoints']
            new_finding.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Temp finding added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'The form has errors, please correct them below.',
                                 extra_tags='alert-danger')

    else:
        form = FindingForm(instance=finding, initial={'is_template': False, 'active': False, 'verified': False,
                                                      'false_p': False, 'duplicate': False, 'out_of_scope': False})

    add_breadcrumb(parent=test, title="Add Finding", top_level=False, request=request)
    return render(request, 'dojo/add_findings.html',
                  {'form': form,
                   'findings': findings,
                   'temp': True,
                   'fid': finding.id,
                   'tid': test.id,
                   'test': test,
                   })


def search(request, tid):
    query_string = ''
    found_entries = Finding.objects.filter(is_template=True).distinct()
    if ('q' in request.GET) and request.GET['q'].strip():
        query_string = request.GET['q']
        found_entries = template_search_helper(
            fields=['title', 'description', ],
            query_string=query_string)
    else:
        found_entries = template_search_helper(
            fields=['title', 'description', ])

    return render(request,
                  'dojo/search_results.html',
                  {'query_string': query_string,
                   'found_entries': found_entries,
                   'tid': tid})


@user_passes_test(lambda u: u.is_staff)
def re_import_scan_results(request, tid):
    additional_message = "When re-uploading a scan, any findings not found in original scan will be updated as " \
                         "mitigated.  The process attempts to identify the differences, however manual verification " \
                         "is highly recommended."
    t = get_object_or_404(Test, id=tid)
    scan_type = t.test_type.name
    engagement = t.engagement
    form = ReImportScanForm()
    if request.method == "POST":
        form = ReImportScanForm(request.POST, request.FILES)
        if form.is_valid():
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            file = request.FILES['file']
            scan_type = t.test_type.name
            try:
                parser = import_parser_factory(file, t)
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
                    endpoints = item.unsaved_endpoints
                    sev = item.severity
                    if sev == 'Information':
                        sev = 'Info'

                    if Finding.SEVERITIES[sev] > Finding.SEVERITIES[min_sev]:
                        continue

                    if scan_type == 'Veracode Scan':
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
                        if find[0].mitigated:
                            # it was once fixed, but now back
                            find[0].mitigated = None
                            find[0].mitigated_by = None
                            find[0].active = True
                            find[0].save()
                            note = Notes(entry="Re-activated by %s re-upload." % scan_type,
                                         author=request.user)
                            note.save()
                            find[0].notes.add(note)
                            reactivated_count += 1
                        new_items.append(find[0].id)
                    else:
                        item.test = t
                        item.date = t.target_start
                        item.reporter = request.user
                        item.last_reviewed = datetime.now(tz=localtz)
                        item.last_reviewed_by = request.user
                        item.save()
                        finding_added_count += 1
                        new_items.append(item.id)
                        find = item
                        if item.unsaved_request is not None and item.unsaved_response is not None:
                            burp_rr = BurpRawRequestResponse(finding=find,
                                                             burpRequestBase64=item.unsaved_request,
                                                             burpResponseBase64=item.unsaved_response,
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

                # calculate the difference
                to_mitigate = set(original_items) - set(new_items)
                for finding_id in to_mitigate:
                    finding = Finding.objects.get(id=finding_id)
                    finding.mitigated = datetime.combine(scan_date, datetime.now(tz=localtz).time())
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
                return HttpResponseRedirect(reverse('view_test', args=(t.id,)))
            except SyntaxError:
                messages.add_message(request,
                                     messages.ERROR,
                                     'There appears to be an error in the XML report, please check and try again.',
                                     extra_tags='alert-danger')

    add_breadcrumb(parent=t, title="Re-upload a %s" % scan_type, top_level=False, request=request)
    return render(request,
                  'dojo/import_scan_results.html',
                  {'form': form,
                   'eid': engagement.id,
                   'additional_message': additional_message,
                   })
