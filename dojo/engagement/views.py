# #  engagements
import logging
import os
from datetime import datetime

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.http import HttpResponseRedirect, StreamingHttpResponse, Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from pytz import timezone

from dojo.filters import EngagementFilter
from dojo.forms import CheckForm, \
    UploadThreatForm, UploadRiskForm, NoteForm, DoneForm, \
    EngForm2, TestForm, ReplaceRiskAcceptanceForm, AddFindingsRiskAcceptanceForm, DeleteEngagementForm, ImportScanForm
from dojo.models import Finding, Product, Engagement, Test, \
    Check_List, Test_Type, Notes, \
    Risk_Acceptance, Development_Environment, BurpRawRequestResponse, Endpoint
from dojo.tools.factory import import_parser_factory
from dojo.utils import get_page_items, add_breadcrumb, handle_uploaded_threat, \
    FileIterWrapper, get_cal_event, message

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
@cache_page(60 * 5)  # cache for 5 minutes
def calendar(request):
    engagements = Engagement.objects.all()
    add_breadcrumb(title="Calendar", top_level=True, request=request)
    return render(request, 'dojo/calendar.html', {
        'engagements': engagements})


@user_passes_test(lambda u: u.is_staff)
def engagement(request):
    filtered = EngagementFilter(request.GET, queryset=Product.objects.filter(
        ~Q(engagement=None),
        engagement__active=True, ).distinct())
    prods = get_page_items(request, filtered, 25)
    name_words = [product.name for product in
                  Product.objects.filter(
                      ~Q(engagement=None),
                      engagement__active=True, ).distinct()]
    eng_words = [engagement.name for product in
                 Product.objects.filter(
                     ~Q(engagement=None),
                     engagement__active=True, ).distinct()
                 for engagement in product.engagement_set.all()]

    add_breadcrumb(title="Active Engagements", top_level=not len(request.GET), request=request)

    return render(request, 'dojo/engagement.html',
                  {'products': prods,
                   'filtered': filtered,
                   'name_words': sorted(set(name_words)),
                   'eng_words': sorted(set(eng_words)),
                   })


@user_passes_test(lambda u: u.is_staff)
def new_engagement(request):
    if request.method == 'POST':
        form = EngForm2(request.POST)
        if form.is_valid():
            new_eng = form.save()
            new_eng.lead = request.user
            new_eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement added successfully.',
                                 extra_tags='alert-success')
            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(new_eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(new_eng.id,)))
    else:
        form = EngForm2()

    add_breadcrumb(title="New Engagement", top_level=False, request=request)
    return render(request, 'dojo/new_eng.html',
                  {'form': form,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_engagement(request, eid):
    eng = Engagement.objects.get(pk=eid)
    if request.method == 'POST':
        form = EngForm2(request.POST, instance=eng)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement updated successfully.',
                                 extra_tags='alert-success')
            if '_Add Tests' in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))
    else:
        form = EngForm2(instance=eng)
    add_breadcrumb(parent=eng, title="Edit Engagement", top_level=False, request=request)
    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'edit': True,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_engagement(request, eid):
    engagement = get_object_or_404(Engagement, pk=eid)
    product = engagement.product
    form = DeleteEngagementForm(instance=engagement)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([engagement])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(engagement.id) == request.POST['id']:
            form = DeleteEngagementForm(request.POST, instance=engagement)
            if form.is_valid():
                engagement.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Engagement and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_product', args=(product.id,)))

    add_breadcrumb(parent=engagement, title="Delete", top_level=False, request=request)

    return render(request, 'dojo/delete_engagement.html',
                  {'engagement': engagement,
                   'form': form,
                   'rels': rels,
                   })


@user_passes_test(lambda u: u.is_staff)
def view_engagement(request, eid):
    eng = Engagement.objects.get(id=eid)
    tests = Test.objects.filter(engagement=eng)
    risks_accepted = eng.risk_acceptance.all()

    exclude_findings = [finding.id for ra in eng.risk_acceptance.all()
                        for finding in ra.accepted_findings.all()]
    eng_findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by('title')

    try:
        check = Check_List.objects.get(engagement=eng)
    except:
        check = None
        pass
    form = DoneForm()
    if request.method == 'POST':
        eng.progress = 'check_list'
        eng.save()

    add_breadcrumb(parent=eng, top_level=False, request=request)

    return render(request, 'dojo/view_eng.html',
                  {'eng': eng, 'tests': tests,
                   'check': check, 'threat': eng.tmodel_path,
                   'risk': eng.risk_path, 'form': form,
                   'risks_accepted': risks_accepted,
                   'can_add_risk': len(eng_findings),
                   })


@user_passes_test(lambda u: u.is_staff)
def add_tests(request, eid):
    eng = Engagement.objects.get(id=eid)
    if request.method == 'POST':
        form = TestForm(request.POST)
        if form.is_valid():
            new_test = form.save(commit=False)
            new_test.engagement = eng
            new_test.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test added successfully.',
                                 extra_tags='alert-success')
            if '_Add Another Test' in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(eng.id,)))
            elif '_Add Findings' in request.POST:
                return HttpResponseRedirect(reverse('add_findings', args=(new_test.id,)))
            elif '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))
    else:
        form = TestForm()
    add_breadcrumb(parent=eng, title="Add Tests", top_level=False, request=request)
    return render(request, 'dojo/add_tests.html',
                  {'form': form, 'eid': eid})


@user_passes_test(lambda u: u.is_staff)
def import_scan_results(request, eid):
    engagement = get_object_or_404(Engagement, id=eid)
    finding_count = 0
    form = ImportScanForm()
    if request.method == "POST":
        form = ImportScanForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']

            scan_type = request.POST['scan_type']
            if not any(scan_type in code for code in ImportScanForm.SCAN_TYPE_CHOICES):
                raise Http404()

            tt, t_created = Test_Type.objects.get_or_create(name=scan_type)
            # will save in development environment
            environment, env_created = Development_Environment.objects.get_or_create(name="Development")
            t = Test(engagement=engagement, test_type=tt, target_start=scan_date,
                     target_end=scan_date, environment=environment, percent_complete=100)
            t.full_clean()
            t.save()

            try:
                parser = import_parser_factory(file, t)
            except ValueError:
                raise Http404()

            try:
                for item in parser.items:
                    sev = item.severity
                    if sev == 'Information' or sev == 'Informational':
                        sev = 'Info'

                    item.severity = sev

                    if Finding.SEVERITIES[sev] > Finding.SEVERITIES[min_sev]:
                        continue

                    item.test = t
                    item.date = t.target_start
                    item.reporter = request.user
                    item.last_reviewed = datetime.now(tz=localtz)
                    item.last_reviewed_by = request.user
                    item.save()

                    if item.unsaved_request is not None and item.unsaved_response is not None:
                        burp_rr = BurpRawRequestResponse(finding=item,
                                                         burpRequestBase64=item.unsaved_request,
                                                         burpResponseBase64=item.unsaved_response,
                                                         )
                        burp_rr.clean()
                        burp_rr.save()

                    for endpoint in item.unsaved_endpoints:
                        ep, created = Endpoint.objects.get_or_create(protocol=endpoint.protocol,
                                                                     host=endpoint.host,
                                                                     path=endpoint.path,
                                                                     query=endpoint.query,
                                                                     fragment=endpoint.fragment,
                                                                     product=t.engagement.product)

                        item.endpoints.add(ep)

                    finding_count += 1

                messages.add_message(request,
                                     messages.SUCCESS,
                                     scan_type + ' processed, a total of ' + message(finding_count, 'finding',
                                                                                     'processed'),
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_test', args=(t.id,)))
            except SyntaxError:
                messages.add_message(request,
                                     messages.ERROR,
                                     'There appears to be an error in the XML report, please check and try again.',
                                     extra_tags='alert-danger')
    add_breadcrumb(parent=engagement, title="Import Scan Results", top_level=False, request=request)
    return render(request,
                  'dojo/import_scan_results.html',
                  {'form': form,
                   'eid': engagement.id,
                   })


@user_passes_test(lambda u: u.is_staff)
def close_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    eng.active = False
    eng.status = 'Completed'
    eng.save()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Engagement closed successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_product', args=(eng.product.id,)))


@user_passes_test(lambda u: u.is_staff)
def reopen_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    eng.active = True
    eng.status = 'In Progress'
    eng.save()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Engagement reopened successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))


"""
Greg:
status: in production
method to complete checklists from the engagement view
"""


@user_passes_test(lambda u: u.is_staff)
def complete_checklist(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    add_breadcrumb(parent=eng, title="Complete checklist", top_level=False, request=request)
    if request.method == 'POST':
        tests = Test.objects.filter(engagement=eng)
        findings = Finding.objects.filter(test__in=tests).all()
        form = CheckForm(request.POST, findings=findings)
        if form.is_valid():
            cl = form.save(commit=False)
            try:
                check_l = Check_List.objects.get(engagement=eng)
                cl.id = check_l.id
                cl.save()
                form.save_m2m()
            except:

                cl.engagement = eng
                cl.save()
                form.save_m2m()
                pass
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Checklist saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        tests = Test.objects.filter(engagement=eng)
        findings = Finding.objects.filter(test__in=tests).all()
        form = CheckForm(findings=findings)

    return render(request,
                  'dojo/checklist.html',
                  {'form': form,
                   'eid': eng.id,
                   'findings': findings,
                   })


"""
Greg
status: in produciton
upload accepted risk at the engagement
"""


@user_passes_test(lambda u: u.is_staff)
def upload_risk(request, eid):
    eng = Engagement.objects.get(id=eid)
    # exclude the findings already accepted
    exclude_findings = [finding.id for ra in eng.risk_acceptance.all()
                        for finding in ra.accepted_findings.all()]
    eng_findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by('title')

    if request.method == 'POST':
        form = UploadRiskForm(request.POST, request.FILES)
        if form.is_valid():
            findings = form.cleaned_data['accepted_findings']
            for finding in findings:
                finding.active = False
                finding.save()
            risk = form.save(commit=False)
            risk.reporter = form.cleaned_data['reporter']
            risk.path = form.cleaned_data['path']
            risk.save()  # have to save before findings can be added
            risk.accepted_findings = findings
            if form.cleaned_data['notes']:
                notes = Notes(entry=form.cleaned_data['notes'],
                              author=request.user,
                              date=localtz.localize(datetime.today()))
                notes.save()
                risk.notes.add(notes)

            risk.save()  # saving notes and findings
            eng.risk_acceptance.add(risk)
            eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Risk acceptance saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        form = UploadRiskForm(initial={'reporter': request.user})

    form.fields["accepted_findings"].queryset = eng_findings
    add_breadcrumb(parent=eng, title="Upload Risk Acceptance", top_level=False, request=request)
    return render(request, 'dojo/up_risk.html',
                  {'eng': eng, 'form': form})


def view_risk(request, eid, raid):
    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    eng = get_object_or_404(Engagement, pk=eid)
    if (request.user.is_staff or
                request.user in eng.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    a_file = risk_approval.path

    if request.method == 'POST':
        note_form = NoteForm(request.POST)
        if note_form.is_valid():
            new_note = note_form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            risk_approval.notes.add(new_note)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')

        if 'delete_note' in request.POST:
            note = get_object_or_404(Notes, pk=request.POST['delete_note_id'])
            if note.author.username == request.user.username:
                risk_approval.notes.remove(note)
                note.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Note deleted successfully.',
                                     extra_tags='alert-success')
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Since you are not the note's author, it was not deleted.",
                    extra_tags='alert-danger')

        if 'remove_finding' in request.POST:
            finding = get_object_or_404(Finding,
                                        pk=request.POST['remove_finding_id'])
            risk_approval.accepted_findings.remove(finding)
            finding.active = True
            finding.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding removed successfully.',
                                 extra_tags='alert-success')
        if 'replace_file' in request.POST:
            replace_form = ReplaceRiskAcceptanceForm(
                request.POST,
                request.FILES,
                instance=risk_approval)
            if replace_form.is_valid():
                risk_approval.path.delete(save=False)
                risk_approval.path = replace_form.cleaned_data['path']
                risk_approval.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'File replaced successfully.',
                                     extra_tags='alert-success')
        if 'add_findings' in request.POST:
            add_findings_form = AddFindingsRiskAcceptanceForm(
                request.POST,
                request.FILES,
                instance=risk_approval)
            if add_findings_form.is_valid():
                findings = add_findings_form.cleaned_data[
                    'accepted_findings']
                for finding in findings:
                    finding.active = False
                    finding.save()
                    risk_approval.accepted_findings.add(finding)
                risk_approval.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Finding%s added successfully.' % ('s'
                                                       if len(findings) > 1 else ''),
                    extra_tags='alert-success')

    note_form = NoteForm()
    replace_form = ReplaceRiskAcceptanceForm()
    add_findings_form = AddFindingsRiskAcceptanceForm()
    exclude_findings = [finding.id for ra in eng.risk_acceptance.all()
                        for finding in ra.accepted_findings.all()]
    findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by("title")

    add_fpage = get_page_items(request, findings, 10, 'apage')
    add_findings_form.fields[
        "accepted_findings"].queryset = add_fpage.object_list

    fpage = get_page_items(request, risk_approval.accepted_findings.order_by(
        'numerical_severity'), 15)

    authorized = (request.user == risk_approval.reporter.username
                  or request.user.is_staff)

    add_breadcrumb(parent=risk_approval, top_level=False, request=request)

    return render(request, 'dojo/view_risk.html',
                  {'risk_approval': risk_approval,
                   'accepted_findings': fpage,
                   'notes': risk_approval.notes.all(),
                   'a_file': a_file,
                   'eng': eng,
                   'note_form': note_form,
                   'replace_form': replace_form,
                   'add_findings_form': add_findings_form,
                   'show_add_findings_form': len(findings),
                   'request': request,
                   'add_findings': add_fpage,
                   'authorized': authorized,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_risk(request, eid, raid):
    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    eng = get_object_or_404(Engagement, pk=eid)

    for finding in risk_approval.accepted_findings.all():
        finding.active = True
        finding.save()

    risk_approval.accepted_findings.clear()
    eng.risk_acceptance.remove(risk_approval)
    eng.save()

    for note in risk_approval.notes.all():
        note.delete()

    risk_approval.path.delete()
    risk_approval.delete()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Risk acceptance deleted successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse("view_engagement", args=(eng.id,)))


def download_risk(request, eid, raid):
    import mimetypes

    mimetypes.init()

    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    en = get_object_or_404(Engagement, pk=eid)
    if (request.user.is_staff
        or request.user in en.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    response = StreamingHttpResponse(
        FileIterWrapper(open(
            settings.MEDIA_ROOT + "/" + risk_approval.path.name)))
    response['Content-Disposition'] = 'attachment; filename="%s"' \
                                      % risk_approval.filename()
    mimetype, encoding = mimetypes.guess_type(risk_approval.path.name)
    response['Content-Type'] = mimetype
    return response


"""
Greg
status: in production
Upload a threat model at the engagement level. Threat models are stored
under media folder
"""


@user_passes_test(lambda u: u.is_staff)
def upload_threatmodel(request, eid):
    eng = Engagement.objects.get(id=eid)
    add_breadcrumb(parent=eng, title="Upload a threat model", top_level=False, request=request)

    if request.method == 'POST':
        form = UploadThreatForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_threat(request.FILES['file'], eng)
            eng.progress = 'other'
            eng.threat_model = True
            eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Threat model saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        form = UploadThreatForm()
    return render(request,
                  'dojo/up_threat.html',
                  {'form': form,
                   'eng': eng,
                   })


@user_passes_test(lambda u: u.is_staff)
def view_threatmodel(request, eid):
    import mimetypes

    mimetypes.init()
    eng = get_object_or_404(Engagement, pk=eid)
    mimetype, encoding = mimetypes.guess_type(eng.tmodel_path)
    response = StreamingHttpResponse(FileIterWrapper(open(eng.tmodel_path)))
    fileName, fileExtension = os.path.splitext(eng.tmodel_path)
    response['Content-Disposition'] = 'attachment; filename=threatmodel' + fileExtension
    response['Content-Type'] = mimetype

    return response


@user_passes_test(lambda u: u.is_staff)
def engagement_ics(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    start_date = datetime.combine(eng.target_start, datetime.min.time())
    end_date = datetime.combine(eng.target_end, datetime.max.time())
    uid = "dojo_eng_%d_%d" % (eng.id, eng.product.id)
    cal = get_cal_event(start_date,
                        end_date,
                        "Engagement: %s (%s)" % (eng.name, eng.product.name),
                        "Set aside for engagement %s, on product %s.  Additional detail can be found at %s" % (
                            eng.name, eng.product.name,
                            request.build_absolute_uri((reverse("view_engagement", args=(eng.id,))))),
                        uid)
    output = cal.serialize()
    response = HttpResponse(content=output)
    response['Content-Type'] = 'text/calendar'
    response['Content-Disposition'] = 'attachment; filename=%s.ics' % eng.name
    return response
