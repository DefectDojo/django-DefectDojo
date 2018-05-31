# #  engagements
import logging
import os
from datetime import datetime, timedelta
import operator

from django.contrib.auth.models import User
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.http import HttpResponseRedirect, StreamingHttpResponse, Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from django.utils import timezone

from dojo.filters import EngagementFilter
from dojo.forms import CheckForm, \
    UploadThreatForm, UploadRiskForm, NoteForm, DoneForm, \
    EngForm, TestForm, ReplaceRiskAcceptanceForm, AddFindingsRiskAcceptanceForm, DeleteEngagementForm, ImportScanForm, \
    JIRAFindingForm, CredMappingForm
from dojo.models import Finding, Product, Engagement, Test, \
    Check_List, Test_Type, Notes, \
    Risk_Acceptance, Development_Environment, BurpRawRequestResponse, Endpoint, \
    JIRA_PKey, JIRA_Issue, Cred_Mapping, Dojo_User, System_Settings
from dojo.tools.factory import import_parser_factory
from dojo.utils import get_page_items, add_breadcrumb, handle_uploaded_threat, \
    FileIterWrapper, get_cal_event, message, get_system_setting, create_notification, tab_view_count
from dojo.tasks import update_epic_task, add_epic_task, close_epic_task

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
@cache_page(60 * 5)  # cache for 5 minutes
def engagement_calendar(request):
    if 'lead' not in request.GET or '0' in request.GET.getlist('lead'):
        engagements = Engagement.objects.all()
    else:
        filters = []
        leads = request.GET.getlist('lead', '')
        if '-1' in request.GET.getlist('lead'):
            leads.remove('-1')
            filters.append(Q(lead__isnull=True))
        filters.append(Q(lead__in=leads))
        engagements = Engagement.objects.filter(reduce(operator.or_, filters))

    add_breadcrumb(
        title="Engagement Calendar", top_level=True, request=request)
    return render(
        request, 'dojo/calendar.html', {
            'caltype': 'engagements',
            'leads': request.GET.getlist('lead', ''),
            'engagements': engagements,
            'users': Dojo_User.objects.all()
        })


@user_passes_test(lambda u: u.is_staff)
def engagement(request):
    filtered = EngagementFilter(
        request.GET,
        queryset=Product.objects.filter(
            ~Q(engagement=None),
            engagement__active=True,
        ).distinct())
    prods = get_page_items(request, filtered.qs, 25)
    name_words = [
        product.name for product in Product.objects.filter(
            ~Q(engagement=None),
            engagement__active=True,
        ).distinct()
    ]
    eng_words = [
        engagement.name for product in Product.objects.filter(
            ~Q(engagement=None),
            engagement__active=True,
        ).distinct() for engagement in product.engagement_set.all()
    ]

    add_breadcrumb(
        title="Active Engagements",
        top_level=not len(request.GET),
        request=request)

    return render(
        request, 'dojo/engagement.html', {
            'products': prods,
            'filtered': filtered,
            'name_words': sorted(set(name_words)),
            'eng_words': sorted(set(eng_words)),
        })


@user_passes_test(lambda u: u.is_staff)
def new_engagement(request):
    if request.method == 'POST':
        form = EngForm(request.POST)
        if form.is_valid():
            new_eng = form.save()
            new_eng.lead = request.user
            new_eng.threat_model = False
            new_eng.api_test = False
            new_eng.pen_test = False
            new_eng.check_list = False
            new_eng.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_eng.tags = t
            messages.add_message(
                request,
                messages.SUCCESS,
                'Engagement added successfully.',
                extra_tags='alert-success')
            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(
                    reverse('add_tests', args=(new_eng.id, )))
            else:
                return HttpResponseRedirect(
                    reverse('view_engagement', args=(new_eng.id, )))
    else:
        form = EngForm(initial={'date': timezone.now().date()})

    add_breadcrumb(title="New Engagement", top_level=False, request=request)
    return render(request, 'dojo/new_eng.html', {
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_engagement(request, eid):
    eng = Engagement.objects.get(pk=eid)
    jform = None
    if request.method == 'POST':
        form = EngForm(request.POST, instance=eng)
        if 'jiraform-push_to_jira' in request.POST:
            jform = JIRAFindingForm(
                request.POST, prefix='jiraform', enabled=True)

        if (form.is_valid() and jform is None) or (form.is_valid() and jform and jform.is_valid()):
            if 'jiraform-push_to_jira' in request.POST:
                try:
                    # jissue = JIRA_Issue.objects.get(engagement=eng)
                    update_epic_task.delay(
                        eng, jform.cleaned_data.get('push_to_jira'))
                    enabled = True
                except:
                    enabled = False
                    add_epic_task.delay(eng,
                                        jform.cleaned_data.get('push_to_jira'))
                    pass
            form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            eng.tags = t
            messages.add_message(
                request,
                messages.SUCCESS,
                'Engagement updated successfully.',
                extra_tags='alert-success')
            if '_Add Tests' in request.POST:
                return HttpResponseRedirect(
                    reverse('add_tests', args=(eng.id, )))
            else:
                return HttpResponseRedirect(
                    reverse('view_engagement', args=(eng.id, )))
    else:
        form = EngForm(instance=eng)
        try:
            # jissue = JIRA_Issue.objects.get(engagement=eng)
            enabled = True
        except:
            enabled = False
            pass

        if get_system_setting('enable_jira') and JIRA_PKey.objects.filter(
                product=eng.product).count() != 0:
            jform = JIRAFindingForm(prefix='jiraform', enabled=enabled)
        else:
            jform = None

    form.initial['tags'] = [tag.name for tag in eng.tags]
    add_breadcrumb(
        parent=eng, title="Edit Engagement", top_level=False, request=request)
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(eng.product.id)
    system_settings = System_Settings.objects.get()

    return render(request, 'dojo/new_eng.html', {
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'engagements',
        'system_settings': system_settings,
        'form': form,
        'edit': True,
        'jform': jform
    })


@user_passes_test(lambda u: u.is_staff)
def delete_engagement(request, eid):
    engagement = get_object_or_404(Engagement, pk=eid)
    product = engagement.product
    form = DeleteEngagementForm(instance=engagement)

    from django.contrib.admin.utils import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([engagement])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(engagement.id) == request.POST['id']:
            form = DeleteEngagementForm(request.POST, instance=engagement)
            if form.is_valid():
                del engagement.tags
                engagement.delete()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Engagement and relationships removed.',
                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse("view_engagements", args=(product.id, )))

    add_breadcrumb(
        parent=engagement, title="Delete", top_level=False, request=request)
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(product.id)
    system_settings = System_Settings.objects.get()

    return render(request, 'dojo/delete_engagement.html', {
        'active_tab': 'engagements',
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'system_settings': system_settings,
        'engagement': engagement,
        'form': form,
        'rels': rels,
    })


def view_engagement(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    tests = Test.objects.filter(engagement=eng).order_by('test_type__name')
    prod = eng.product
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    risks_accepted = eng.risk_acceptance.all()
    system_settings = System_Settings.objects.get()
    if not auth:
        # will render 403
        raise PermissionDenied

    try:
        jissue = JIRA_Issue.objects.get(engagement=eng)
    except:
        jissue = None
        pass
    try:
        jconf = JIRA_PKey.objects.get(product=eng.product).conf
    except:
        jconf = None
        pass
    exclude_findings = [
        finding.id for ra in eng.risk_acceptance.all()
        for finding in ra.accepted_findings.all()
    ]
    eng_findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by('title')

    try:
        check = Check_List.objects.get(engagement=eng)
    except:
        check = None
        pass
    form = DoneForm()
    if request.method == 'POST' and request.user.is_staff:
        eng.progress = 'check_list'
        eng.save()

    creds = Cred_Mapping.objects.filter(
        product=eng.product).select_related('cred_id').order_by('cred_id')
    cred_eng = Cred_Mapping.objects.filter(
        engagement=eng.id).select_related('cred_id').order_by('cred_id')

    add_breadcrumb(parent=eng, top_level=False, request=request)
    if hasattr(settings, 'ENABLE_DEDUPLICATION'):
        if settings.ENABLE_DEDUPLICATION:
            enabled = True
            findings = Finding.objects.filter(
                test__engagement=eng, duplicate=False)
        else:
            enabled = False
            findings = None
    else:
        enabled = False
        findings = None

    if findings is not None:
        fpage = get_page_items(request, findings, 15)
    else:
        fpage = None

    # ----------

    try:
        start_date = Finding.objects.filter(
            test__engagement__product=eng.product).order_by('date')[:1][0].date
    except:
        start_date = timezone.now()

    end_date = timezone.now()

    risk_acceptances = Risk_Acceptance.objects.filter(
        engagement__in=Engagement.objects.filter(product=eng.product))

    accepted_findings = [
        finding for ra in risk_acceptances
        for finding in ra.accepted_findings.all()
    ]

    week_date = end_date - timedelta(
        days=7)  # seven days and /newer are considered "new"

    new_verified_findings = Finding.objects.filter(
        test__engagement__product=eng.product,
        date__range=[week_date, end_date],
        false_p=False,
        verified=True,
        duplicate=False,
        out_of_scope=False).order_by("date")

    open_findings = Finding.objects.filter(
        test__engagement__product=eng.product,
        date__range=[start_date, end_date],
        false_p=False,
        verified=True,
        duplicate=False,
        out_of_scope=False,
        active=True,
        mitigated__isnull=True)

    closed_findings = Finding.objects.filter(
        test__engagement__product=eng.product,
        date__range=[start_date, end_date],
        false_p=False,
        verified=True,
        duplicate=False,
        out_of_scope=False,
        mitigated__isnull=False)

    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(prod.id)
    return render(
        request, 'dojo/view_eng.html', {
            'eng': eng,
            'active_tab': 'engagements',
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'system_settings': system_settings,
            'tests': tests,
            'findings': fpage,
            'enabled': enabled,
            'check': check,
            'threat': eng.tmodel_path,
            'risk': eng.risk_path,
            'form': form,
            'risks_accepted': risks_accepted,
            'can_add_risk': len(eng_findings),
            'jissue': jissue,
            'jconf': jconf,
            'open_findings': open_findings,
            'closed_findings': closed_findings,
            'accepted_findings': accepted_findings,
            'new_findings': new_verified_findings,
            'start_date': start_date,
            'creds': creds,
            'cred_eng': cred_eng
        })


@user_passes_test(lambda u: u.is_staff)
def add_tests(request, eid):
    eng = Engagement.objects.get(id=eid)
    cred_form = CredMappingForm()
    cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
        engagement=eng).order_by('cred_id')

    if request.method == 'POST':
        form = TestForm(request.POST)
        cred_form = CredMappingForm(request.POST)
        cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            engagement=eng).order_by('cred_id')
        if form.is_valid():
            new_test = form.save(commit=False)
            new_test.engagement = eng
            try:
                new_test.lead = User.objects.get(id=form['lead'].value())
            except:
                new_test.lead = None
                pass
            new_test.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_test.tags = t

            # Save the credential to the test
            if cred_form.is_valid():
                if cred_form.cleaned_data['cred_user']:
                    # Select the credential mapping object from the selected list and only allow if the credential is associated with the product
                    cred_user = Cred_Mapping.objects.filter(
                        pk=cred_form.cleaned_data['cred_user'].id,
                        engagement=eid).first()

                    new_f = cred_form.save(commit=False)
                    new_f.test = new_test
                    new_f.cred_id = cred_user.cred_id
                    new_f.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Test added successfully.',
                extra_tags='alert-success')

            create_notification(
                event='test_added',
                title=new_test.test_type.name + " for " + eng.product.name,
                test=new_test,
                engagement=eng,
                url=request.build_absolute_uri(
                    reverse('view_engagement', args=(eng.id, ))))

            if '_Add Another Test' in request.POST:
                return HttpResponseRedirect(
                    reverse('add_tests', args=(eng.id, )))
            elif '_Add Findings' in request.POST:
                return HttpResponseRedirect(
                    reverse('add_findings', args=(new_test.id, )))
            elif '_Finished' in request.POST:
                return HttpResponseRedirect(
                    reverse('view_engagement', args=(eng.id, )))
    else:
        form = TestForm()
        form.initial['target_start'] = eng.target_start
        form.initial['target_end'] = eng.target_end
        form.initial['lead'] = request.user
    add_breadcrumb(
        parent=eng, title="Add Tests", top_level=False, request=request)
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(eng.product.id)
    system_settings = System_Settings.objects.get()
    return render(request, 'dojo/add_tests.html', {
        'active_tab': 'engagements',
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'system_settings': system_settings,
        'form': form,
        'cred_form': cred_form,
        'eid': eid
    })


@user_passes_test(lambda u: u.is_staff)
def import_scan_results(request, eid):
    engagement = get_object_or_404(Engagement, id=eid)
    finding_count = 0
    form = ImportScanForm()
    cred_form = CredMappingForm()
    cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
        engagement=engagement).order_by('cred_id')

    if request.method == "POST":
        form = ImportScanForm(request.POST, request.FILES)
        cred_form = CredMappingForm(request.POST)
        cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            engagement=engagement).order_by('cred_id')
        if form.is_valid():
            file = request.FILES['file']
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            active = form.cleaned_data['active']
            verified = form.cleaned_data['verified']

            scan_type = request.POST['scan_type']
            if not any(scan_type in code
                       for code in ImportScanForm.SCAN_TYPE_CHOICES):
                raise Http404()

            tt, t_created = Test_Type.objects.get_or_create(name=scan_type)
            # will save in development environment
            environment, env_created = Development_Environment.objects.get_or_create(
                name="Development")
            t = Test(
                engagement=engagement,
                test_type=tt,
                target_start=scan_date,
                target_end=scan_date,
                environment=environment,
                percent_complete=100)
            t.lead = request.user
            t.full_clean()
            t.save()
            tags = request.POST.getlist('tags')
            ts = ", ".join(tags)
            t.tags = ts

            # Save the credential to the test
            if cred_form.is_valid():
                if cred_form.cleaned_data['cred_user']:
                    # Select the credential mapping object from the selected list and only allow if the credential is associated with the product
                    cred_user = Cred_Mapping.objects.filter(
                        pk=cred_form.cleaned_data['cred_user'].id,
                        engagement=eid).first()

                    new_f = cred_form.save(commit=False)
                    new_f.test = t
                    new_f.cred_id = cred_user.cred_id
                    new_f.save()

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
                    if item.date == timezone.now().date():
                        item.date = t.target_start

                    item.reporter = request.user
                    item.last_reviewed = timezone.now()
                    item.last_reviewed_by = request.user
                    item.active = active
                    item.verified = verified
                    item.save(dedupe_option=False)

                    if hasattr(item, 'unsaved_req_resp') and len(
                            item.unsaved_req_resp) > 0:
                        for req_resp in item.unsaved_req_resp:
                            burp_rr = BurpRawRequestResponse(
                                finding=item,
                                burpRequestBase64=req_resp["req"],
                                burpResponseBase64=req_resp["resp"],
                            )
                            burp_rr.clean()
                            burp_rr.save()

                    if item.unsaved_request is not None and item.unsaved_response is not None:
                        burp_rr = BurpRawRequestResponse(
                            finding=item,
                            burpRequestBase64=item.unsaved_request,
                            burpResponseBase64=item.unsaved_response,
                        )
                        burp_rr.clean()
                        burp_rr.save()

                    for endpoint in item.unsaved_endpoints:
                        ep, created = Endpoint.objects.get_or_create(
                            protocol=endpoint.protocol,
                            host=endpoint.host,
                            path=endpoint.path,
                            query=endpoint.query,
                            fragment=endpoint.fragment,
                            product=t.engagement.product)

                        item.endpoints.add(ep)
                    item.save()

                    if item.unsaved_tags is not None:
                        item.tags = item.unsaved_tags

                    finding_count += 1

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    scan_type + ' processed, a total of ' + message(
                        finding_count, 'finding', 'processed'),
                    extra_tags='alert-success')

                create_notification(
                    event='results_added',
                    title=str(finding_count) + " findings for " + engagement.product.name,
                    finding_count=finding_count,
                    test=t,
                    engagement=engagement,
                    url=request.build_absolute_uri(
                        reverse('view_test', args=(t.id, ))))

                return HttpResponseRedirect(
                    reverse('view_test', args=(t.id, )))
            except SyntaxError:
                messages.add_message(
                    request,
                    messages.ERROR,
                    'There appears to be an error in the XML report, please check and try again.',
                    extra_tags='alert-danger')

    add_breadcrumb(
        parent=engagement,
        title="Import Scan Results",
        top_level=False,
        request=request)
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(engagement.product.id)
    system_settings = System_Settings.objects.get()
    return render(request, 'dojo/import_scan_results.html', {
        'form': form,
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'engagements',
        'eid': engagement.id,
        'cred_form': cred_form,
    })


@user_passes_test(lambda u: u.is_staff)
def close_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    eng.active = False
    eng.status = 'Completed'
    eng.updated = timezone.now()
    eng.save()

    if get_system_setting('enable_jira'):
        jpkey_set = JIRA_PKey.objects.filter(product=eng.product)
        if jpkey_set.count() >= 1:
            close_epic_task(eng, True)
    messages.add_message(
        request,
        messages.SUCCESS,
        'Engagement closed successfully.',
        extra_tags='alert-success')
    return HttpResponseRedirect(reverse("view_engagements", args=(eng.product.id, )))


@user_passes_test(lambda u: u.is_staff)
def reopen_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    eng.active = True
    eng.status = 'In Progress'
    eng.save()
    messages.add_message(
        request,
        messages.SUCCESS,
        'Engagement reopened successfully.',
        extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_engagement', args=(eid, )))


"""
Greg:
status: in production
method to complete checklists from the engagement view
"""


@user_passes_test(lambda u: u.is_staff)
def complete_checklist(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    add_breadcrumb(
        parent=eng,
        title="Complete checklist",
        top_level=False,
        request=request)
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
            messages.add_message(
                request,
                messages.SUCCESS,
                'Checklist saved.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_engagement', args=(eid, )))
    else:
        tests = Test.objects.filter(engagement=eng)
        findings = Finding.objects.filter(test__in=tests).all()
        form = CheckForm(findings=findings)

    return render(request, 'dojo/checklist.html', {
        'form': form,
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
    exclude_findings = [
        finding.id for ra in eng.risk_acceptance.all()
        for finding in ra.accepted_findings.all()
    ]
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
                notes = Notes(
                    entry=form.cleaned_data['notes'],
                    author=request.user,
                    date=timezone.now())
                notes.save()
                risk.notes.add(notes)

            risk.save()  # saving notes and findings
            eng.risk_acceptance.add(risk)
            eng.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Risk acceptance saved.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_engagement', args=(eid, )))
    else:
        form = UploadRiskForm(initial={'reporter': request.user})

    form.fields["accepted_findings"].queryset = eng_findings
    add_breadcrumb(
        parent=eng,
        title="Upload Risk Acceptance",
        top_level=False,
        request=request)
    return render(request, 'dojo/up_risk.html', {'eng': eng, 'form': form})


def view_risk(request, eid, raid):
    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    eng = get_object_or_404(Engagement, pk=eid)
    if (request.user.is_staff or request.user in eng.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    a_file = risk_approval.path

    if request.method == 'POST':
        note_form = NoteForm(request.POST)
        if note_form.is_valid():
            new_note = note_form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            risk_approval.notes.add(new_note)
            messages.add_message(
                request,
                messages.SUCCESS,
                'Note added successfully.',
                extra_tags='alert-success')

        if 'delete_note' in request.POST:
            note = get_object_or_404(Notes, pk=request.POST['delete_note_id'])
            if note.author.username == request.user.username:
                risk_approval.notes.remove(note)
                note.delete()
                messages.add_message(
                    request,
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
            finding = get_object_or_404(
                Finding, pk=request.POST['remove_finding_id'])
            risk_approval.accepted_findings.remove(finding)
            finding.active = True
            finding.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding removed successfully.',
                extra_tags='alert-success')
        if 'replace_file' in request.POST:
            replace_form = ReplaceRiskAcceptanceForm(
                request.POST, request.FILES, instance=risk_approval)
            if replace_form.is_valid():
                risk_approval.path.delete(save=False)
                risk_approval.path = replace_form.cleaned_data['path']
                risk_approval.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'File replaced successfully.',
                    extra_tags='alert-success')
        if 'add_findings' in request.POST:
            add_findings_form = AddFindingsRiskAcceptanceForm(
                request.POST, request.FILES, instance=risk_approval)
            if add_findings_form.is_valid():
                findings = add_findings_form.cleaned_data['accepted_findings']
                for finding in findings:
                    finding.active = False
                    finding.save()
                    risk_approval.accepted_findings.add(finding)
                risk_approval.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Finding%s added successfully.' % ('s' if len(findings) > 1
                                                       else ''),
                    extra_tags='alert-success')

    note_form = NoteForm()
    replace_form = ReplaceRiskAcceptanceForm()
    add_findings_form = AddFindingsRiskAcceptanceForm()
    exclude_findings = [
        finding.id for ra in eng.risk_acceptance.all()
        for finding in ra.accepted_findings.all()
    ]
    findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by("title")

    add_fpage = get_page_items(request, findings, 10, 'apage')
    add_findings_form.fields[
        "accepted_findings"].queryset = add_fpage.object_list

    fpage = get_page_items(
        request,
        risk_approval.accepted_findings.order_by('numerical_severity'), 15)

    authorized = (request.user == risk_approval.reporter.username or request.user.is_staff)

    add_breadcrumb(parent=risk_approval, top_level=False, request=request)

    return render(
        request, 'dojo/view_risk.html', {
            'risk_approval': risk_approval,
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
    messages.add_message(
        request,
        messages.SUCCESS,
        'Risk acceptance deleted successfully.',
        extra_tags='alert-success')
    return HttpResponseRedirect(reverse("view_engagement", args=(eng.id, )))


def download_risk(request, eid, raid):
    import mimetypes

    mimetypes.init()

    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    en = get_object_or_404(Engagement, pk=eid)
    if (request.user.is_staff or request.user in en.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    response = StreamingHttpResponse(
        FileIterWrapper(
            open(settings.MEDIA_ROOT + "/" + risk_approval.path.name)))
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
    add_breadcrumb(
        parent=eng,
        title="Upload a threat model",
        top_level=False,
        request=request)

    if request.method == 'POST':
        form = UploadThreatForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_threat(request.FILES['file'], eng)
            eng.progress = 'other'
            eng.threat_model = True
            eng.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Threat model saved.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_engagement', args=(eid, )))
    else:
        form = UploadThreatForm()
    return render(request, 'dojo/up_threat.html', {
        'form': form,
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
    response[
        'Content-Disposition'] = 'attachment; filename=threatmodel' + fileExtension
    response['Content-Type'] = mimetype

    return response


@user_passes_test(lambda u: u.is_staff)
def engagement_ics(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    start_date = datetime.combine(eng.target_start, datetime.min.time())
    end_date = datetime.combine(eng.target_end, datetime.max.time())
    uid = "dojo_eng_%d_%d" % (eng.id, eng.product.id)
    cal = get_cal_event(
        start_date, end_date,
        "Engagement: %s (%s)" % (eng.name, eng.product.name),
        "Set aside for engagement %s, on product %s.  Additional detail can be found at %s"
        % (eng.name, eng.product.name,
           request.build_absolute_uri(
               (reverse("view_engagement", args=(eng.id, ))))), uid)
    output = cal.serialize()
    response = HttpResponse(content=output)
    response['Content-Type'] = 'text/calendar'
    response['Content-Disposition'] = 'attachment; filename=%s.ics' % eng.name
    return response
