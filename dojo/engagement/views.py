#  engagements
import logging
from datetime import datetime
import operator
import base64
from django.contrib.auth.models import User
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.db.models import Q, Count
from django.http import HttpResponseRedirect, StreamingHttpResponse, Http404, HttpResponse, FileResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from django.utils import timezone
from time import strftime
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS

from dojo.engagement.services import close_engagement, reopen_engagement
from dojo.filters import EngagementFilter
from dojo.forms import CheckForm, \
    UploadThreatForm, UploadRiskForm, NoteForm, \
    EngForm, TestForm, ReplaceRiskAcceptanceForm, AddFindingsRiskAcceptanceForm, DeleteEngagementForm, ImportScanForm, \
    CredMappingForm, JIRAEngagementForm, JIRAImportScanForm, TypedNoteForm, JIRAProjectForm

from dojo.models import Finding, Product, Engagement, Test, \
    Check_List, Test_Type, Notes, \
    Risk_Acceptance, Development_Environment, BurpRawRequestResponse, Endpoint, \
    Cred_Mapping, Dojo_User, System_Settings, Note_Type, Endpoint_Status
from dojo.tools import handles_active_verified_statuses
from dojo.tools.factory import import_parser_factory
from dojo.utils import get_page_items, add_breadcrumb, handle_uploaded_threat, \
    FileIterWrapper, get_cal_event, message, Product_Tab, is_scan_file_too_large, \
    get_system_setting
from dojo.notifications.helper import create_notification
from dojo.finding.views import find_available_notetypes
from functools import reduce
from django.db.models.query import QuerySet
from dojo.user.helper import user_must_be_authorized, user_is_authorized, check_auth_users_list
import dojo.jira_link.helper as jira_helper


logger = logging.getLogger(__name__)
parse_logger = logging.getLogger('dojo')


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
    products_with_engagements = Product.objects.filter(~Q(engagement=None), engagement__active=True).distinct()
    filtered = EngagementFilter(
        request.GET,
        queryset=products_with_engagements.prefetch_related('engagement_set', 'prod_type', 'engagement_set__lead',
                                                            'engagement_set__test_set__lead', 'engagement_set__test_set__test_type'))
    prods = get_page_items(request, filtered.qs, 25)
    name_words = products_with_engagements.values_list('name', flat=True)
    eng_words = Engagement.objects.filter(active=True).values_list('name', flat=True).distinct()

    add_breadcrumb(
        title="Active Engagements",
        top_level=not len(request.GET),
        request=request)

    prods.object_list = prefetch_for_products_with_engagments(prods.object_list)

    return render(
        request, 'dojo/engagement.html', {
            'products': prods,
            'filtered': filtered,
            'name_words': sorted(set(name_words)),
            'eng_words': sorted(set(eng_words)),
        })


@user_passes_test(lambda u: u.is_staff)
def engagements_all(request):

    products_with_engagements = Product.objects.filter(~Q(engagement=None)).distinct()
    filtered = EngagementFilter(
        request.GET,
        queryset=products_with_engagements.prefetch_related('engagement_set', 'prod_type', 'engagement_set__lead',
                                                            'engagement_set__test_set__lead', 'engagement_set__test_set__test_type'))

    prods = get_page_items(request, filtered.qs, 25)

    name_words = products_with_engagements.values_list('name', flat=True)
    eng_words = Engagement.objects.all().values_list('name', flat=True).distinct()

    add_breadcrumb(
        title="All Engagements",
        top_level=not len(request.GET),
        request=request)

    prods.object_list = prefetch_for_products_with_engagments(prods.object_list)

    return render(
        request, 'dojo/engagements_all.html', {
            'products': prods,
            'filtered': filtered,
            'name_words': sorted(set(name_words)),
            'eng_words': sorted(set(eng_words)),
        })


def prefetch_for_products_with_engagments(products_with_engagements):
    if isinstance(products_with_engagements, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        return products_with_engagements.prefetch_related('tagged_items__tag',
            'engagement_set__tagged_items__tag',
            'engagement_set__test_set__tagged_items__tag',
            'engagement_set__jira_project__jira_instance',
            'jira_project_set__jira_instance')

    logger.debug('unable to prefetch because query was already executed')
    return products_with_engagements


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'change', 'eid')
def edit_engagement(request, eid):
    engagement = Engagement.objects.get(pk=eid)
    is_ci_cd = engagement.engagement_type == "CI/CD"
    jira_epic_form = None
    jira_project = None
    jira_error = False

    if request.method == 'POST':
        form = EngForm(request.POST, instance=engagement, cicd=is_ci_cd, product=engagement.product.id, user=request.user)
        jira_project = jira_helper.get_jira_project(engagement, use_inheritance=False)

        if form.is_valid():
            # first save engagement details
            new_status = form.cleaned_data.get('status')
            engagement = form.save(commit=False)
            if (new_status == "Cancelled" or new_status == "Completed"):
                engagement.active = False
            else:
                engagement.active = True
            engagement.save()

            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
            engagement.tags = t

            messages.add_message(
                request,
                messages.SUCCESS,
                'Engagement updated successfully.',
                extra_tags='alert-success')

            success, jira_project_form = jira_helper.process_jira_project_form(request, instance=jira_project, engagement=engagement)
            error = not success

            success, jira_epic_form = jira_helper.process_jira_epic_form(request, engagement=engagement)
            error = error or not success

            if not error:
                if '_Add Tests' in request.POST:
                    return HttpResponseRedirect(
                        reverse('add_tests', args=(engagement.id, )))
                else:
                    return HttpResponseRedirect(
                        reverse('view_engagement', args=(engagement.id, )))
        else:
            logger.debug(form.errors)

    form = EngForm(initial={'product': engagement.product}, instance=engagement, cicd=is_ci_cd, product=engagement.product, user=request.user)

    jira_project_form = None
    jira_epic_form = None
    if get_system_setting('enable_jira'):
        jira_project = jira_helper.get_jira_project(engagement, use_inheritance=False)
        jira_project_form = JIRAProjectForm(instance=jira_project, target='engagement', product=engagement.product)
        logger.debug('showing jira-epic-form')
        jira_epic_form = JIRAEngagementForm(instance=engagement)

    form.initial['tags'] = [tag.name for tag in engagement.tags]

    title = ' CI/CD' if is_ci_cd else ''
    product_tab = Product_Tab(engagement.product.id, title="Edit" + title + " Engagement", tab="engagements")
    product_tab.setEngagement(engagement)
    return render(request, 'dojo/new_eng.html', {
        'product_tab': product_tab,
        'form': form,
        'edit': True,
        'jira_epic_form': jira_epic_form,
        'jira_project_form': jira_project_form,
        'engagement': engagement,
    })


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'delete', 'eid')
def delete_engagement(request, eid):
    engagement = get_object_or_404(Engagement, pk=eid)
    product = engagement.product
    form = DeleteEngagementForm(instance=engagement)

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
                create_notification(event='other',
                                    title='Deletion of %s' % engagement.name,
                                    description='The engagement "%s" was deleted by %s' % (engagement.name, request.user),
                                    url=request.build_absolute_uri(reverse('view_engagements', args=(product.id, ))),
                                    recipients=[engagement.lead],
                                    icon="exclamation-triangle")

                if engagement.engagement_type == 'CI/CD':
                    return HttpResponseRedirect(reverse("view_engagements_cicd", args=(product.id, )))
                else:
                    return HttpResponseRedirect(reverse("view_engagements", args=(product.id, )))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([engagement])
    rels = collector.nested()

    product_tab = Product_Tab(product.id, title="Delete Engagement", tab="engagements")
    product_tab.setEngagement(engagement)
    return render(request, 'dojo/delete_engagement.html', {
        'product_tab': product_tab,
        'engagement': engagement,
        'form': form,
        'rels': rels,
    })


@user_must_be_authorized(Engagement, 'view', 'eid')
def view_engagement(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    tests = (
        Test.objects.filter(engagement=eng)
        .prefetch_related('tagged_items__tag', 'test_type')
        .annotate(count_findings_test_all=Count('finding__id'))
        .annotate(count_findings_test_active_verified=Count('finding__id', filter=Q(finding__active=True)))
        .annotate(count_findings_test_mitigated=Count('finding__id', filter=Q(finding__is_Mitigated=True)))
        .annotate(count_findings_test_dups=Count('finding__id', filter=Q(finding__duplicate=True)))
        .order_by('test_type__name', '-updated')
    )

    prod = eng.product
    risks_accepted = eng.risk_acceptance.all().select_related('owner')
    preset_test_type = None
    network = None
    if eng.preset:
        preset_test_type = eng.preset.test_type.all()
        network = eng.preset.network_locations.all()
    system_settings = System_Settings.objects.get()

    jissue = jira_helper.get_jira_issue(eng)
    jira_project = jira_helper.get_jira_project(eng)

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
    notes = eng.notes.all()
    note_type_activation = Note_Type.objects.filter(is_active=True).count()
    if note_type_activation:
        available_note_types = find_available_notetypes(notes)
    if request.method == 'POST' and request.user.is_staff:
        eng.progress = 'check_list'
        eng.save()

        if note_type_activation:
            form = TypedNoteForm(request.POST, available_note_types=available_note_types)
        else:
            form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            eng.notes.add(new_note)
            if note_type_activation:
                form = TypedNoteForm(available_note_types=available_note_types)
            else:
                form = NoteForm()
            url = request.build_absolute_uri(reverse("view_engagement", args=(eng.id,)))
            title = "Engagement: %s on %s" % (eng.name, eng.product.name)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')
    else:
        if note_type_activation:
            form = TypedNoteForm(available_note_types=available_note_types)
        else:
            form = NoteForm()

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

    title = ""
    if eng.engagement_type == "CI/CD":
        title = " CI/CD"
    product_tab = Product_Tab(prod.id, title="View" + title + " Engagement", tab="engagements")
    product_tab.setEngagement(eng)
    return render(
        request, 'dojo/view_eng.html', {
            'eng': eng,
            'product_tab': product_tab,
            'system_settings': system_settings,
            'tests': tests,
            'findings': fpage,
            'enabled': enabled,
            'check': check,
            'threat': eng.tmodel_path,
            'risk': eng.risk_path,
            'form': form,
            'notes': notes,
            'risks_accepted': risks_accepted,
            'can_add_risk': eng_findings.count(),
            'jissue': jissue,
            'jira_project': jira_project,
            'accepted_findings': accepted_findings,
            'start_date': start_date,
            'creds': creds,
            'cred_eng': cred_eng,
            'network': network,
            'preset_test_type': preset_test_type
        })


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
def add_tests(request, eid):
    eng = Engagement.objects.get(id=eid)
    cred_form = CredMappingForm()
    cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
        engagement=eng).order_by('cred_id')

    if request.method == 'POST':
        form = TestForm(request.POST, engagement=eng)
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

            # Set status to in progress if a test is added
            if eng.status != "In Progress" and eng.active is True:
                eng.status = "In Progress"
                eng.save()

            new_test.save()
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
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
                url=reverse('view_engagement', args=(eng.id, )))

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
        form = TestForm(engagement=eng)
        form.initial['target_start'] = eng.target_start
        form.initial['target_end'] = eng.target_end
        form.initial['lead'] = request.user
    add_breadcrumb(
        parent=eng, title="Add Tests", top_level=False, request=request)
    product_tab = Product_Tab(eng.product.id, title="Add Tests", tab="engagements")
    product_tab.setEngagement(eng)
    return render(request, 'dojo/add_tests.html', {
        'product_tab': product_tab,
        'form': form,
        'cred_form': cred_form,
        'eid': eid,
        'eng': eng
    })


# @user_passes_test(lambda u: u.is_staff)
# @user_must_be_authorized(Product, 'staff', 'eid')
# Cant use the easy decorator because of the potential for either eid/pid being used
def import_scan_results(request, eid=None, pid=None):
    engagement = None
    form = ImportScanForm()
    cred_form = CredMappingForm()
    finding_count = 0
    jform = None
    user = request.user

    if eid:
        engagement = get_object_or_404(Engagement, id=eid)
        engagement_or_product = engagement
        cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(engagement=engagement).order_by('cred_id')
    elif pid:
        product = get_object_or_404(Product, id=pid)
        engagement_or_product = product
    elif not user.is_staff:
        raise PermissionDenied

    if not user_is_authorized(user, 'staff', engagement_or_product):
        raise PermissionDenied

    push_all_jira_issues = jira_helper.is_push_all_issues(engagement_or_product)

    if request.method == "POST":
        form = ImportScanForm(request.POST, request.FILES)
        cred_form = CredMappingForm(request.POST)
        cred_form.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            engagement=engagement).order_by('cred_id')

        if jira_helper.get_jira_project(engagement_or_product):
            jform = JIRAImportScanForm(request.POST, push_all=push_all_jira_issues, prefix='jiraform')
            logger.debug('jform valid: %s', jform.is_valid())
            logger.debug('jform errors: %s', jform.errors)

        if form.is_valid() and (jform is None or jform.is_valid()):
            # Allows for a test to be imported with an engagement created on the fly
            if engagement is None:
                engagement = Engagement()
                # product = get_object_or_404(Product, id=pid)
                engagement.name = "AdHoc Import - " + strftime("%a, %d %b %Y %X", timezone.now().timetuple())
                engagement.threat_model = False
                engagement.api_test = False
                engagement.pen_test = False
                engagement.check_list = False
                engagement.target_start = timezone.now().date()
                engagement.target_end = timezone.now().date()
                engagement.product = product
                engagement.active = True
                engagement.status = 'In Progress'
                engagement.save()
            file = request.FILES.get('file', None)
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            active = form.cleaned_data['active']
            verified = form.cleaned_data['verified']
            scan_type = request.POST['scan_type']
            if not any(scan_type in code
                       for code in ImportScanForm.SCAN_TYPE_CHOICES):
                raise Http404()
            if file and is_scan_file_too_large(file):
                messages.add_message(request,
                                     messages.ERROR,
                                     "Report file is too large. Maximum supported size is {} MB".format(settings.SCAN_FILE_MAX_SIZE),
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('import_scan_results', args=(engagement,)))

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
            t.lead = user
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
                parser = import_parser_factory(file, t, active, verified)
            except Exception as e:
                messages.add_message(request,
                                     messages.ERROR,
                                     "An error has occurred in the parser, please see error "
                                     "log for details.",
                                     extra_tags='alert-danger')
                parse_logger.exception(e)
                parse_logger.error("Error in parser: {}".format(str(e)))
                return HttpResponseRedirect(reverse('import_scan_results', args=(engagement.id,)))

            try:
                # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
                # push_to_jira = jira_helper.is_push_to_jira(new_finding, jform.cleaned_data.get('push_to_jira'))
                push_to_jira = push_all_jira_issues or (jform and jform.cleaned_data.get('push_to_jira'))

                for item in parser.items:
                    # print("item blowup")
                    # print(item)
                    sev = item.severity
                    if sev == 'Information' or sev == 'Informational':
                        sev = 'Info'

                    item.severity = sev

                    if Finding.SEVERITIES[sev] > Finding.SEVERITIES[min_sev]:
                        continue

                    item.test = t
                    item.reporter = user
                    item.last_reviewed = timezone.now()
                    item.last_reviewed_by = user
                    if not handles_active_verified_statuses(form.get_scan_type()):
                        item.active = active
                        item.verified = verified

                    item.save(dedupe_option=False, false_history=True)

                    if hasattr(item, 'unsaved_req_resp') and len(
                            item.unsaved_req_resp) > 0:
                        for req_resp in item.unsaved_req_resp:
                            if form.get_scan_type() == "Arachni Scan":
                                burp_rr = BurpRawRequestResponse(
                                    finding=item,
                                    burpRequestBase64=req_resp["req"],
                                    burpResponseBase64=req_resp["resp"],
                                )
                            else:
                                burp_rr = BurpRawRequestResponse(
                                    finding=item,
                                    burpRequestBase64=base64.b64encode(req_resp["req"].encode("utf-8")),
                                    burpResponseBase64=base64.b64encode(req_resp["resp"].encode("utf-8")),
                                )
                            burp_rr.clean()
                            burp_rr.save()

                    if item.unsaved_request is not None and item.unsaved_response is not None:
                        burp_rr = BurpRawRequestResponse(
                            finding=item,
                            burpRequestBase64=base64.b64encode(item.unsaved_request.encode()),
                            burpResponseBase64=base64.b64encode(item.unsaved_response.encode()),
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
                        eps, created = Endpoint_Status.objects.get_or_create(
                            finding=item,
                            endpoint=ep)
                        ep.endpoint_status.add(eps)

                        item.endpoints.add(ep)
                        item.endpoint_status.add(eps)
                    for endpoint in form.cleaned_data['endpoints']:
                        ep, created = Endpoint.objects.get_or_create(
                            protocol=endpoint.protocol,
                            host=endpoint.host,
                            path=endpoint.path,
                            query=endpoint.query,
                            fragment=endpoint.fragment,
                            product=t.engagement.product)
                        eps, created = Endpoint_Status.objects.get_or_create(
                            finding=item,
                            endpoint=ep)
                        ep.endpoint_status.add(eps)

                        item.endpoints.add(ep)
                        item.endpoint_status.add(eps)

                    item.save(false_history=True, push_to_jira=push_to_jira)

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
                    initiator=user,
                    event='scan_added',
                    title=str(finding_count) + " findings for " + engagement.product.name,
                    finding_count=finding_count,
                    test=t,
                    engagement=engagement,
                    url=reverse('view_test', args=(t.id, )))

                return HttpResponseRedirect(
                    reverse('view_test', args=(t.id, )))
            except SyntaxError:
                messages.add_message(
                    request,
                    messages.ERROR,
                    'There appears to be an error in the XML report, please check and try again.',
                    extra_tags='alert-danger')
    prod_id = None
    custom_breadcrumb = None
    title = "Import Scan Results"
    if engagement:
        prod_id = engagement.product.id
        product_tab = Product_Tab(prod_id, title=title, tab="engagements")
        product_tab.setEngagement(engagement)
    else:
        prod_id = pid
        custom_breadcrumb = {"", ""}
        product_tab = Product_Tab(prod_id, title=title, tab="findings")

    if jira_helper.get_jira_project(engagement_or_product):
        jform = JIRAImportScanForm(push_all=push_all_jira_issues, prefix='jiraform')

    form.fields['endpoints'].queryset = Endpoint.objects.filter(product__id=product_tab.product.id)
    return render(request, 'dojo/import_scan_results.html', {
        'form': form,
        'product_tab': product_tab,
        'engagement_or_product': engagement_or_product,
        'custom_breadcrumb': custom_breadcrumb,
        'title': title,
        'cred_form': cred_form,
        'jform': jform
    })


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
def close_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    close_engagement(eng)
    messages.add_message(
        request,
        messages.SUCCESS,
        'Engagement closed successfully.',
        extra_tags='alert-success')
    create_notification(event='other',
                        title='Closure of %s' % eng.name,
                        description='The engagement "%s" was closed' % (eng.name),
                        url=request.build_absolute_uri(reverse('view_engagements', args=(eng.product.id, ))),)
    if eng.engagement_type == 'CI/CD':
        return HttpResponseRedirect(reverse("view_engagements_cicd", args=(eng.product.id, )))
    else:
        return HttpResponseRedirect(reverse("view_engagements", args=(eng.product.id, )))


@user_passes_test(lambda u: u.is_staff)
def reopen_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    reopen_engagement(eng)
    messages.add_message(
        request,
        messages.SUCCESS,
        'Engagement reopened successfully.',
        extra_tags='alert-success')
    create_notification(event='other',
                        title='Reopening of %s' % eng.name,
                        description='The engagement "%s" was reopened' % (eng.name),
                        url=request.build_absolute_uri(reverse('view_engagements', args=(eng.product.id, ))),)
    if eng.engagement_type == 'CI/CD':
        return HttpResponseRedirect(reverse("view_engagements_cicd", args=(eng.product.id, )))
    else:
        return HttpResponseRedirect(reverse("view_engagements", args=(eng.product.id, )))


"""
Greg:
status: in production
method to complete checklists from the engagement view
"""


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
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

    product_tab = Product_Tab(eng.product.id, title="Checklist", tab="engagements")
    product_tab.setEngagement(eng)
    return render(request, 'dojo/checklist.html', {
        'form': form,
        'product_tab': product_tab,
        'eid': eng.id,
        'findings': findings,
    })


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
def upload_risk(request, eid):
    eng = Engagement.objects.get(id=eid)

    unaccepted_findings = Finding.objects.filter(active="True", verified="True", duplicate="False", test__in=eng.test_set.all()) \
        .exclude(risk_acceptance__isnull=False).order_by('title')

    if request.method == 'POST':
        form = UploadRiskForm(request.POST, request.FILES)
        if form.is_valid():
            findings = form.cleaned_data['accepted_findings']
            for finding in findings:
                finding.active = False
                finding.save()
            risk = form.save(commit=False)
            risk.owner = form.cleaned_data['owner']
            risk.expiration_date = form.cleaned_data['expiration_date']
            risk.accepted_by = form.cleaned_data['accepted_by']
            risk.compensating_control = form.cleaned_data['compensating_control']
            risk.path = form.cleaned_data['path']
            risk.save()  # have to save before findings can be added
            risk.accepted_findings.set(findings)
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
                'Risk exception saved.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_engagement', args=(eid, )))
    else:
        form = UploadRiskForm(initial={'owner': request.user, 'name': 'Ad Hoc ' + timezone.now().strftime('%b %d, %Y, %H:%M:%S')})

    form.fields["accepted_findings"].queryset = unaccepted_findings
    product_tab = Product_Tab(eng.product.id, title="Upload Risk Exception", tab="engagements")
    product_tab.setEngagement(eng)

    return render(request, 'dojo/up_risk.html', {
                  'eng': eng,
                  'product_tab': product_tab,
                  'form': form
                  })


def view_risk(request, eid, raid):
    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    eng = get_object_or_404(Engagement, pk=eid)
    if request.user.is_staff or check_auth_users_list(request.user, eng):
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

    accepted_findings = risk_approval.accepted_findings.order_by('numerical_severity')
    fpage = get_page_items(request, accepted_findings, 15)

    unaccepted_findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=accepted_findings).order_by("title")
    add_fpage = get_page_items(request, unaccepted_findings, 10, 'apage')
    # on this page we need to add unaccepted findings as possible findings to add as accepted
    add_findings_form.fields[
        "accepted_findings"].queryset = add_fpage.object_list

    authorized = (request.user == risk_approval.owner.username or request.user.is_staff)

    product_tab = Product_Tab(eng.product.id, title="Risk Exception", tab="engagements")
    product_tab.setEngagement(eng)
    return render(
        request, 'dojo/view_risk.html', {
            'risk_approval': risk_approval,
            'product_tab': product_tab,
            'accepted_findings': fpage,
            'notes': risk_approval.notes.all(),
            'a_file': a_file,
            'eng': eng,
            'note_form': note_form,
            'replace_form': replace_form,
            'add_findings_form': add_findings_form,
            # 'show_add_findings_form': len(unaccepted_findings),
            'request': request,
            'add_findings': add_fpage,
            'authorized': authorized,
        })


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'delete', 'eid')
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
    if request.user.is_staff or check_auth_users_list(request.user, en):
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


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
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
    product_tab = Product_Tab(eng.product.id, title="Upload Threat Model", tab="engagements")
    return render(request, 'dojo/up_threat.html', {
        'form': form,
        'product_tab': product_tab,
        'eng': eng,
    })


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
def view_threatmodel(request, eid):
    eng = get_object_or_404(Engagement, pk=eid)
    response = FileResponse(open(eng.tmodel_path, 'rb'))
    return response


# @user_passes_test(lambda u: u.is_staff)
@user_must_be_authorized(Engagement, 'staff', 'eid')
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
