import logging

from auditlog.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.decorators import user_passes_test
from django.contrib import messages
from django.http import Http404
from django.shortcuts import render, get_object_or_404
from dojo.models import Engagement, Test, Finding, Endpoint, Product, FileUpload
from dojo.filters import LogEntryFilter
from dojo.forms import ManageFileFormSet
from dojo.utils import get_page_items, Product_Tab, get_system_setting



logger = logging.getLogger(__name__)


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except KeyError:
        raise Http404()

    product_id = None
    active_tab = None
    finding = None
    test = False
    object_value = None

    if str(ct) == "product":
        product_id = obj.id
        active_tab = "overview"
        object_value = Product.objects.get(id=obj.id)
    elif str(ct) == "engagement":
        object_value = Engagement.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "engagements"
    elif str(ct) == "test":
        object_value = Test.objects.get(id=obj.id)
        product_id = object_value.engagement.product.id
        active_tab = "engagements"
        test = True
    elif str(ct) == "finding":
        object_value = Finding.objects.get(id=obj.id)
        product_id = object_value.test.engagement.product.id
        active_tab = "findings"
        finding = object_value
    elif str(ct) == "endpoint":
        object_value = Endpoint.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "endpoints"

    product_tab = None
    if product_id:
        product_tab = Product_Tab(product_id, title="History", tab=active_tab)
        if active_tab == "engagements":
            if str(ct) == "engagement":
                product_tab.setEngagement(object_value)
            else:
                product_tab.setEngagement(object_value.engagement)

    history = LogEntry.objects.filter(content_type=ct,
                                      object_pk=obj.id).order_by('-timestamp')
    history = LogEntryFilter(request.GET, queryset=history)
    paged_history = get_page_items(request, history.qs, 25)

    if not get_system_setting('enable_auditlog'):
        messages.add_message(
            request,
            messages.WARNING,
            'Audit logging is currently disabled in System Settings.',
            extra_tags='alert-danger')

    return render(request, 'dojo/action_history.html',
                  {"history": paged_history,
                   'product_tab': product_tab,
                   "filtered": history,
                   "obj": obj,
                   "test": test,
                   "object_value": object_value,
                   "finding": finding
                   })


@user_passes_test(lambda u: u.is_staff)
def manage_files(request, oid, obj_type):
    if obj_type == 'Engagement':
        obj = get_object_or_404(Engagement, pk=oid)
        obj_vars = ('view_engagement', 'engagement__isnull', 'engagement_set')
    elif obj_type == 'Test':
        obj = get_object_or_404(Test, pk=oid)
        obj_vars = ('view_test', 'test__isnull', 'test_set')
    elif obj_type == 'Finding':
        obj = get_object_or_404(Finding, pk=oid)
        obj_vars = ('view_finding', 'finding__isnull', 'finding_set')
    else:
        raise Http404()

    files_formset = ManageFileFormSet(queryset=obj.files.all())
    error = False

    if request.method == 'POST':
        files_formset = ManageFileFormSet(
            request.POST, request.FILES, queryset=obj.files.all())
        if files_formset.is_valid():
            # remove all from database and disk

            files_formset.save()

            for o in files_formset.deleted_objects:
                os.remove(os.path.join(settings.MEDIA_ROOT, o.file.name))

            for o in files_formset.new_objects:
                obj.files.add(o)

            keyword = obj_vars[1]
            orphan_files = FileUpload.objects.filter(keyword=True)
            for o in orphan_files:
                os.remove(os.path.join(settings.MEDIA_ROOT, o.file.name))
                o.delete()

            files = os.listdir(os.path.join(settings.MEDIA_ROOT, 'uploaded_files'))

            for file in files:
                with_media_root = os.path.join(settings.MEDIA_ROOT, 'uploaded_files', file)
                with_part_root_only = os.path.join('uploaded_files', file)
                if os.path.isfile(with_media_root):
                    file = FileUpload.objects.filter(
                        file=with_part_root_only)

                    if len(file) == 0:
                        os.remove(with_media_root)
                        cache_to_remove = os.path.join(settings.MEDIA_ROOT, 'CACHE', os.path.splitext(file)[0])
                        if os.path.isdir(cache_to_remove):
                            shutil.rmtree(cache_to_remove)
                    else:
                        for f in file:
                            if getattr(f, obj_vars[2]) is None:
                                f.delete()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Files updated successfully.',
                extra_tags='alert-success')
        else:
            error = True
            messages.add_message(
                request,
                messages.ERROR,
                'Please check form data and try again.',
                extra_tags='alert-danger')

        if not error:
            return HttpResponseRedirect(reverse(obj_vars[0], args=(eid, )))
    return render(
        request, 'dojo/manage_files.html', {
            'files_formset': files_formset,
            'obj': obj,
            'obj_type': obj_type,
        })
