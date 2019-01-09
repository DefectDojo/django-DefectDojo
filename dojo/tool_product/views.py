# #  product
import logging
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.urlresolvers import reverse
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from dojo.forms import DeleteToolProductSettingsForm, ToolProductSettingsForm, NoteForm
from dojo.models import Product, Tool_Product_Settings, Tool_Configuration, Tool_Product_History
from dojo.management.commands.run_tool import run_on_demand_scan
from django.http import HttpResponseRedirect
from dojo.utils import add_breadcrumb, Product_Tab
from threading import Thread

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def new_tool_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == 'POST':
        tform = ToolProductSettingsForm(request.POST)
        if tform.is_valid():
            # form.tool_type = tool_type
            new_prod = tform.save(commit=False)
            new_prod.product = prod
            new_prod.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Product Tool Configuration Successfully Created.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('all_tool_product', args=(pid, )))
    else:
        tform = ToolProductSettingsForm()
    product_tab = Product_Tab(pid, title="Tool Configurations", tab="settings")
    return render(request, 'dojo/new_tool_product.html', {
        'tform': tform,
        'product_tab': product_tab,
        'pid': pid
    })


@user_passes_test(lambda u: u.is_staff)
def all_tool_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    tools = Tool_Product_Settings.objects.filter(product=prod).order_by('name')
    product_tab = Product_Tab(prod.id, title="Tool Configurations", tab="settings")
    return render(request, 'dojo/view_tool_product_all.html', {
        'prod': prod,
        'tools': tools,
        'product_tab': product_tab
    })

#markme
@user_passes_test(lambda u: u.is_superuser)
def run_tool_product(request, pid, ttid):
    scan_settings = get_object_or_404(Tool_Product_Settings, pk=ttid)
    user = request.user
    if user.is_superuser:
        pass
    else:
        raise PermissionDenied

    if scan_settings.url == "" and scan_settings.tool_configuration:
        scan_settings.url = scan_settings.tool_configuration.url
        
    scan_is_running = False
    if request.method == 'POST':
        if 'scan_now' in request.POST:
            t = Thread(target=run_on_demand_scan, args=(str(ttid),))
            t.start()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Tool successfully started.',
                                 extra_tags='alert-success')
            # need to redirect else reload will kick off new scans
            return HttpResponseRedirect(reverse('run_tool_product', args=(pid, ttid)))

    scan_history = Tool_Product_History.objects.get(product=ttid)
    for scan in scan_history.all():
        if scan.status in ["Running", "Pending"]:
            scan_is_running = True

    add_breadcrumb(
        title="Run Product Tool",
        top_level=False,
        request=request)

    return render(request, 'dojo/run_tool_product.html', {
        'tool_config': tool_config,
        'scan_settings': scan_settings,
        'scans': scan_history.order_by('id'),
        'scan_is_running': scan_is_running,
        'pid': pid,
        'ttid': ttid,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_tool_product(request, pid, ttid):
    prod = get_object_or_404(Product, id=pid)
    tool_product = Tool_Product_Settings.objects.get(pk=ttid)

    if request.method == 'POST':
        tform = ToolProductSettingsForm(request.POST, instance=tool_product)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Tool Product Configuration Successfully Updated.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('all_tool_product', args=(pid, )))
    else:
        tform = ToolProductSettingsForm(instance=tool_product)

    product_tab = Product_Tab(pid, title="Edit Product Tool Configuration", tab="settings")
    return render(request, 'dojo/edit_tool_product.html', {
        'tform': tform,
        'product_tab': product_tab
    })


@user_passes_test(lambda u: u.is_staff)
def delete_tool_product(request, pid, ttid):
    tool_product = Tool_Product_Settings.objects.get(pk=ttid)
    prod = get_object_or_404(Product, id=pid)
    if request.method == 'POST':
        tform = DeleteToolProductSettingsForm(
            request.POST, instance=tool_product)
        tool_product.delete()
        messages.add_message(
            request,
            messages.SUCCESS,
            'Tool Product Successfully Deleted.',
            extra_tags='alert-success')
        return HttpResponseRedirect(reverse('all_tool_product', args=(pid, )))
    else:
        tform = ToolProductSettingsForm(instance=tool_product)

    product_tab = Product_Tab(pid, title="Delete Product Tool Configuration", tab="settings")

    return render(request, 'dojo/delete_tool_product.html', {
        'tform': tform,
        'product_tab': product_tab
    })


@user_passes_test(lambda u: u.is_staff)
def tool_product(request):
    confs = Tool_Product_Settings.objects.all().order_by('name')
    add_breadcrumb(
        title="Tool Configuration List",
        top_level=not len(request.GET),
        request=request)
    return render(request, 'dojo/tool_product.html', {
        'confs': confs,
    })
