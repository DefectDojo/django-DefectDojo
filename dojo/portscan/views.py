# # scans and scan settings

import logging
from threading import Thread

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from dojo.forms import PortscanSettingsForm, DeleteIPScanForm
from dojo.management.commands.run_portscan import run_on_demand_scan
from dojo.models import Product, Scan, IPScan, PortscanSettings
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)

"""
Greg:
status: completed in use
"""


def view_portscan(request, sid):
    scan = get_object_or_404(Scan, id=sid)
    prod = get_object_or_404(Product, id=scan.scan_settings.product.id)
    scan_settings_id = scan.scan_settings.id
    if request.user.is_staff or request.user in prod.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    if request.method == "POST":
        form = DeleteIPScanForm(request.POST, instance=scan)
        if form.is_valid():
            scan.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Portscan results deleted successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_portscan_settings', args=(prod.id, scan_settings_id,)))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'There was a problem deleting portscan, please try again.',
                extra_tags='alert-danger')
    ipScans = []
    ipScan_objects = IPScan.objects.filter(scan=scan)
    for i in ipScan_objects:
        service_list = eval(i.services)
        row = [i.address]
        for (port, protocol, status, service) in service_list:
            row.append(port)
            row.append(protocol)
            row.append(status)
            row.append(service)
            ipScans.append(row)
            row = [""]

    form = DeleteIPScanForm(instance=scan)

    add_breadcrumb(parent=scan, top_level=False, request=request)

    return render(
        request,
        'dojo/view_portscan.html',
        {'scan': scan,
         'ipScans': ipScans,
         'form': form}
    )


"""
Greg:
status: completed in use
"""


def view_portscan_settings(request, pid, sid):
    scan_settings = get_object_or_404(PortscanSettings, id=sid)
    user = request.user
    if user.is_staff or user in scan_settings.product.authorized_users.all():
        pass
    else:
        raise PermissionDenied

    scan_is_running = False

    if request.method == 'POST':
        if 'baseline' in request.POST:
            baseline_scan = get_object_or_404(Scan,
                                              id=request.POST['baseline'])
            for scan in scan_settings.scan_set.all():
                if scan.id == baseline_scan.id:
                    scan.baseline = True
                else:
                    scan.baseline = False
                scan.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Base line successfully saved.',
                                 extra_tags='alert-success')
        elif 'scan_now' in request.POST:
            t = Thread(target=run_on_demand_scan, args=(str(sid),))
            t.start()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Portscan successfully started.',
                                 extra_tags='alert-success')
            # need to redirect else reload will kick off new scans
            return HttpResponseRedirect(reverse('view_portscan_settings', args=(scan_settings.product.id, sid,)))

    for scan in scan_settings.scan_set.all():
        if scan.status in ["Running", "Pending"]:
            scan_is_running = True

    add_breadcrumb(parent=scan_settings, top_level=False, request=request)

    return render(
        request,
        'dojo/view_portscan_settings.html',
        {'scan_settings': scan_settings,
         'scans': scan_settings.scan_set.order_by('id'),
         'scan_is_running': scan_is_running,
         })


"""
Greg:
status: in Prod
view scan settings for self-service scan
"""


def edit_portscan_settings(request, pid, sid):
    old_scan = PortscanSettings.objects.get(id=sid)
    pid = old_scan.product.id
    user = request.user
    if user.is_staff or user in old_scan.product.authorized_users.all():
        pass
    else:
        raise PermissionDenied

    if request.method == 'POST':
        if request.POST.get('edit'):
            form = PortscanSettingsForm(data=request.POST, instance=old_scan)
            if form.is_valid():
                form.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Portscan settings saved.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_portscan_settings', args=(old_scan.product.id, sid,)))
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Scan settings not saved.',
                                     extra_tags='alert-danger')
                add_breadcrumb(parent=old_scan, top_level=False, request=request)
                return render(request,
                              'dojo/edit_portscan_settings.html',
                              {'form': form,
                               'sid': sid,
                               'pid': pid})
        elif request.POST.get('delete'):
            pid = old_scan.product.id
            old_scan.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Portscan settings deleted.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    try:
        form = PortscanSettingsForm(instance=old_scan)
    except:
        form = PortscanSettingsForm()
    add_breadcrumb(parent=old_scan, top_level=False, request=request)
    return render(request,
                  'dojo/edit_portscan_settings.html',
                  {'form': form,
                   'sid': sid,
                   'pid': pid})


"""
Greg
status: in prod, completed by interns not enabled by default
Self-service port scanning tool found at the product level
"""


def gmap(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.user.is_staff or request.user in prod.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    form = PortscanSettingsForm()
    if request.method == 'POST':
        form = PortscanSettingsForm(data=request.POST)
        if form.is_valid():
            new_scan = form.save(commit=False)
            new_scan.product = prod
            new_scan.user = request.user
            new_scan.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Portscan settings saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Portscan settings not saved.',
                                 extra_tags='alert-danger')

    add_breadcrumb(title="Portscan", top_level=False, request=request)

    return render(request,
                  'dojo/gmap.html',
                  {'form': form,
                   'pid': pid})