# #  product
import logging

from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.conf import settings

from dojo.utils import add_breadcrumb
from dojo.forms import DedupeConfigForm
from dojo.models import Dedupe_Configuration, Test_Type
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

logger = logging.getLogger(__name__)


@user_is_configuration_authorized('dojo.add_dedupe_config')
def new_dedupe_config(request):
    if request.method == 'POST':
        tform = DedupeConfigForm(request.POST)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Deduplication Configuration Successfully Created.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('dedupe_config', ))
    else:
        tform = DedupeConfigForm()
        if 'name' in request.GET:
            tform.fields['name'].initial = request.GET.get('name')
        add_breadcrumb(title=_("New Deduplication Configuration"), top_level=False, request=request)

    return render(request, 'dojo/new_dedupe_config.html', {'tform': tform})


@user_is_configuration_authorized('dojo.change_dedupe_config')
def edit_dedupe_config(request, ttid):
    dedupe_config = Dedupe_Configuration.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = DedupeConfigForm(request.POST, instance=dedupe_config)
        if tform.is_valid():
            tform.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Deduplication config successfully updated.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('dedupe_config', ))
    else:
        tform = DedupeConfigForm(instance=dedupe_config)
        print(tform)

    add_breadcrumb(title=_("Edit Deduplication Configuration"), top_level=False, request=request)

    return render(request, 'dojo/edit_dedupe_config.html', {'tform': tform})


@user_is_configuration_authorized('dojo.view_dedupe_configuration')
def dedupe_config(request):
    all_test_types =  Test_Type.objects.all()
    existing_confs = Dedupe_Configuration.objects.all().order_by('scanner')
    existing_confs_scanner_names = list(map(lambda c: str(c.scanner), existing_confs))
    for test_type in all_test_types:
        if test_type.name not in existing_confs_scanner_names:
            if hasattr(settings, 'DEDUPLICATION_ALGORITHM_PER_PARSER'):
                if (test_type.name in settings.DEDUPLICATION_ALGORITHM_PER_PARSER):
                    dedupe_alg = settings.DEDUPLICATION_ALGORITHM_PER_PARSER[test_type.name]
                    if dedupe_alg == 'hash_code':
                        if (test_type.name in settings.HASHCODE_FIELDS_PER_SCANNER):
                            preset_hash_code_config = settings.HASHCODE_FIELDS_PER_SCANNER[test_type.name]
                            test = Dedupe_Configuration(scanner=test_type, hashcode_fields=preset_hash_code_config)
                            test.save()
    
    refreshed_confs = Dedupe_Configuration.objects.all().order_by('scanner')
    for c in refreshed_confs:
        print(c.hashcode_fields)
    add_breadcrumb(title=_("Deduplication Config List"), top_level=not len(request.GET), request=request)

    return render(request, 'dojo/dedupe_config.html', {'confs': refreshed_confs})
