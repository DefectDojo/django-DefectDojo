# # test types
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from pytz import timezone

from dojo.filters import TestTypeFilter
from dojo.forms import Test_TypeForm
from dojo.models import Test_Type
from dojo.utils import get_page_items, add_breadcrumb

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)

"""
Jay
Status: in prod
Test Type views
"""


@user_passes_test(lambda u: u.is_staff)
def test_type(request):
    initial_queryset = Test_Type.objects.all().order_by('name')
    name_words = [tt.name for tt in
                  initial_queryset]
    test_types = TestTypeFilter(request.GET, queryset=initial_queryset)
    tts = get_page_items(request, test_types, 25)
    add_breadcrumb(title="Test Type List", top_level=True, request=request)
    return render(request, 'dojo/test_type.html', {
        'name': 'Test Type List',
        'metric': False,
        'user': request.user,
        'tts': tts,
        'test_types': test_types,
        'name_words': name_words})


@user_passes_test(lambda u: u.is_staff)
def add_test_type(request):
    form = Test_TypeForm()
    if request.method == 'POST':
        form = Test_TypeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test type added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('test_type'))
    add_breadcrumb(title="Add Test Type", top_level=False, request=request)
    return render(request, 'dojo/new_test_type.html', {
        'name': 'Add Test Type',
        'metric': False,
        'user': request.user,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_test_type(request, ptid):
    tt = get_object_or_404(Test_Type, pk=ptid)
    form = Test_TypeForm(instance=tt)
    if request.method == 'POST':
        form = Test_TypeForm(request.POST, instance=tt)
        if form.is_valid():
            tt = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test type updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('test_type'))

    add_breadcrumb(title="Edit Test Type", top_level=False, request=request)
    return render(request, 'dojo/edit_test_type.html', {
        'name': 'Edit Test Type',
        'metric': False,
        'user': request.user,
        'form': form,
        'pt': tt})
