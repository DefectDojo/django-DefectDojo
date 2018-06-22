# Standard library imports
import json
import logging
import sys

# Third party imports
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.contrib.admin.utils import NestedObjects
from django.core.urlresolvers import reverse
from django.db import DEFAULT_DB_ALIAS
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from jira import JIRA
from django.http import JsonResponse
from django.forms.models import model_to_dict

# Local application/library imports
from dojo.forms import RuleForm, DeleteRuleForm, RuleFormSet
from dojo.models import User, JIRA_Conf, JIRA_Issue, Notes, Rule,\
    System_Settings, Finding, Test, Test_Type, Engagement, \
    Product, Product_Type

from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)

#Fields for each model ruleset

finding_fields = [f.name for f in Finding._meta.fields]
test_fields = [f.name for f in Test._meta.fields]
test_type_fields = [f.name for f in Test_Type._meta.fields]
engagement_fields = [f.name for f in Engagement._meta.fields]
product_fields = [f.name for f in Product._meta.fields]
product_type_fields = [f.name for f in Product_Type._meta.fields]
field_dictionary = {}
field_dictionary['Finding'] = finding_fields
field_dictionary['Test Type'] = test_type_fields
field_dictionary['Test'] = test_fields
field_dictionary['Engagement'] = engagement_fields
field_dictionary['Product'] = product_fields
field_dictionary['Product Type'] = product_type_fields

#Add Scan Type
def rules(request):
    initial_queryset = Rule.objects.all().order_by('name')
    add_breadcrumb(title="Rules", top_level=True, request=request)
    return render(request, 'dojo/rules.html', {
        'name': 'Rules List',
        'metric': False,
        'user': request.user,
        'rules': initial_queryset})


@user_passes_test(lambda u: u.is_staff)
def new_rule(request):
    if request.method == 'POST':
        form = RuleFormSet(request.POST)
        match_f = request.POST.get('match_field')
        apply_f = request.POST.get('applied_field')
        print >>sys.stderr, 'DEBUGGING'
        print >>sys.stderr, form.is_valid()
        print >>sys.stderr, form.errors
        if form.is_valid():
            form.save()
            messages.add_message(request,
                     messages.SUCCESS,
                     'Rule created successfully.',
                     extra_tags='alert-success')
            return HttpResponseRedirect(reverse('rules'))
    form = RuleFormSet()
    add_breadcrumb(title="New Dojo Rule", top_level=False, request=request)
    return render(request, 'dojo/new_rule.html',
                  {'form': form,
                   'finding_fields': finding_fields,
                   'test_fields': test_fields,
                   'engagement_fields': engagement_fields,
                   'product_fields': product_fields,
                   'product_type_fields': product_type_fields,
                   'field_dictionary': json.dumps(field_dictionary)})

@user_passes_test(lambda u: u.is_staff)
def edit_rule(request, ptid):
    pt = get_object_or_404(Rule, pk=ptid)
    form = RuleForm(instance=pt)
    if request.method == 'POST':
        form = Rule(request.POST, instance=pt)
        if form.is_valid():
            pt = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Rule updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('Rules'))
    add_breadcrumb(title="Edit Rule", top_level=False, request=request)
    return render(request, 'dojo/edit_rule.html', {
        'name': 'Edit Rule',
        'metric': False,
        'user': request.user,
        'form': form,
        'pt': pt})

@user_passes_test(lambda u: u.is_staff)
def delete_rule(request, pid):
    product = get_object_or_404(Rule, pk=pid)
    form = DeleteRuleForm(instance=product)

    from django.contrib.admin.utils import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([product])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(product.id) == request.POST['id']:
            form = DeleteRuleForm(request.POST, instance=product)
            if form.is_valid():
                product.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Rule deleted.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('Rules'))

    add_breadcrumb(parent=product, title="Delete", top_level=False, request=request)
    system_settings = System_Settings.objects.get()
    return render(request, 'dojo/delete_product.html',
                  {'product': product,
                   'form': form,
                   'active_tab': 'findings',
                   'system_settings': system_settings,
                   'rels': rels,
                   })
