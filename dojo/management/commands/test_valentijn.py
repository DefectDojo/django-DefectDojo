from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding
from django.db.models.functions import ExtractMonth, ExtractYear, TruncDate
import logging
from calendar import monthrange
from datetime import date, datetime, timedelta
from math import ceil

from dateutil.relativedelta import relativedelta
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone

from dojo.models import Finding, Engagement, Risk_Acceptance
from django.db.models import Count, Max
from dojo.utils import add_breadcrumb, get_punchcard_data

from defectDojo_engagement_survey.models import Answered_Survey
from dateutil.relativedelta import relativedelta, MO, SU
from dojo.utils import get_system_setting, calculate_grade
from django.utils.timezone import localdate
from math import pi, sqrt
import numpy
import time
import calendar as tcalendar
import logging
from collections import OrderedDict
from datetime import datetime, date, timedelta
from math import ceil
from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.db.models import Sum, Count, Q
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from dojo.templatetags.display_tags import get_level
from dojo.filters import ProductFilter, ProductFindingFilter, EngagementFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm, DojoMetaDataForm, JIRAPKeyForm, JIRAFindingForm, AdHocFindingForm, \
                       EngagementPresetsForm, DeleteEngagementPresetsForm, Sonarqube_ProductForm
from dojo.models import Product_Type, Note_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance, Test, JIRA_PKey, Finding_Template, \
    Tool_Product_Settings, Cred_Mapping, Test_Type, Languages, App_Analysis, Benchmark_Type, Benchmark_Product_Summary, \
    Endpoint, Engagement_Presets, DojoMeta, Sonarqube_Product
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting, create_notification, Product_Tab, get_punchcard_data
from custom_field.models import CustomFieldValue, CustomField
from dojo.tasks import add_epic_task, add_issue_task
from tagging.models import Tag, TaggedItem
from tagging.managers import ModelTaggedItemManager
from tagging.utils import get_tag_list
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Prefetch

logger = logging.getLogger(__name__)
"""
Author: Aaron Weaver
This script will update the hashcode and dedupe findings in DefectDojo:
"""


class Command(BaseCommand):

    def handle(self, *args, **options):
       
        # initial_queryset = Product.objects.all().select_related('technical_contact') \
        # .select_related('product_manager').select_related('prod_type').select_related('team_manager')

        prods = Product.objects.all()


        # name_words = [product.name for product in
        #                 Product.objects.all().select_related('technical_contact').select_related('product_manager').select_related('prod_type').select_related('team_manager') ]

        #prods = ProductFilter(request.GET, queryset=initial_queryset, user=request.user)
        # prods = initial_queryset

        # prods = prods.prefetch_related(Prefetch('engagement_product', queryset=Engagement.objects.all().filter(active=True), to_attr='engagements'))
        prods = prods.prefetch_related(Prefetch('engagement_product', queryset=Engagement.objects.all(), to_attr='engagements'))
        # prods = prods.prefetch_related(Prefetch('engagement_product', queryset=Engagement.objects.all().annotate(), to_attr='engagement_count'))

        prods = prods.annotate(engagement_count = Count('engagement_product__id'))
        # prods = prods.annotate(engagement_count = Sum('engagement_product__active'))

        prods = prods.annotate(active_engagement_count2 = Count('engagement_product__id', filter=Q(engagement_product__active=True)))
        prods = prods.annotate(inactive_engagement_count2 = Count('engagement_product__id', filter=Q(engagement_product__active=False)))
        prods = prods.annotate(last_date = Max('engagement_product__target_start'))        
# from django.db.models import Q
# ...

# clients = Client.objects.filter(...).annotate(
#     completed_request_count=Count('request', filter=Q(request__completed=True))
# )


        for prod in prods.all():
            # prod = prods[0]
            print(prod.name)
            print(prod.engagement_count)
            print(prod.active_engagement_count2)
            print(prod.inactive_engagement_count2)
            print(prod.last_date)
            
            for eng in prod.engagements:
                print(str(eng.id) + ': ' + eng.name + "  : " + str(eng.target_start))
            break

        # for prod in prods.all():
            # print(prod.engagements)

        # prod_list = Paginator(prods, 5)

        # prod_list = Tag

        # page = prod_list.get_page(1);
        
        # from tagging.generic import fetch_content_objects
        # tags = Tag.objects.usage_for_queryset(prods)
        # logger.debug(tags)
        # items = TaggedItem.objects.get_by_model(prods, tags)
        # logger.debug(items) 
        # items = ModelTaggedItemManager.with_any(prods, tags)
        # logger.debug(items)
        # fetch_content_objects(TaggedItem.objects().all)

        # for prod in page:
        #     logger.debug(prod.name)
        #     logger.debug(prod.product_engagement.all())
            # calculate_grade(prod)

            # logger.debug(prod.tags)

            # logger.debug(prod.platform)
            # logger.debug(prod.lifecycle)
            # logger.debug(prod.origin)
            # logger.debug(prod.external_audience)
            # logger.debug(prod.internet_accessible)

            # logger.debug(prod.last_engagement_date)

            # jira_conf = JIRA_PKey.objects.filter(product=prod)

            # logger.debug(prod.findings_count)
            # logger.debug(prod.endpoint_count)





