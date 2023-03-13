# #  product
import logging

from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from dojo.models import Product_API_Scan_Configuration
from dojo.utils import dojo_crypto_encrypt, prepare_for_view
from dojo.utils import add_breadcrumb
from dojo.forms import ToolConfigForm
from dojo.tool_config.factory import create_API
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

logger = logging.getLogger(__name__)


@user_is_configuration_authorized('dojo.view_tool_configuration')
def api_scan_configurations(request):
    confs = Product_API_Scan_Configuration.objects.all().order_by('product')
    for c in confs:
        print(c.product)
    add_breadcrumb(title="API Scan Configurations List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/view_all_product_api_scan_configurations.html',
                  {'confs': confs})
