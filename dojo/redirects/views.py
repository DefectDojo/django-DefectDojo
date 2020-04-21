from dojo.models import Product, Engagement
from dojo.utils import redirect
from django.shortcuts import get_object_or_404
import logging

logger = logging.getLogger(__name__)


def view_product_by_name(request, pname):
    return redirect(get_prod_by_name(pname))


def view_product_by_meta(request, pmeta_name, pmeta_value):
    return redirect(get_prod_by_meta(pmeta_name, pmeta_value))


def view_cicd_engagements_by_product_by_name(request, pname):
    return redirect(get_prod_by_name(pname), '/engagements/cicd')


def view_cicd_engagements_by_product_by_meta(request, pmeta_name, pmeta_value):
    return redirect(get_prod_by_meta(pmeta_name, pmeta_value), '/engagements/cicd')


def view_engagement_by_name_by_product_name(request, pmeta_name, pmeta_value, ename):
    prod = get_prod_by_meta(pmeta_name, pmeta_value)
    eng = get_eng_by_product_and_name(prod.id, ename)
    return redirect(eng)


def view_engagement_by_branch_tag_by_product_name(request, pmeta_name, pmeta_value, btname):
    prod = get_prod_by_meta(pmeta_name, pmeta_value)
    eng = get_eng_by_product_and_branch_tag_name(prod.id, btname)
    return redirect(eng)


def get_prod_by_name(name):
    return get_object_or_404(Product.objects.all().only('id'), name=name)


def get_prod_by_meta(name, value):
    return get_object_or_404(Product.objects.filter(product_meta__name=name, product_meta__value=value).only('id'))


def get_eng_by_product_and_name(pid, ename):
    return get_object_or_404(Engagement.objects.filter(product__id=pid, name=ename).only('id'))


def get_eng_by_product_and_branch_tag_name(pid, btname):
    return get_object_or_404(Engagement.objects.filter(product__id=pid, branch_tag=btname).only('id'))
