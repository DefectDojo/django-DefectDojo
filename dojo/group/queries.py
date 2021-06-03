from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q
from dojo.models import Dojo_Group, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission

def get_authorized_products_for_group(group):
    products = Product_Group.objects \
        .filter(group=group)
    return products

def get_authorized_product_types_for_group(group):
    product_types = Product_Type_Group.objects \
        .filter(group=group)