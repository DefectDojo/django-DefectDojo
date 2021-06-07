from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q
from django.shortcuts import render, get_object_or_404
from dojo.models import Dojo_Group, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group, Dojo_User
from dojo.authorization.authorization import get_roles_for_permission

def get_authorized_products_for_group(group):
    products = Product_Group.objects \
        .filter(group=group)
    return products

def get_authorized_product_types_for_group(group):
    product_types = Product_Type_Group.objects \
        .filter(group=group)

def get_members_for_group(group):
    users = []
    for user in group.users:
        users.append(get_object_or_404(Dojo_User, id=user.id))