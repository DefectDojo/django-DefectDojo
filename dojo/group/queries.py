from dojo.models import Product_Group, Product_Type_Group

def get_authorized_products_for_group(group):
    products = Product_Group.objects \
        .filter(group=group)
    return products

def get_authorized_product_types_for_group(group):
    product_types = Product_Type_Group.objects \
        .filter(group=group)
    return product_types