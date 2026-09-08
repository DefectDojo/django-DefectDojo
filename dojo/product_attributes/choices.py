"""
Lazy choice callables for the Product platform/lifecycle/origin filters.

Passed as ``choices=`` to django-filter ``MultipleChoiceFilter``s so the option lists are
read from the database at request time (never at import time, which would break app
startup) and the filters keep accepting the stable ``value`` strings that clients have
always used (e.g. ``?platform=web``).
"""
from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform


def _value_choices(model):
    return [(option.value, option.name)
            for option in model.objects.all().order_by("display_order", "name")]


def platform_value_choices():
    return _value_choices(Product_Platform)


def lifecycle_value_choices():
    return _value_choices(Product_Lifecycle)


def origin_value_choices():
    return _value_choices(Product_Origin)
