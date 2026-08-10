import logging

from django import forms

from dojo.labels import get_labels
from dojo.models import Dojo_User
from dojo.product_type.models import Product_Type

logger = logging.getLogger(__name__)

labels = get_labels()


class Product_TypeForm(forms.ModelForm):
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["critical_product"].label = labels.ORG_CRITICAL_PRODUCT_LABEL
        self.fields["key_product"].label = labels.ORG_KEY_PRODUCT_LABEL

    class Meta:
        model = Product_Type
        fields = ["name", "description", "critical_product", "key_product"]


class Delete_Product_TypeForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Product_Type
        fields = ["id"]


class Add_Product_Type_AuthorizedUsersForm(forms.Form):
    users = forms.ModelMultipleChoiceField(
        queryset=Dojo_User.objects.none(), required=True, label="Users",
    )

    def __init__(self, *args, product_type=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.product_type = product_type
        current = product_type.authorized_users.values_list("pk", flat=True)
        self.fields["users"].queryset = (
            Dojo_User.objects.filter(is_active=True)
            .exclude(is_superuser=True)
            .exclude(pk__in=current)
            .order_by("first_name", "last_name")
        )
