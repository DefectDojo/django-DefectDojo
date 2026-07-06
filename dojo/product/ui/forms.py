from django import forms
from django.utils import timezone
from django.utils.dates import MONTHS

from dojo.labels import get_labels
from dojo.models import (
    Dojo_User,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    SLA_Configuration,
    Tool_Configuration,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.validators import tag_validator

labels = get_labels()


class ProductForm(forms.ModelForm):
    name = forms.CharField(max_length=255, required=True)
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=True)

    prod_type = forms.ModelChoiceField(label=labels.ORG_LABEL,
                                       queryset=Product_Type.objects.none(),
                                       required=True)

    sla_configuration = forms.ModelChoiceField(label="SLA Configuration",
                                        queryset=SLA_Configuration.objects.all(),
                                        required=True,
                                        initial="Default")

    product_manager = forms.ModelChoiceField(label=labels.ASSET_MANAGER_LABEL,
                                             queryset=Dojo_User.objects.exclude(is_active=False).order_by("first_name", "last_name"), required=False)
    technical_contact = forms.ModelChoiceField(queryset=Dojo_User.objects.exclude(is_active=False).order_by("first_name", "last_name"), required=False)
    team_manager = forms.ModelChoiceField(queryset=Dojo_User.objects.exclude(is_active=False).order_by("first_name", "last_name"), required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["prod_type"].queryset = get_authorized_product_types("add")
        self.fields["enable_product_tag_inheritance"].label = labels.ASSET_TAG_INHERITANCE_ENABLE_LABEL
        self.fields["enable_product_tag_inheritance"].help_text = labels.ASSET_TAG_INHERITANCE_ENABLE_HELP
        if prod_type_id := kwargs.get("instance", Product()).prod_type_id:  # we are editing existing instance
            self.fields["prod_type"].queryset |= Product_Type.objects.filter(pk=prod_type_id)  # even if user does not have permission for any other ProdType we need to add at least assign ProdType to make form submittable (otherwise empty list was here which generated invalid form)

        # if this product has findings being asynchronously updated, disable the sla config field
        if self.instance.async_updating:
            self.fields["sla_configuration"].disabled = True
            self.fields["sla_configuration"].widget.attrs["message"] = (
                "Finding SLA expiration dates are currently being recalculated. "
                "This field cannot be changed until the calculation is complete."
            )

    class Meta:
        model = Product
        fields = ["name", "description", "tags", "product_manager", "technical_contact", "team_manager", "prod_type", "sla_configuration", "regulations",
                "business_criticality", "platform", "lifecycle", "origin", "user_records", "revenue", "external_audience", "enable_product_tag_inheritance",
                "internet_accessible", "enable_simple_risk_acceptance", "enable_full_risk_acceptance", "disable_sla_breach_notifications"]

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")


class DeleteProductForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Product
        fields = ["id"]


class Add_Product_AuthorizedUsersForm(forms.Form):
    users = forms.ModelMultipleChoiceField(
        queryset=Dojo_User.objects.none(), required=True, label="Users",
    )

    def __init__(self, *args, product=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.product = product
        current = product.authorized_users.values_list("pk", flat=True)
        self.fields["users"].queryset = (
            Dojo_User.objects.filter(is_active=True)
            .exclude(is_superuser=True)
            .exclude(pk__in=current)
            .order_by("first_name", "last_name")
        )


class Authorize_User_For_ProductsForm(forms.Form):
    products = forms.ModelMultipleChoiceField(
        queryset=Product.objects.none(), required=True, label=labels.ASSET_PLURAL_LABEL,
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        # Show products the user is not already directly authorized for.
        self.fields["products"].queryset = (
            Product.objects.exclude(authorized_users=user).order_by("name")
        )


def get_years():
    now = timezone.now()
    return [(now.year, now.year), (now.year - 1, now.year - 1), (now.year - 2, now.year - 2)]


class ProductCountsFormBase(forms.Form):
    month = forms.ChoiceField(choices=list(MONTHS.items()), required=True, error_messages={
        "required": "*"})
    year = forms.ChoiceField(choices=get_years, required=True, error_messages={
        "required": "*"})


class ProductTagCountsForm(ProductCountsFormBase):
    product_tag = forms.ModelChoiceField(required=True,
                                         queryset=Product.tags.tag_model.objects.none().order_by("name"),
                                         label=labels.ASSET_TAG_LABEL,
                                         error_messages={
                                             "required": "*"})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        prods = get_authorized_products("view")
        tags_available_to_user = Product.tags.tag_model.objects.filter(product__in=prods)
        self.fields["product_tag"].queryset = tags_available_to_user


class Product_API_Scan_ConfigurationForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    tool_configuration = forms.ModelChoiceField(
        label="Tool Configuration",
        queryset=Tool_Configuration.objects.all().order_by("name"),
        required=True,
    )

    class Meta:
        model = Product_API_Scan_Configuration
        exclude = ["product"]


class DeleteProduct_API_Scan_ConfigurationForm(forms.ModelForm):
    id = forms.IntegerField(required=True, widget=forms.widgets.HiddenInput())

    class Meta:
        model = Product_API_Scan_Configuration
        fields = ["id"]
