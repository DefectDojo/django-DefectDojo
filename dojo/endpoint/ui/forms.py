from django import forms
from tagulous.forms import TagField

from dojo.endpoint.models import Endpoint
from dojo.endpoint.utils import endpoint_filter, endpoint_get_or_create, validate_endpoints_to_add
from dojo.labels import get_labels
from dojo.models import Finding, Product
from dojo.product.queries import get_authorized_products
from dojo.validators import tag_validator

labels = get_labels()


class ImportEndpointMetaForm(forms.Form):
    file = forms.FileField(widget=forms.widgets.FileInput(
        attrs={"accept": ".csv"}),
        label="Choose meta file",
        required=True)  # Could not get required=True to actually accept the file as present
    create_endpoints = forms.BooleanField(
        label="Create nonexisting Endpoint",
        initial=True,
        required=False,
        help_text="Create endpoints that do not already exist")
    create_tags = forms.BooleanField(
        label="Add Tags",
        initial=True,
        required=False,
        help_text="Add meta from file as tags in the format key:value")
    create_dojo_meta = forms.BooleanField(
        label="Add Meta",
        initial=False,
        required=False,
        help_text="Add data from file as Metadata. Metadata is used for displaying custom fields")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class EditEndpointForm(forms.ModelForm):
    class Meta:
        model = Endpoint
        exclude = ["product", "inherited_tags"]

    def __init__(self, *args, **kwargs):
        self.product = None
        self.endpoint_instance = None
        super().__init__(*args, **kwargs)
        if "instance" in kwargs:
            self.endpoint_instance = kwargs.pop("instance")
            self.product = self.endpoint_instance.product
            product_id = self.endpoint_instance.product.pk
            findings = Finding.objects.filter(test__engagement__product__id=product_id)
            self.fields["findings"].queryset = findings

    def clean(self):

        cleaned_data = super().clean()

        protocol = cleaned_data["protocol"]
        userinfo = cleaned_data["userinfo"]
        host = cleaned_data["host"]
        port = cleaned_data["port"]
        path = cleaned_data["path"]
        query = cleaned_data["query"]
        fragment = cleaned_data["fragment"]

        endpoint = endpoint_filter(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            product=self.product,
        )
        if endpoint.count() > 1 or (endpoint.count() == 1 and endpoint.first().pk != self.endpoint_instance.pk):
            msg = "It appears as though an endpoint with this data already exists for this product."
            raise forms.ValidationError(msg, code="invalid")

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")


class AddEndpointForm(forms.Form):
    endpoint = forms.CharField(max_length=5000, required=True, label="Endpoint(s)",
                               help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                         "Each must be valid.",
                               widget=forms.widgets.Textarea(attrs={"rows": "15", "cols": "400"}))
    product = forms.CharField(required=True,
                              label=labels.ASSET_LABEL, help_text=labels.ASSET_ENDPOINT_HELP,
                              widget=forms.widgets.HiddenInput())
    tags = TagField(required=False,
                    help_text="Add tags that help describe this endpoint.  "
                              "Choose from the list or add new tags. Press Enter key to add.")

    def __init__(self, *args, **kwargs):
        product = None
        if "product" in kwargs:
            product = kwargs.pop("product")
        super().__init__(*args, **kwargs)
        self.fields["product"] = forms.ModelChoiceField(
            queryset=get_authorized_products("add"),
            label=labels.ASSET_LABEL,
            help_text=labels.ASSET_ENDPOINT_HELP)
        if product is not None:
            self.fields["product"].initial = product.id

        self.product = product
        self.endpoints_to_process = []

    def save(self):
        processed_endpoints = []
        for e in self.endpoints_to_process:
            endpoint, _created = endpoint_get_or_create(
                protocol=e[0],
                userinfo=e[1],
                host=e[2],
                port=e[3],
                path=e[4],
                query=e[5],
                fragment=e[6],
                product=self.product,
            )
            processed_endpoints.append(endpoint)
        return processed_endpoints

    def clean(self):

        cleaned_data = super().clean()

        if "endpoint" in cleaned_data and "product" in cleaned_data:
            endpoint = cleaned_data["endpoint"]
            product = cleaned_data["product"]
            if isinstance(product, Product):
                self.product = product
            else:
                self.product = Product.objects.get(id=int(product))
        else:
            msg = "Please enter a valid URL or IP address."
            raise forms.ValidationError(msg, code="invalid")

        endpoints_to_add_list, errors = validate_endpoints_to_add(endpoint)
        if errors:
            raise forms.ValidationError(errors)
        self.endpoints_to_process = endpoints_to_add_list

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")


class DeleteEndpointForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Endpoint
        fields = ["id"]
