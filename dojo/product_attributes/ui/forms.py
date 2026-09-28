from django import forms

from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform


class ProductAttributeOptionForm(forms.ModelForm):
    class Meta:
        fields = ["value", "name", "icon", "display_order"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ``value`` is the immutable machine key. It may be set when creating a new
        # option, but never changed afterwards (existing assets, imports and rules
        # reference it).
        if self.instance and self.instance.pk:
            self.fields["value"].disabled = True


class ProductPlatformForm(ProductAttributeOptionForm):
    class Meta(ProductAttributeOptionForm.Meta):
        model = Product_Platform


class ProductLifecycleForm(ProductAttributeOptionForm):
    class Meta(ProductAttributeOptionForm.Meta):
        model = Product_Lifecycle


class ProductOriginForm(ProductAttributeOptionForm):
    class Meta(ProductAttributeOptionForm.Meta):
        model = Product_Origin


class DeleteProductAttributeOptionForm(forms.Form):
    id = forms.IntegerField(widget=forms.HiddenInput())
