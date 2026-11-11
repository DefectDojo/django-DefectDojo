from django import forms

from dojo.product_attributes.models import VALUE_COMMA_ERROR, Product_Lifecycle, Product_Origin, Product_Platform


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

    def clean_value(self):
        value = self.cleaned_data["value"]
        # Only a new option is checked: an existing row keeps its own (the field is disabled on edit).
        if not self.instance.pk and "," in value:
            raise forms.ValidationError(VALUE_COMMA_ERROR)
        return value


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
