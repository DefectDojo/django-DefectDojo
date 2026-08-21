import logging

from django import forms

from dojo.models import Development_Environment, Engagement, Product_API_Scan_Configuration, Test, Test_Type
from dojo.user.queries import get_authorized_users, get_authorized_users_for_product_and_product_type
from dojo.utils import get_product
from dojo.validators import tag_validator

logger = logging.getLogger(__name__)


class TestForm(forms.ModelForm):
    title = forms.CharField(max_length=255, required=False)
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": "3"}), required=False)
    test_type = forms.ModelChoiceField(queryset=Test_Type.objects.all().order_by("name"))
    environment = forms.ModelChoiceField(
        queryset=Development_Environment.objects.all().order_by("name"))
    target_start = forms.DateTimeField(widget=forms.TextInput(
        attrs={"class": "datepicker", "autocomplete": "off"}))
    target_end = forms.DateTimeField(widget=forms.TextInput(
        attrs={"class": "datepicker", "autocomplete": "off"}))
    lead = forms.ModelChoiceField(
        queryset=None,
        required=False, label="Testing Lead")

    def __init__(self, *args, **kwargs):
        obj = None

        if "engagement" in kwargs:
            obj = kwargs.pop("engagement")

        if "instance" in kwargs:
            obj = kwargs.get("instance")

        super().__init__(*args, **kwargs)

        if obj:
            product = get_product(obj)
            self.fields["lead"].queryset = get_authorized_users_for_product_and_product_type(None, product, "view").filter(is_active=True)
            self.fields["api_scan_configuration"].queryset = Product_API_Scan_Configuration.objects.filter(product=product)
        else:
            self.fields["lead"].queryset = get_authorized_users("view").filter(is_active=True)

    def is_valid(self):
        valid = super().is_valid()

        # we're done now if not valid
        if not valid:
            return valid
        if self.cleaned_data["target_start"] > self.cleaned_data["target_end"]:
            self.add_error("target_start", "Your target start date exceeds your target end date")
            self.add_error("target_end", "Your target start date exceeds your target end date")
            return False
        return True

    class Meta:
        model = Test
        fields = ["title", "test_type", "target_start", "target_end", "description",
                  "environment", "percent_complete", "tags", "lead", "version", "branch_tag", "build_id", "commit_hash",
                  "api_scan_configuration"]

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")


class DeleteTestForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Test
        fields = ["id"]


class CopyTestForm(forms.Form):
    engagement = forms.ModelChoiceField(
        required=True,
        queryset=Engagement.objects.none(),
        error_messages={"required": "*"})

    def __init__(self, *args, **kwargs):
        authorized_lists = kwargs.pop("engagements", None)
        super().__init__(*args, **kwargs)
        self.fields["engagement"].queryset = authorized_lists
