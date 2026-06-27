from django import forms

from dojo.engagement.queries import get_authorized_engagements
from dojo.labels import get_labels
from dojo.models import Engagement, Engagement_Presets, Product
from dojo.product.queries import get_authorized_products
from dojo.user.queries import get_authorized_users, get_authorized_users_for_product_and_product_type
from dojo.utils import get_system_setting
from dojo.validators import tag_validator

labels = get_labels()


class EngForm(forms.ModelForm):
    name = forms.CharField(
        max_length=300, required=False,
        help_text=(
            "Add a descriptive name to identify this engagement. "
            "Without a name the target start date will be set."
        ))
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=False, help_text="Description of the engagement and details regarding the engagement.")
    product = forms.ModelChoiceField(label=labels.ASSET_LABEL,
                                     queryset=Product.objects.none(),
                                     required=True)
    target_start = forms.DateField(widget=forms.TextInput(
        attrs={"class": "datepicker", "autocomplete": "off"}))
    target_end = forms.DateField(widget=forms.TextInput(
        attrs={"class": "datepicker", "autocomplete": "off"}))
    lead = forms.ModelChoiceField(
        queryset=None,
        required=True, label="Testing Lead")
    test_strategy = forms.URLField(required=False, label="Test Strategy URL")

    def __init__(self, *args, **kwargs):
        cicd = False
        product = None
        if "cicd" in kwargs:
            cicd = kwargs.pop("cicd")

        if "product" in kwargs:
            product = kwargs.pop("product")

        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")

        super().__init__(*args, **kwargs)

        if product:
            self.fields["preset"] = forms.ModelChoiceField(help_text="Settings and notes for performing this engagement.", required=False, queryset=Engagement_Presets.objects.filter(product=product))
            self.fields["lead"].queryset = get_authorized_users_for_product_and_product_type(None, product, "view").filter(is_active=True)
        else:
            self.fields["lead"].queryset = get_authorized_users("view").filter(is_active=True)

        self.fields["product"].queryset = get_authorized_products("add")

        # Don't show CICD fields on a interactive engagement
        if cicd is False:
            del self.fields["build_id"]
            del self.fields["commit_hash"]
            del self.fields["branch_tag"]
            del self.fields["cicd_scm_server"]
            del self.fields["cicd_build_server"]
            del self.fields["cicd_orchestration_engine"]
            # del self.fields['source_code_management_uri']
        else:
            del self.fields["test_strategy"]
            del self.fields["status"]

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

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    class Meta:
        model = Engagement
        exclude = ("first_contacted", "real_start", "engagement_type", "inherited_tags",
                   "real_end", "requester", "reason", "updated", "report_type",
                   "product", "threat_model", "api_test", "pen_test", "check_list")


class DeleteEngagementForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Engagement
        fields = ["id"]


class EngagementPresetsForm(forms.ModelForm):

    notes = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=False, help_text="Description of what needs to be tested or setting up environment for testing")

    scope = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=False, help_text="Scope of Engagement testing, IP's/Resources/URL's)")

    class Meta:
        model = Engagement_Presets
        exclude = ["product"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class DeleteEngagementPresetsForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Engagement_Presets
        fields = ["id"]


class AddEngagementForm(forms.Form):
    product = forms.ModelChoiceField(
        queryset=Product.objects.none(),
        required=True,
        widget=forms.widgets.Select(),
        help_text="Select which product to attach Engagement")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["product"].queryset = get_authorized_products("add")


class ExistingEngagementForm(forms.Form):
    engagement = forms.ModelChoiceField(
        queryset=Engagement.objects.none(),
        required=True,
        widget=forms.widgets.Select(),
        help_text="Select which Engagement to link the Questionnaire to")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["engagement"].queryset = get_authorized_engagements("edit").order_by("-target_start")
