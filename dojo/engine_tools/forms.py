from django import forms
from dojo.templatetags.authorization_tags import is_in_reviewer_group
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.models import Product, Product_Type, Engagement
from dojo.engine_tools.helpers import Constants


class CreateFindingExclusionForm(forms.ModelForm):
    type = forms.ChoiceField(required=True,
                             choices=FindingExclusion.TYPE_CHOICES)
    unique_id_from_tool = forms.CharField(
        required=True,
        max_length=500,
        help_text=Constants.VULNERABILITY_ID_HELP_TEXT.value)
    reason = forms.CharField(max_length=200, required=True,
                             widget=forms.Textarea,
                             label="Reason",
                             help_text="Please provide a reason for excluding this vulnerability id.")
    
    practice = forms.CharField(required=False,
                                label="Practice Origin Exclusion",
                                help_text="practice where exclusion originates",)
    
    scope = forms.ChoiceField(
        choices=[('all', 'All Engagements'), ('specific', 'Specific Engagements')],
        widget=forms.RadioSelect,
        initial='all',
        label="Scope"
    )
    
    product_type = forms.ModelChoiceField(
        queryset=Product_Type.objects.all().order_by('name'),
        required=False,
        label="Product Type"
    )
    
    product = forms.ModelChoiceField(
        queryset=Product.objects.none(),
        required=False,
        label="Product"
    )
    
    engagements = forms.ModelMultipleChoiceField(
        queryset=Engagement.objects.none(),
        required=False,
        label="Engagements"
    )
    
    class Meta:
        model = FindingExclusion
        fields = ["type", "unique_id_from_tool", "reason", "practice", "scope", "product_type", "product", "engagements"]
        
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        
        if not is_in_reviewer_group(self.user):
            self.fields.pop("scope")

        if self.initial.get("practice"):
            self.fields.pop("practice")

        if 'product_type' in self.data:
            try:
                product_type_id = int(self.data.get('product_type'))
                self.fields['product'].queryset = Product.objects.filter(prod_type_id=product_type_id).order_by('name')
            except (ValueError, TypeError):
                pass
        elif self.instance.pk and self.instance.product_type:
             self.fields['product'].queryset = self.instance.product_type.product_set.order_by('name')

        if 'product' in self.data:
            try:
                product_id = int(self.data.get('product'))
                self.fields['engagements'].queryset = Engagement.objects.filter(product_id=product_id).order_by('name')
            except (ValueError, TypeError):
                pass
        elif self.instance.pk and self.instance.product:
            self.fields['engagements'].queryset = self.instance.product.engagement_set.order_by('name')

    def clean(self):
        cleaned_data = super().clean()
        scope = cleaned_data.get("scope")
        
        if scope == 'specific':
            if not is_in_reviewer_group(self.user):
                raise forms.ValidationError("You do not have permission to create a specific engagement exclusion.")
            if not cleaned_data.get("product_type"):
                self.add_error('product_type', "This field is required when 'Specific Engagements' is selected.")
            if not cleaned_data.get("product"):
                self.add_error('product', "This field is required when 'Specific Engagements' is selected.")
        
        return cleaned_data


class EditFindingExclusionForm(forms.ModelForm):
    scope = forms.ChoiceField(
        choices=[('all', 'All Engagements'), ('specific', 'Specific Engagements')],
        widget=forms.RadioSelect,
        label="Scope"
    )

    class Meta:
        model = FindingExclusion
        fields = [
            "type", "unique_id_from_tool", "reason",
            "expiration_date", "status", "practice",
            "scope", "product_type", "product", "engagements"
        ]
        widgets = {
            'expiration_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

        self.fields["expiration_date"].required = False

        if not is_in_reviewer_group(self.user):
            self.fields.pop("scope")

        if self.initial.get("practice"):
            self.fields.pop("practice")

        if 'product_type' in self.data:
            try:
                product_type_id = int(self.data.get('product_type'))
                self.fields['product'].queryset = (
                    Product.objects
                    .filter(prod_type_id=product_type_id)
                    .order_by('name')
                )
            except (ValueError, TypeError):
                pass
        elif self.instance.pk and self.instance.product_type:
            self.fields['product'].queryset = (
                Product.objects
                .filter(prod_type=self.instance.product_type)
                .order_by('name')
            )
        else:
            self.fields['product'].queryset = Product.objects.none()

        if 'product' in self.data:
            try:
                product_id = int(self.data.get('product'))
                self.fields['engagements'].queryset = (
                    Engagement.objects
                    .filter(product_id=product_id)
                    .order_by('name')
                )
            except (ValueError, TypeError):
                pass
        elif self.instance.pk and self.instance.product:
            self.fields['engagements'].queryset = (
                self.instance.product.engagement_set.order_by('name')
            )
        else:
            self.fields['engagements'].queryset = Engagement.objects.none()
 
    
class FindingExclusionDiscussionForm(forms.ModelForm):
    class Meta:
        model = FindingExclusionDiscussion
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Add a comment...'})
        }
