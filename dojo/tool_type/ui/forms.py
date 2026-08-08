from django import forms

from dojo.tool_type.models import Tool_Type


class ToolTypeForm(forms.ModelForm):
    class Meta:
        model = Tool_Type
        exclude = ["product"]

    def __init__(self, *args, **kwargs):
        instance = kwargs.get("instance")
        self.newly_created = True
        if instance is not None:
            self.newly_created = instance.pk is None
        super().__init__(*args, **kwargs)

    def clean(self):
        form_data = self.cleaned_data
        if self.newly_created:
            name = form_data.get("name")
            # Make sure this will not create a duplicate test type
            if Tool_Type.objects.filter(name=name).count() > 0:
                msg = "A Tool Type with the name already exists"
                raise forms.ValidationError(msg)

        return form_data
