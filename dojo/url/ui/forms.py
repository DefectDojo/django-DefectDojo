import logging

from django import forms
from tagulous.forms import TagField

from dojo.location.models import Location
from dojo.url.models import URL
from dojo.validators import tag_validator

logger = logging.getLogger(__name__)


class URLForm(forms.ModelForm):
    tags = TagField(
        label="Tags",
        required=False,
        help_text="Add tags that help describe this endpoint. Choose from the list or add new tags. Press Enter key to add.",
        autocomplete_tags=Location.tags.tag_model.objects.all().order_by("name"),
    )

    class Meta:
        model = URL
        exclude = ["location", "host_validation_failure"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance is not None and hasattr(self.instance, "location"):
            self.fields["tags"].initial = self.instance.location.tags.all()

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    def save(self, commit: bool = True, update_only: bool = False) -> URL:  # noqa: FBT001, FBT002
        url = super().save(commit=False)
        if commit:
            url = super().save(commit=True) if update_only else URL.get_or_create_from_object(url)
            url.location.tags.set(self.cleaned_data["tags"])
        return url


class DeleteURLForm(forms.ModelForm):
    id = forms.IntegerField(required=True, widget=forms.widgets.HiddenInput())

    class Meta:
        model = URL
        fields = ["id"]
