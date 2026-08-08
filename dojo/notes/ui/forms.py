from django import forms

from dojo.notes.models import Notes
from dojo.utils import get_system_setting


class NoteForm(forms.ModelForm):
    entry = forms.CharField(max_length=2400, widget=forms.Textarea(attrs={"rows": 4, "cols": 15}),
                            label="Notes:")

    class Meta:
        model = Notes
        fields = ["entry", "private"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class TypedNoteForm(NoteForm):

    def __init__(self, *args, **kwargs):
        queryset = kwargs.pop("available_note_types")
        super().__init__(*args, **kwargs)
        self.fields["note_type"] = forms.ModelChoiceField(queryset=queryset, label="Note Type", required=True)

    class Meta:
        model = Notes
        fields = ["note_type", "entry", "private"]


class DeleteNoteForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Notes
        fields = ["id"]
