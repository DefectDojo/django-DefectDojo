from django import forms

from dojo.note_type.models import Note_Type


class NoteTypeForm(forms.ModelForm):
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=True)

    class Meta:
        model = Note_Type
        fields = ["name", "description", "is_single", "is_mandatory"]


class EditNoteTypeForm(NoteTypeForm):

    def __init__(self, *args, **kwargs):
        is_single = kwargs.pop("is_single")
        super().__init__(*args, **kwargs)
        if is_single is False:
            self.fields["is_single"].widget = forms.HiddenInput()


class DisableOrEnableNoteTypeForm(NoteTypeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["name"].disabled = True
        self.fields["description"].disabled = True
        self.fields["is_single"].disabled = True
        self.fields["is_mandatory"].disabled = True
        self.fields["is_active"].disabled = True

    class Meta:
        model = Note_Type
        fields = "__all__"
