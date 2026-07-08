from django import forms

from dojo.announcement.models import Announcement


class AnnouncementCreateForm(forms.ModelForm):
    class Meta:
        model = Announcement
        fields = "__all__"


class AnnouncementRemoveForm(AnnouncementCreateForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["dismissable"].disabled = True
        self.fields["message"].disabled = True
        self.fields["style"].disabled = True
