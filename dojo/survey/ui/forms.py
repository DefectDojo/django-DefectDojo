import json
import warnings
from datetime import datetime

from crispy_forms.bootstrap import InlineCheckboxes, InlineRadios
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout
from django import forms
from django.db.models import Count
from django.utils import timezone
from polymorphic.base import ManagerInheritanceWarning

from dojo.survey.models import (
    Answered_Survey,
    Choice,
    ChoiceAnswer,
    ChoiceQuestion,
    Engagement_Survey,
    General_Survey,
    Question,
    TextAnswer,
    TextQuestion,
)
from dojo.user.queries import get_authorized_users


class MultipleSelectWithPop(forms.SelectMultiple):
    def render(self, name, *args, **kwargs):
        from django.utils.safestring import mark_safe  # noqa: PLC0415 -- lazy import, avoids circular dependency
        html = super().render(name, *args, **kwargs)
        popup_plus = '<div class="input-group dojo-input-group">' + html + '<span class="input-group-btn"><a href="/' + name + '/add" class="btn btn-primary" class="add-another" id="add_id_' + name + '" onclick="return showAddAnotherPopup(this);"><span class="glyphicon glyphicon-plus"></span></a></span></div>'
        return mark_safe(popup_plus)


# ==============================
# Defect Dojo Engaegment Surveys
# ==============================

# List of validator_name:func_name
# Show in admin a multichoice list of validator names
# pass this to form using field_name='validator_name' ?
class QuestionForm(forms.Form):

    """Base class for a Question"""

    def __init__(self, *args, **kwargs):
        self.helper = FormHelper()
        self.helper.form_method = "post"

        # If true crispy-forms will render a <form>..</form> tags
        self.helper.form_tag = kwargs.pop("form_tag", True)

        self.engagement_survey = kwargs.get("engagement_survey")

        self.answered_survey = kwargs.get("answered_survey")
        if not self.answered_survey:
            del kwargs["engagement_survey"]
        else:
            del kwargs["answered_survey"]

        self.helper.form_class = kwargs.get("form_class", "")

        self.question = kwargs.pop("question", None)

        if not self.question:
            msg = "Need a question to render"
            raise ValueError(msg)

        super().__init__(*args, **kwargs)


class TextQuestionForm(QuestionForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # work out initial data

        initial_answer = TextAnswer.objects.filter(
            answered_survey=self.answered_survey,
            question=self.question,
        )

        initial_answer = initial_answer[0].answer if initial_answer.exists() else ""

        self.fields["answer"] = forms.CharField(
            label=self.question.text,
            widget=forms.Textarea(attrs={"rows": 3, "cols": 10}),
            required=not self.question.optional,
            initial=initial_answer,
        )

    def save(self):
        if not self.is_valid():
            msg = "form is not valid"
            raise forms.ValidationError(msg)

        answer = self.cleaned_data.get("answer")

        if not answer:
            if self.fields["answer"].required:
                msg = "Required"
                raise forms.ValidationError(msg)
            return

        text_answer, created = TextAnswer.objects.get_or_create(
            answered_survey=self.answered_survey,
            question=self.question,
        )

        if created:
            text_answer.answered_survey = self.answered_survey
        text_answer.answer = answer
        text_answer.save()


class ChoiceQuestionForm(QuestionForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        choices = [(c.id, c.label) for c in self.question.choices.all()]

        # initial values

        initial_choices = []
        choice_answer = ChoiceAnswer.objects.filter(
            answered_survey=self.answered_survey,
            question=self.question,
        ).annotate(a=Count("answer")).filter(a__gt=0)

        # we have ChoiceAnswer instance
        if choice_answer:
            choice_answer = choice_answer[0]
            initial_choices = list(choice_answer.answer.all().values_list("id", flat=True))
            if self.question.multichoice is False:
                initial_choices = initial_choices[0]

        # default classes
        widget = forms.RadioSelect
        field_type = forms.ChoiceField
        inline_type = InlineRadios

        if self.question.multichoice:
            field_type = forms.MultipleChoiceField
            widget = forms.CheckboxSelectMultiple
            inline_type = InlineCheckboxes

        field = field_type(
            label=self.question.text,
            required=not self.question.optional,
            choices=choices,
            initial=initial_choices,
            widget=widget,
        )

        self.fields["answer"] = field

        # Render choice buttons inline
        self.helper.layout = Layout(
            inline_type("answer"),
        )

    def clean_answer(self):
        real_answer = self.cleaned_data.get("answer")

        # for single choice questions, the selected answer is a single string
        if not isinstance(real_answer, list):
            real_answer = [real_answer]
        return real_answer

    def save(self):
        if not self.is_valid():
            msg = "Form is not valid"
            raise forms.ValidationError(msg)

        real_answer = self.cleaned_data.get("answer")

        if not real_answer:
            if self.fields["answer"].required:
                msg = "Required"
                raise forms.ValidationError(msg)
            return

        choices = Choice.objects.filter(id__in=real_answer)

        # find ChoiceAnswer and filter in answer !
        choice_answer = ChoiceAnswer.objects.filter(
            answered_survey=self.answered_survey,
            question=self.question,
        )

        # we have ChoiceAnswer instance
        if choice_answer:
            choice_answer = choice_answer[0]

        if not choice_answer:
            # create a ChoiceAnswer
            choice_answer = ChoiceAnswer.objects.create(
                answered_survey=self.answered_survey,
                question=self.question,
            )

        # re save out the choices
        choice_answer.answered_survey = self.answered_survey
        choice_answer.answer.set(choices)
        choice_answer.save()


class Add_Questionnaire_Form(forms.ModelForm):
    survey = forms.ModelChoiceField(
        queryset=Engagement_Survey.objects.all(),
        required=True,
        widget=forms.widgets.Select(),
        help_text="Select the Questionnaire to add.")

    class Meta:
        model = Answered_Survey
        exclude = ("responder",
                   "completed",
                   "engagement",
                   "answered_on",
                   "assignee")


class AddGeneralQuestionnaireForm(forms.ModelForm):
    survey = forms.ModelChoiceField(
        queryset=Engagement_Survey.objects.all(),
        required=True,
        widget=forms.widgets.Select(),
        help_text="Select the Questionnaire to add.")
    expiration = forms.DateField(widget=forms.TextInput(
        attrs={"class": "datepicker", "autocomplete": "off"}))

    class Meta:
        model = General_Survey
        exclude = ("num_responses", "generated")

    # date can only be today or in the past, not the future
    def clean_expiration(self):
        expiration = self.cleaned_data.get("expiration", None)
        if expiration:
            today = datetime.today().date()
            if expiration < today:
                msg = "The expiration cannot be in the past"
                raise forms.ValidationError(msg)
            if expiration == today:
                msg = "The expiration cannot be today"
                raise forms.ValidationError(msg)
            return timezone.make_aware(
                datetime.combine(expiration, datetime.min.time()),
            )
        msg = "An expiration for the survey must be supplied"
        raise forms.ValidationError(msg)


class Delete_Questionnaire_Form(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Answered_Survey
        fields = ["id"]


class DeleteGeneralQuestionnaireForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = General_Survey
        fields = ["id"]


class Delete_Eng_Survey_Form(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Engagement_Survey
        fields = ["id"]


class CreateQuestionnaireForm(forms.ModelForm):
    class Meta:
        model = Engagement_Survey
        exclude = ["questions"]


with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class EditQuestionnaireQuestionsForm(forms.ModelForm):
        questions = forms.ModelMultipleChoiceField(
            Question.polymorphic.all(),
            required=True,
            help_text="Select questions to include on this questionnaire.  Field can be used to search available questions.",
            widget=MultipleSelectWithPop(attrs={"size": "11"}))

        class Meta:
            model = Engagement_Survey
            exclude = ["name", "description", "active"]


class CreateQuestionForm(forms.Form):
    type = forms.ChoiceField(
        choices=(("---", "-----"), ("text", "Text"), ("choice", "Choice")))
    order = forms.IntegerField(
        min_value=1,
        widget=forms.TextInput(attrs={"data-type": "both"}),
        help_text="The order the question will appear on the questionnaire")
    optional = forms.BooleanField(help_text="If selected, user doesn't have to answer this question",
                                  initial=False,
                                  required=False,
                                  widget=forms.CheckboxInput(attrs={"data-type": "both"}))
    text = forms.CharField(widget=forms.Textarea(attrs={"data-type": "text"}),
                           label="Question Text",
                           help_text="The actual question.")


class CreateTextQuestionForm(forms.Form):
    class Meta:
        model = TextQuestion
        exclude = ["order", "optional"]


class MultiWidgetBasic(forms.widgets.MultiWidget):
    def __init__(self, attrs=None):
        widgets = [forms.TextInput(attrs={"data-type": "choice"}),
                   forms.TextInput(attrs={"data-type": "choice"}),
                   forms.TextInput(attrs={"data-type": "choice"}),
                   forms.TextInput(attrs={"data-type": "choice"}),
                   forms.TextInput(attrs={"data-type": "choice"}),
                   forms.TextInput(attrs={"data-type": "choice"})]
        super().__init__(widgets, attrs)

    def decompress(self, value):
        if value:
            return json.loads(value)
        return [None, None, None, None, None, None]

    def format_output(self, rendered_widgets):
        return "<br/>".join(rendered_widgets)


class MultiExampleField(forms.fields.MultiValueField):
    widget = MultiWidgetBasic

    def __init__(self, *args, **kwargs):
        list_fields = [forms.fields.CharField(required=True),
                       forms.fields.CharField(required=True),
                       forms.fields.CharField(required=False),
                       forms.fields.CharField(required=False),
                       forms.fields.CharField(required=False),
                       forms.fields.CharField(required=False)]
        super().__init__(list_fields, *args, **kwargs)

    def compress(self, values):
        return json.dumps(values)


class CreateChoiceQuestionForm(forms.Form):
    multichoice = forms.BooleanField(required=False,
                                     initial=False,
                                     widget=forms.CheckboxInput(attrs={"data-type": "choice"}),
                                     help_text="Can more than one choice can be selected?")

    answer_choices = MultiExampleField(required=False, widget=MultiWidgetBasic(attrs={"data-type": "choice"}))

    class Meta:
        model = ChoiceQuestion
        exclude = ["order", "optional", "choices"]


class EditQuestionForm(forms.ModelForm):
    class Meta:
        model = Question
        exclude = []


class EditTextQuestionForm(EditQuestionForm):
    class Meta:
        model = TextQuestion
        exclude = []


class EditChoiceQuestionForm(EditQuestionForm):
    choices = forms.ModelMultipleChoiceField(
        Choice.objects.all(),
        required=True,
        help_text="Select choices to include on this question.  Field can be used to search available choices.",
        widget=MultipleSelectWithPop(attrs={"size": "11"}))

    class Meta:
        model = ChoiceQuestion
        exclude = []


class AddChoicesForm(forms.ModelForm):
    class Meta:
        model = Choice
        exclude = []


class AssignUserForm(forms.ModelForm):
    assignee = forms.CharField(required=False,
                                widget=forms.widgets.HiddenInput())

    def __init__(self, *args, **kwargs):
        assignee = None
        if "assignee" in kwargs:
            assignee = kwargs.pop("asignees")
        super().__init__(*args, **kwargs)
        if assignee is None:
            self.fields["assignee"] = forms.ModelChoiceField(queryset=get_authorized_users("view"), empty_label="Not Assigned", required=False)
        else:
            self.fields["assignee"].initial = assignee

    class Meta:
        model = Answered_Survey
        exclude = ["engagement", "survey", "responder", "completed", "answered_on"]
