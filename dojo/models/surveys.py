# ==========================
# Defect Dojo Engaegment Surveys
# ==============================

from polymorphic.models import PolymorphicModel

from django.db import models
from django.utils.translation import gettext as _

from django_extensions.db.models import TimeStampedModel


class Question(PolymorphicModel, TimeStampedModel):
    '''
        Represents a question.
    '''

    class Meta:
        ordering = ['order']

    order = models.PositiveIntegerField(default=1,
                                        help_text=_('The render order'))

    optional = models.BooleanField(
        default=False,
        help_text=_("If selected, user doesn't have to answer this question"))

    text = models.TextField(blank=False, help_text=_('The question text'), default='')

    def __str__(self):
        return self.text


class TextQuestion(Question):
    '''
    Question with a text answer
    '''

    def get_form(self):
        '''
        Returns the form for this model
        '''
        from ..forms import TextQuestionForm
        return TextQuestionForm


class Choice(TimeStampedModel):
    '''
    Model to store the choices for multi choice questions
    '''

    order = models.PositiveIntegerField(default=1)

    label = models.TextField(default="")

    class Meta:
        ordering = ['order']

    def __str__(self):
        return self.label


class ChoiceQuestion(Question):
    '''
    Question with answers that are chosen from a list of choices defined
    by the user.
    '''

    multichoice = models.BooleanField(default=False,
                                      help_text=_("Select one or more"))

    choices = models.ManyToManyField(Choice)

    def get_form(self):
        '''
        Returns the form for this model
        '''

        from ..forms import ChoiceQuestionForm
        return ChoiceQuestionForm


# meant to be a abstract survey, identified by name for purpose
class Engagement_Survey(models.Model):
    name = models.CharField(max_length=200, null=False, blank=False,
                            editable=True, default='')
    description = models.TextField(editable=True, default='')
    questions = models.ManyToManyField(Question)
    active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _("Engagement Survey")
        verbose_name_plural = "Engagement Surveys"
        ordering = ('-active', 'name',)

    def __str__(self):
        return self.name


# meant to be an answered survey tied to an engagement

class Answered_Survey(models.Model):
    # tie this to a specific engagement
    engagement = models.ForeignKey('Engagement', related_name='engagement+',
                                   null=True, blank=False, editable=True,
                                   on_delete=models.CASCADE)
    # what surveys have been answered
    survey = models.ForeignKey(Engagement_Survey, on_delete=models.CASCADE)
    assignee = models.ForeignKey('Dojo_User', related_name='assignee',
                                  null=True, blank=True, editable=True,
                                  default=None, on_delete=models.RESTRICT)
    # who answered it
    responder = models.ForeignKey('Dojo_User', related_name='responder',
                                  null=True, blank=True, editable=True,
                                  default=None, on_delete=models.RESTRICT)
    completed = models.BooleanField(default=False)
    answered_on = models.DateField(null=True)

    class Meta:
        verbose_name = _("Answered Engagement Survey")
        verbose_name_plural = _("Answered Engagement Surveys")

    def __str__(self):
        return self.survey.name


class General_Survey(models.Model):
    survey = models.ForeignKey(Engagement_Survey, on_delete=models.CASCADE)
    num_responses = models.IntegerField(default=0)
    generated = models.DateTimeField(auto_now_add=True, null=True)
    expiration = models.DateTimeField(null=False, blank=False)

    class Meta:
        verbose_name = _("General Engagement Survey")
        verbose_name_plural = _("General Engagement Surveys")

    def __str__(self):
        return self.survey.name


class Answer(PolymorphicModel, TimeStampedModel):
    ''' Base Answer model
    '''
    question = models.ForeignKey(Question, on_delete=models.CASCADE)

    answered_survey = models.ForeignKey(Answered_Survey,
                                        null=False,
                                        blank=False,
                                        on_delete=models.CASCADE)


class TextAnswer(Answer):
    answer = models.TextField(
        blank=False,
        help_text=_('The answer text'),
        default='')

    def __str__(self):
        return self.answer


class ChoiceAnswer(Answer):
    answer = models.ManyToManyField(
        Choice,
        help_text=_('The selected choices as the answer'))

    def __str__(self):
        if len(self.answer.all()):
            return str(self.answer.all()[0])
        else:
            return 'No Response'
