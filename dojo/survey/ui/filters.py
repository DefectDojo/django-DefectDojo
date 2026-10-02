import warnings

import six
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _
from django_filters import BooleanFilter, CharFilter, FilterSet
from django_filters.filters import ChoiceFilter
from polymorphic.base import ManagerInheritanceWarning

from dojo.survey.models import ChoiceQuestion, Engagement_Survey, Question, TextQuestion


class QuestionnaireFilter(FilterSet):
    name = CharFilter(lookup_expr="icontains")
    description = CharFilter(lookup_expr="icontains")
    active = BooleanFilter()

    class Meta:
        model = Engagement_Survey
        exclude = ["questions"]

    survey_set = FilterSet


class QuestionTypeFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs.all()

    def text_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(TextQuestion))

    def choice_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(ChoiceQuestion))

    options = {
        None: (_("Any"), any),  # noqa: A003 -- shadows builtin; matches original dojo/filters.py pattern
        1: (_("Text Question"), text_question),
        2: (_("Choice Question"), choice_question),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.options[value][0])


with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class QuestionFilter(FilterSet):
        text = CharFilter(lookup_expr="icontains")
        type = QuestionTypeFilter()

        class Meta:
            model = Question
            exclude = ["polymorphic_ctype", "created", "modified", "order"]

        question_set = FilterSet
