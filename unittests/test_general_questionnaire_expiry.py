"""
Regression tests for the expiration of a shared general questionnaire link
(``answer_empty_survey`` in ``dojo/survey/ui/views.py``).

``General_Survey.expiration`` is the lifetime of the shared link. The route the
link points at is login exempt, so with "Allow Anonymous Survey Responses"
enabled an unauthenticated client reaches it. The route never read the field,
and the only code acting on it was a delete sweep in the permission gated
questionnaire list view, so an expired link kept accepting responses until an
authorized user happened to load that page.

The route answers 404 rather than 403 so an expired link and an unknown one
look the same to an anonymous client.
"""
from datetime import timedelta

from django.urls import reverse
from django.utils import timezone

from dojo.models import (
    Answered_Survey,
    Engagement_Survey,
    General_Survey,
    TextQuestion,
)
from unittests.dojo_test_case import DojoTestCase


class GeneralQuestionnaireExpiryTests(DojoTestCase):
    def setUp(self):
        super().setUp()
        self.system_settings(allow_anonymous_survey_repsonse=True)
        self.questionnaire = Engagement_Survey.objects.create(
            name="expiry_probe", description="expiry_probe", active=True,
        )
        self.question = TextQuestion.objects.create(text="expiry_probe question", order=1)
        self.questionnaire.questions.add(self.question)
        self.expired = General_Survey.objects.create(
            survey=self.questionnaire,
            expiration=timezone.now() - timedelta(days=1),
        )
        self.live = General_Survey.objects.create(
            survey=self.questionnaire,
            expiration=timezone.now() + timedelta(days=7),
        )

    def answer_url(self, general_survey):
        return reverse("answer_empty_survey", args=(general_survey.id,))

    def test_expired_link_is_not_readable(self):
        self.assertEqual(self.client.get(self.answer_url(self.expired)).status_code, 404)

    def test_expired_link_records_no_response(self):
        response = self.client.post(
            self.answer_url(self.expired),
            {f"{self.question.id}-answer": "answer to an expired questionnaire"},
        )

        self.assertEqual(response.status_code, 404)
        self.assertFalse(Answered_Survey.objects.filter(survey=self.questionnaire).exists())
        self.expired.refresh_from_db()
        self.assertEqual(self.expired.num_responses, 0)

    def test_live_link_still_answerable(self):
        self.assertEqual(self.client.get(self.answer_url(self.live)).status_code, 200)

        response = self.client.post(
            self.answer_url(self.live),
            {f"{self.question.id}-answer": "answer to a live questionnaire"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(Answered_Survey.objects.filter(survey=self.questionnaire).count(), 1)
        self.live.refresh_from_db()
        self.assertEqual(self.live.num_responses, 1)
