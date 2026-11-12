# Regression: a model registered after the app registry is ready (DojoEvents, once nothing imported it
# during startup) expires every model's manager cache, and the rebuilt managers lose tagulous's
# enhancement: Finding.objects.create() stopped going through TaggedQuerySet.create().
from django.apps import apps
from django.test import SimpleTestCase
from django_tagulous.models.fields import SingleTagField, TagField
from django_tagulous.models.tagged import TaggedManager, TaggedQuerySet


def tagged_models():
    return [
        model
        for model in apps.get_app_config("dojo").get_models()
        if any(isinstance(field, (TagField, SingleTagField)) for field in model._meta.get_fields())
    ]


class TestTaggedModelManagers(SimpleTestCase):

    def test_dojo_has_tagged_models(self):
        self.assertIn("Finding", {model.__name__ for model in tagged_models()})

    def test_every_tagged_model_keeps_the_tagulous_manager(self):
        plain = [
            f"{model.__name__}: {type(model.objects).__name__} / {type(model.objects.get_queryset()).__name__}"
            for model in tagged_models()
            if not isinstance(model.objects, TaggedManager)
            or not isinstance(model.objects.get_queryset(), TaggedQuerySet)
        ]
        self.assertEqual(plain, [], msg="tagged models whose objects manager is not tagulous-enhanced")
