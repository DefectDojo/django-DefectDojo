import contextlib

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete, pre_delete, pre_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Finding, Test
from dojo.notes.helper import delete_related_notes
from dojo.notifications.helper import create_notification


@receiver(post_delete, sender=Test)
def test_post_delete(sender, instance, using, origin, **kwargs):
    if instance == origin:
        if settings.ENABLE_AUDITLOG:
            le = LogEntry.objects.get(
                action=LogEntry.Action.DELETE,
                content_type=ContentType.objects.get(app_label="dojo", model="test"),
                object_id=instance.id,
            )
            description = _('The test "%(name)s" was deleted by %(user)s') % {
                                "name": str(instance), "user": le.actor}
        else:
            description = _('The test "%(name)s" was deleted') % {"name": str(instance)}
        create_notification(event="test_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                            title=_("Deletion of %(name)s") % {"name": str(instance)},
                            description=description,
                            product=instance.engagement.product,
                            url=reverse("view_engagement", args=(instance.engagement.id, )),
                            recipients=[instance.engagement.lead],
                            icon="exclamation-triangle")


@receiver(pre_save, sender=Test)
def update_found_by_for_findings(sender, instance, **kwargs):
    with contextlib.suppress(sender.DoesNotExist):
        obj = sender.objects.get(pk=instance.pk)
        # Check if the test type has changed
        if obj.test_type != instance.test_type:
            # Save a reference to the old test type ID to replace with the new one
            old_test_type = obj.test_type
            new_test_type = instance.test_type
            # Get all the findings in this test
            findings = Finding.objects.filter(test=instance)
            # Update each of the findings found by column
            for find in findings:
                find.found_by.remove(old_test_type)
                find.found_by.add(new_test_type)


@receiver(pre_delete, sender=Test)
def test_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)
