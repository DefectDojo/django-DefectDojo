from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Engagement
from dojo.notes.helper import delete_related_notes
from dojo.notifications.helper import create_notification


@receiver(post_save, sender=Engagement)
def engagement_post_save(sender, instance, created, **kwargs):
    if created:
        title = _('Engagement created for "%(product)s": %(name)s') % {"product": instance.product, "name": instance.name}
        create_notification(event="engagement_added", title=title, engagement=instance, product=instance.product,
                            url=reverse("view_engagement", args=(instance.id,)), url_api=reverse("engagement-detail", args=(instance.id,)))


@receiver(pre_save, sender=Engagement)
def engagement_pre_save(sender, instance, **kwargs):
    old = sender.objects.filter(pk=instance.pk).first()
    if old and instance.status != old.status:
        if instance.status in ["Cancelled", "Completed"]:
            create_notification(event="engagement_closed",
                                title=_("Closure of %s") % instance.name,
                                description=_('The engagement "%s" was closed') % (instance.name),
                                engagement=instance, url=reverse("engagement_all_findings", args=(instance.id, )))
        elif instance.status == "In Progress" and old.status != "Not Started":
            create_notification(event="engagement_reopened",
                                title=_("Reopening of %s") % instance.name,
                                engagement=instance,
                                description=_('The engagement "%s" was reopened') % (instance.name),
                                url=reverse("view_engagement", args=(instance.id, )))


@receiver(post_delete, sender=Engagement)
def engagement_post_delete(sender, instance, using, origin, **kwargs):
    if instance == origin:
        if settings.ENABLE_AUDITLOG:
            le = LogEntry.objects.get(
                action=LogEntry.Action.DELETE,
                content_type=ContentType.objects.get(app_label="dojo", model="engagement"),
                object_id=instance.id,
            )
            description = _('The engagement "%(name)s" was deleted by %(user)s') % {
                                "name": instance.name, "user": le.actor}
        else:
            description = _('The engagement "%(name)s" was deleted') % {"name": instance.name}
        create_notification(event="engagement_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                            title=_("Deletion of %(name)s") % {"name": instance.name},
                            description=description,
                            product=instance.product,
                            url=reverse("view_product", args=(instance.product.id, )),
                            recipients=[instance.lead],
                            icon="exclamation-triangle")


@receiver(pre_delete, sender=Engagement)
def engagement_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)
