from django.db.models.signals import post_save
from django.dispatch import receiver

from dojo.models import Announcement, Dojo_User, UserAnnouncement


@receiver(post_save, sender=Dojo_User)
def add_announcement_to_new_user(sender, instance, **kwargs):
    announcement = Announcement.objects.first()
    if announcement is not None:
        UserAnnouncement.objects.get_or_create(
            user=instance, announcement=announcement,
        )


@receiver(post_save, sender=Announcement)
def announcement_post_save(sender, instance, created, **kwargs):
    if created:
        UserAnnouncement.objects.bulk_create(
            [
                UserAnnouncement(
                    user=user_id, announcement=instance,
                )
                for user_id in Dojo_User.objects.all()
            ],
        )
