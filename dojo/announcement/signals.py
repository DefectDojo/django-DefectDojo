from dojo.models import Announcement, UserAnnouncement, Dojo_User
from django.db.models.signals import post_save
from django.dispatch import receiver


@receiver(post_save, sender=Dojo_User)
def add_announcement_to_new_user(sender, instance, **kwargs):
    announcements = Announcement.objects.all()
    if announcements.count() > 0:
        dojo_user = Dojo_User.objects.get(id=instance.id)
        announcement = announcements.first()
        user_announcments = UserAnnouncement.objects.filter(
            user=dojo_user, announcement=announcement
        )
        if user_announcments.count() == 0:
            UserAnnouncement.objects.get_or_create(
                user=dojo_user, announcement=announcement
            )
