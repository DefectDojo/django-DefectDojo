from dojo.models import Announcement, UserAnnouncement, Dojo_User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings


@receiver(post_save, sender=Dojo_User)
def add_announcement_to_new_user(sender, instance, **kwargs):
    if settings.CREATE_INITIAL_BANNER:
        announcements = Announcement.objects.all()
        if announcements.count() > 0:
            dojo_user = Dojo_User.objects.get(id=instance.id)
            announcement = announcements.first()
            user_announcements = UserAnnouncement.objects.filter(
                user=dojo_user,
                announcement=announcement)
            if user_announcements.count() == 0:
                UserAnnouncement.objects.get_or_create(
                    user=dojo_user,
                    announcement=announcement)
