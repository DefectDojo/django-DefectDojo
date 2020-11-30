
from dojo.models import Finding, Engagement, System_Settings
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q, Exists, OuterRef


logger = logging.getLogger(__name__)


def auto_delete_engagements():
    # TODO implement dry-run option
    """
    For an engagement to be in-scope for automated deletion, the following rules apply:
    - must have been updated before x days (as defined in system settings)
    - (hardcoded) must be a CI/CD engagement
    - (hardcoded) must only contain duplicate findings
    - (hardocded) must not contain any notes on any of its findings

    The original use-case of this feature relates to the mass imports that one can have through CI pipelines,
    generating a vast amount of findings which ultimately will boggle down defectdojo's performance
    and make it harder to see what needs to be seen.
    """

    """
    def _notify(engagement_id, engagement_title):
        create_notification(
            event='auto_delete_engagement',
            title=engagement_title,
            id=engagement_id,
        )
    """

    system_settings = System_Settings.objects.get()
    # if system_settings.engagement_auto_delete_enable:
    # how to not exclude the tag when not empty? If empty, then query results are unexpected.
    # setting arbitrary string for now, which is unlikely to be a used tag.
    # lock_tag = system_settings.engagement_auto_delete_lock_tag or 'qAEH2HL6Qd9ofZYLCGykN2WQ'
    lock_tag = 'donotdelete'
    logger.info("Proceeding with automatic engagements deletion, for engagements older than {} days".format(
        30
    ))
    logger.info("Lock tag is {}".format(lock_tag))

    # cutoff_date = timezone.make_aware(datetime.today()) - timedelta(days=system_settings.engagement_auto_delete_days)
    cutoff_date = timezone.make_aware(datetime.today()) - timedelta(days=30)
    cutoff_date.tzinfo
    logger.info("Cutoff date is {}".format(cutoff_date))
    engagements_to_delete = Engagement.objects.annotate(
        all_duplicates=~Exists(
            Finding.objects.filter(~Q(duplicate=True), test__engagement_id=OuterRef('pk'))
        ),
        has_no_note=~Exists(
            Finding.objects.filter(~Q(notes__isnull=True), test__engagement_id=OuterRef('pk'))
        ),
    ).filter(
        engagement_type='CI/CD',
        created__lt=cutoff_date,
        all_duplicates=True,
        has_no_note=True
    ).exclude(
        tagged_items__tag__name__contains=lock_tag
    )

    for engagement in engagements_to_delete:
        logger.info("Deleting engagement id {} ({})".format(engagement.id, engagement.name))
        _notify(engagement, "Engagement {} ({})- auto-deleted".format(engagement.id, engagement.name))
        engagement.delete()

    else:
        logger.debug("Automatic engagement deletion is not activated.")
