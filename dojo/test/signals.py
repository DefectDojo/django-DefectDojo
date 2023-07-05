import contextlib
from django.db.models import signals
from django.dispatch import receiver
import logging
from dojo.models import Test, Finding

logger = logging.getLogger(__name__)


@receiver(signals.pre_save, sender=Test)
def update_found_byt_for_findings(sender, instance, **kwargs):
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
