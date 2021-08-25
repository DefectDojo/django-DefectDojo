from django.core.management.base import BaseCommand


"""
Author: Josh Hewing and Michael Chen- This script will solve issue #3666 by checking for deduplication configuration at startup
"""


class Command(BaseCommand):
    for each_var in HASHCODE_FIELDS_PER_SCANNER:
        for each_ind in each_var:
            if each_ind not in HASHCODE_ALLOWED_FIELDS:
                deduplicationLogger.error("compute_hash_code - configuration error: some elements of HASHCODE_FIELDS_PER_SCANNER are not in the allowed list HASHCODE_ALLOWED_FIELDS. " "Using default fields")
