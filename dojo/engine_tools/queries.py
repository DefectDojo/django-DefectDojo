# Utils
from django.conf import settings
from django.db.models import Q


# Tags filter for finding exclusion filters
exclusion_tags = settings.FINDING_EXCLUSION_FILTER_TAGS
priority_tags = settings.CELERY_CRON_PRIORITY_FILTER_TAGS
    
tag_list = exclusion_tags.split(",")
    
tag_filter = Q()
for tag in tag_list:
    tag_filter |= Q(tags__name__icontains=tag)
    
priority_tag_filter = Q()
for tag in priority_tags.split(","):
    priority_tag_filter |= Q(tags__name__icontains=tag)
