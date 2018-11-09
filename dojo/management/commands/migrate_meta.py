
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from custom_field.models import CustomFieldValue
from pytz import timezone

from dojo.models import DojoMeta, Product, Endpoint
from dojo.utils import get_system_setting

locale = timezone(get_system_setting('time_zone'))


class Command(BaseCommand):
    help = 'No input commands for dedupe findings.'

    def handle(self, *args, **options):
        ctp = ContentType.objects.get_for_model(Product)
        cte = ContentType.objects.get_for_model(Endpoint)

        for cfv in CustomFieldValue.objects.filter(field__content_type=ctp):
            DojoMeta.objects.create(
                product_id=cfv.object_id,
                name=cfv.field.name,
                value=cfv.value)

        for cfv in CustomFieldValue.objects.filter(field__content_type=cte):
            DojoMeta.objects.create(
                endpoint_id=cfv.object_id,
                name=cfv.field.name,
                value=cfv.value)
