
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from custom_field.models import CustomFieldValue, CustomField
from pytz import timezone

from dojo.models import DojoMeta, Product, Endpoint
from dojo.utils import get_system_setting

locale = timezone(get_system_setting('time_zone'))


class Command(BaseCommand):
    help = 'No input commands for dedupe findings.'

    def handle(self, *args, **options):
        ctp = ContentType.objects.get_for_model(Product.objects.all()[0])
        cte = ContentType.objects.get_for_model(Endpoint.objects.all()[0])
        legacy_meta_prod = CustomField.objects.filter(content_type=ctp)
        legacy_meta_ep = CustomField.objects.filter(content_type=cte)

        for cf in legacy_meta_prod:
            cfv = CustomFieldValue.objects.filter(field=cf,)
            dm = DojoMeta(name=cf.name, value=cfv.value, model_name='Product', model_id=cfv.object_id)
            dm.save()

        for cf in legacy_meta_ep:
            cfv = CustomFieldValue.objects.filter(field=cf,)
            dm = DojoMeta(name=cf.name, value=cfv.value, model_name='Endpoint', model_id=cfv.object_id)
            dm.save()
