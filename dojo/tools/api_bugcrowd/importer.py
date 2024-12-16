import logging

from django.core.exceptions import ValidationError

from dojo.models import Product_API_Scan_Configuration

from .api_client import BugcrowdAPI

logger = logging.getLogger(__name__)


class BugcrowdApiImporter:

    """Import from Bugcrowd API"""

    def get_findings(self, test):
        client, config = self.prepare_client(test)
        logger.debug(
            f"Fetching submissions program {str(config.service_key_1)} and target {str(config.service_key_2)}",
        )

        submissions_paged = client.get_findings(
            config.service_key_1,
            config.service_key_2,
        )

        submissions = []
        counter = 0
        for page in submissions_paged:
            submissions += page
            counter += 1
        logger.debug(f"{counter} Bugcrowd submissions pages fetched")

        return submissions, config

    def prepare_client(self, test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = test.api_scan_configuration
            # Double check of config
            if config.product != product:
                msg = (
                    "API Scan Configuration for Bugcrowd API and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
                )
                raise ValidationError(msg)
        else:
            configs = Product_API_Scan_Configuration.objects.filter(
                product=product,
                tool_configuration__tool_type__name="Bugcrowd API",
            )
            if configs.count() == 1:
                config = configs.first()
            elif configs.count() > 1:
                msg = (
                    "More than one Product API Scan Configuration has been configured, but none of them has been "
                    "chosen. Please specify at Test which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)
            else:
                msg = (
                    "There are no API Scan Configurations for this Product. "
                    "Please add at least one API Scan Configuration for bugcrowd to this Product. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)

        tool_config = config.tool_configuration
        return BugcrowdAPI(tool_config), config
