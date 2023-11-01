from django.core.exceptions import ValidationError
from dojo.models import Product_API_Scan_Configuration

from .api_client import MSDefenderAPI


class MSDefenderApiImporter(object):
    """
    Import from MSDefender API
    """

    config_id = "MSDefender API"

    def get_findings(self, test):
        client, config = self.prepare_client(test)
        findings = client.get_findings()
        return findings

    def prepare_client(self, test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = test.api_scan_configuration
            # Double check of config
            if config.product != product:
                raise ValidationError(
                    "API Scan Configuration for MSDefender API and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
                )
        else:
            configs = Product_API_Scan_Configuration.objects.filter(
                product=product,
                tool_configuration__tool_type__name=self.config_id,
            )
            if configs.count() == 1:
                config = configs.first()
            elif configs.count() > 1:
                raise ValidationError(
                    "More than one Product API Scan Configuration has been configured, but none of them has been "
                    "chosen.\nPlease specify at Test which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
            else:
                raise ValidationError(
                    "There are no API Scan Configurations for this Product.\n"
                    "Please add at least one API Scan Configuration for MSDefender API to this Product. "
                    f'Product: "{product.name}" ({product.id})'
                )

        tool_config = config.tool_configuration
        return MSDefenderAPI(tool_config), config
