from django.core.exceptions import ValidationError
from dojo.models import Product_API_Scan_Configuration

from .api_client import BlackduckAPI


class BlackduckApiImporter(object):
    """
    Import from BlackDuck API
    """

    config_id = "BlackDuck API"

    def get_findings(self, test):
        client, config = self.prepare_client(test)
        project = client.get_project_by_name(config.service_key_1)
        version = client.get_version_by_name(project, config.service_key_2)
        return client.get_vulnerable_bom_components(version)

    def prepare_client(self, test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = test.api_scan_configuration
            # Double check of config
            if config.product != product:
                raise ValidationError(
                    f'API Scan Configuration for "{self.config_id}" and Product do not match. '
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
                    "chosen. Please specify at Test which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
            else:
                raise ValidationError(
                    "There are no API Scan Configurations for this Product. Please add at least one API Scan "
                    f'Configuration for "{self.config_id}" to this Product. '
                    f'Product: "{product.name}" ({product.id})'
                )

        tool_config = config.tool_configuration
        return BlackduckAPI(tool_config), config
