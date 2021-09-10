import logging

from dojo.tools.cobalt_api.api_client import CobaltAPI

logger = logging.getLogger(__name__)


class CobaltApiImporter(object):
    """
    Import from Cobalt.io API
    """

    def get_findings(self, test):
        client, config = self.prepare_client(test)
        findings = client.get_findings(config.cobaltio_asset_id)
        return findings

    def prepare_client(self, test):
        product = test.engagement.product
        if test.cobaltio_config:
            config = test.cobaltio_config
            # Double check of config
            if config.product != product:
                raise Exception('Product Cobalt.io Configuration and "Product" mismatch')
        else:
            configs = product.cobaltio_product_set.filter(product=product)
            if configs.count() == 1:
                config = configs.first()
            elif configs.count() > 1:
                raise Exception(
                    'There is more than one Cobalt.io Configuration for this Product but none of them has been choosen.\n'
                    'Please specify at Test which one should be used.'
                )
            else:
                raise Exception(
                    'There are no Cobalt.io Configurations for this Product.\n'
                    'Please add at least one Cobalt.io Configuration to this Product.'
                )

        tool_config = config.cobaltio_tool_config
        return CobaltAPI(tool_config), config
