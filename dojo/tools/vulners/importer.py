import logging
from django.core.exceptions import ValidationError
from dojo.models import Product_API_Scan_Configuration
from dojo.tools.vulners.api_client import VulnersAPI

logger = logging.getLogger(__name__)


class VulnersImporter(object):
    """
    Import from Vulners API
    """

    def get_findings(self, test):
        client, config = self.prepare_client(test)
        findings = client.get_findings()
        return findings

    def get_vulns_description(self, test, vulns_id):
        client, config = self.prepare_client(test)
        description = client.get_vulns_description(vulns_id)
        return description

    def prepare_client(self, test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = test.api_scan_configuration
            # Double check of config
            if config.product != product:
                raise ValidationError('API Scan Configuration for Vulners API and Product do not match.')
        else:
            configs = Product_API_Scan_Configuration.objects.filter(product=product, tool_configuration__tool_type__name='Vulners')
            if configs.count() == 1:
                config = configs.first()
            elif configs.count() > 1:
                raise ValidationError(
                    'More than one Product API Scan Configuration has been configured, but none of them has been chosen. Please specify at Test which one should be used.'
                )
            else:
                raise ValidationError(
                    'There are no API Scan Configurations for this Product. Please add at least one API Scan Configuration for Vulners to this Product.'
                )

        tool_config = config.tool_configuration
        return VulnersAPI(tool_config), config
