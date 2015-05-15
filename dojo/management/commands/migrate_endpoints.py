import re
from urlparse import urlsplit
from django.core.management.base import BaseCommand
from pytz import timezone
from dojo.models import Finding, Endpoint

import dojo.settings as settings
from django.forms import ValidationError
from django.core.validators import URLValidator, validate_ipv46_address, RegexValidator

locale = timezone(settings.TIME_ZONE)

"""
Authors: Jay Paz
Migrate Finding endpoint to endpoints which are a model of their own and can better provide reporting and metrics.
The field endpoint is now deprecated and wil be completely removed in version 1.0.3.
"""


class Command(BaseCommand):
    help = "Migrate Finding endpoint to endpoints which are a model of their own and can better provide reporting and" \
           "metrics. The field endpoint is now deprecated and wil be completely removed in version 1.0.3."
    # add any value you want excluded in this list, any value that includes these will be excluded as an endpoint
    exclude = []

    def create_endpoint(self, protocol, host, path, query, fragment, product, finding):
        try:
            endpoint, created = Endpoint.objects.get_or_create(protocol=protocol,
                                                               host=host.lower(),
                                                               path=path,
                                                               query=query,
                                                               fragment=fragment,
                                                               product=product)
        except:
            print '****************** UNABLE TO ADD ENDPOINT ******************'
            print protocol, host, path, query, fragment, product, finding
            print '************************************************************'

        if created:
            print "Endpoint created: ", endpoint

        finding.endpoints.add(endpoint)
        finding.save()

    def handle(self, *args, **options):
        findings = Finding.objects.all().order_by('id')
        for finding in findings:
            product = finding.test.engagement.product
            aes = re.findall(r'[^,;\s]+', finding.endpoint)
            aes += re.findall(r'[^,;\s]+', finding.description)
            set = {}
            affected_endpoints = [set.setdefault(e, e) for e in aes if
                                  e and len(e) > 5 and e not in set]
            endpoints_to_process = []
            for ae in affected_endpoints:
                ae = ae.strip()
                add = True
                if len(ae) < 7:
                    add = False
                    continue
                for ex in self.exclude:
                    if ex in ae:
                        add = False
                        break
                if add:
                    endpoints_to_process.append(ae)

            affected_endpoints = endpoints_to_process

            if affected_endpoints:
                for ae in affected_endpoints:
                    ae = ae.strip()
                    if ae.endswith(".") or ae.endswith('"'):
                        ae = ae[:-1]
                    port_re = "(:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"

                    try:
                        url_validator = URLValidator()
                        url_validator(ae)
                        protocol, host, path, query, fragment = urlsplit(ae)
                        self.create_endpoint(protocol, host, path, query, fragment, product, finding)
                    except ValidationError:
                        try:
                            # do we have a port number?
                            host = ae
                            regex = re.compile(port_re)
                            if regex.findall(ae):
                                for g in regex.findall(ae):
                                    host = re.sub(port_re, '', host)
                            validate_ipv46_address(host)
                            self.create_endpoint(None, ae, None, None, None, product, finding)
                        except ValidationError:
                            try:
                                regex = re.compile(
                                    # r'^(?:[a-z0-9\.\-]*)://'  # scheme is validated separately
                                    r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}(?<!-)\.?)|'  # domain...
                                    r'localhost|'  # localhost...
                                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
                                    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
                                    r'(?::\d+)?'  # optional port
                                    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
                                validate_hostname = RegexValidator(regex=regex)
                                # do we have a port number?
                                validate_hostname(host)
                                protocol, host, path, query, fragment = (None, ae, None, None, None)
                                if "/" in host or "?" in host or "#" in host:
                                    # add a fake protocol
                                    host_with_protocol = "http://" + host
                                    protocol, host, path, query, fragment = urlsplit(host_with_protocol)
                                self.create_endpoint(None, host, path, query, fragment, product, finding)
                            except:
                                pass
            # Will preserve old endpoint data in Description
            finding.description += "\n\n"
            finding.description += "Vulnerable Endpoints: \n"
            finding.description += finding.endpoint
            finding.save()








