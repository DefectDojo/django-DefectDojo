import Queue
from datetime import datetime
import sys
import threading

from django.core.mail import send_mail
from django.core.management import call_command
from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Product, Tool_Product_Settings, Endpoint, Tool_Product_History, Engagement, Finding
from dojo.tools.factory import import_parser_factory
from django.conf import settings
from dojo.utils import get_system_setting

from urlparse import urlunparse
import requests, base64, subprocess, paramiko, StringIO

locale = timezone(get_system_setting('time_zone'))

class Command(BaseCommand):
    help = "Details:\n\tRuns product-tool configuration for each endpoint of its connected product\n\nArguments:\n\tID of Product-Tool configuration\n\tID of engagement"

    def add_arguments(self, parser):
        parser.add_argument('ttid', type=int, help="ID of product-tool configuration")
        parser.add_argument('eid', type=int, help="ID of engagement or 0 for none")

    def handle(self, *args, **options):
        ttid = options['ttid']
        eid = options['eid']

        # Run the tool for a specific product-tool configuration, endpoint and engagement
        def runTool(ttid, endpoint, eid):
            scan_settings = Tool_Product_Settings.objects.filter(pk=ttid)
            tool_config = scan_settings.tool_configuration

            if scan_settings.url == "" and scan_settings.tool_configuration:
                scan_settings.url = scan_settings.tool_configuration.url

            # write to Tool_Product_History
            url_settings = urlparse(scan_settings.url)
            scan_history = Tool_Product_History(product=scan_settings.id, status="Pending", last_scan=timezone.now())
            
            if url_settings.scheme not in ["http", "https", "ssh"]:
                scan_history.status = "Failed"
                scan_history.save()
                print("Failed scan for ID " + ttid + " due to invalid URL scheme")
                return False
            else:
                scan_history.status = "Running"
                scan_history.save()

            if eid == 0:
                engagement = Engagement()
                product = Product.objects.get(id=scan_settings.product.id)
                engagement.name = "RunTool Import - " + strftime("%a, %d %b %Y %X", timezone.now().timetuple())
                engagement.threat_model = False
                engagement.api_test = False
                engagement.pen_test = False
                engagement.check_list = False
                engagement.target_start = timezone.now().date()
                engagement.target_end = timezone.now().date()
                engagement.product = product
                engagement.active = True
                engagement.status = 'In Progress'
                engagement.save()
            else:
                engagement = Engagement.objects.get(id=eid)

            tt, t_created = Test_Type.objects.get_or_create(name=tool_config.scan_type)
            # will save in development environment
            environment, env_created = Development_Environment.objects.get_or_create(name="Development")
            t = Test(
                engagement=engagement,
                test_type=tt,
                target_start=timezone.now().date(),
                environment=environment,
                percent_complete=0)
            t.full_clean()
            t.save()

            result = ""
            if url_settings.scheme in ["http", "https"]:
                http_headers = {}

                if tool_config.authentication_type == "API":
                    http_headers = {"APIKEY": scan_settings.tool_configuration.api_key}
                elif tool_config.authentication_type == "Password":
                    http_headers = {"Authorization": base64.b64encode('%s:%s' % (tool_config.username, tool_config.password))}

                result = requests.get(scan_settings.url, headers=headers)

            # ssh://host/folder/file.extension?param connects to the host and runs the file in the query with the parameter provided
            elif url_settings.scheme == "ssh":
                # On localhost it is directly executed
                if url_settings.netloc == "localhost":
                    result = subprocess.check_output([url_settings.path, url_settings.query, url_settings.fragment])
                else:
                    # Otherwise we connect via SSH
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    if url_settings.port == None:
                        url_settings.port = 22

                    if tool_config.authentication_type == "Password":
                        try:
                            client.connect(url_settings.netloc, url_settings.port, tool_config.username, tool_config.password)
                        except (BadHostKeyException, AuthenticationException, SSHException, socket.error) as e:
                            print(e)
                            scan_history.status = "Failed"
                            scan_history.save()
                            return False

                    elif tool_config.authentication_type == "SSH":
                        sshKey = StringIO.StringIO(tool_config.ssh)

                        try:
                            key = paramiko.RSAKey.from_private_key_file(sshKey)
                        except paramiko.PasswordRequiredException:
                            key = paramiko.RSAKey.from_private_key_file(sshKey, password)
                        
                        try:
                            client.connect(host=url_settings.netloc, port=url_settings.port, username=tool_config.username, pkey=key)
                        except (BadHostKeyException, AuthenticationException, SSHException, socket.error) as e:
                            print(e)
                            scan_history.status = "Failed"
                            scan_history.save()
                            return False

                        stdin, stdout, stderr = client.exec_command(url_settings.path+" "+url_settings.query+" "+url_settings.fragment)
                        result = stdout.readlines()

            scan_history.status = "Success"
            scan_history.save()
            t.percent_complete = 100
            t.save()

            parse_result = StringIO.StringIO(result)
            try:
                parser = import_parser_factory(parse_result, t)
            except ValueError:
                print("Import of parser factory failed")
                return False

            try:
                for item in parser.items:
                    sev = item.severity
                    if sev == 'Information' or sev == 'Informational':
                        sev = 'Info'

                    item.severity = sev
                    item.test = t
                    if item.date == timezone.now().date():
                        item.date = t.target_start

                    item.last_reviewed = timezone.now()
                    item.active = active
                    item.verified = False
                    item.save(dedupe_option=False)

                    if hasattr(item, 'unsaved_req_resp') and len(
                            item.unsaved_req_resp) > 0:
                        for req_resp in item.unsaved_req_resp:
                            burp_rr = BurpRawRequestResponse(
                                finding=item,
                                burpRequestBase64=req_resp["req"],
                                burpResponseBase64=req_resp["resp"],
                            )
                            burp_rr.clean()
                            burp_rr.save()

                    if item.unsaved_request is not None and item.unsaved_response is not None:
                        burp_rr = BurpRawRequestResponse(
                            finding=item,
                            burpRequestBase64=item.unsaved_request,
                            burpResponseBase64=item.unsaved_response,
                        )
                        burp_rr.clean()
                        burp_rr.save()

                    for endpoint in item.unsaved_endpoints:
                        ep, created = Endpoint.objects.get_or_create(
                            protocol=endpoint.protocol,
                            host=endpoint.host,
                            path=endpoint.path,
                            query=endpoint.query,
                            fragment=endpoint.fragment,
                            product=t.engagement.product)

                        item.endpoints.add(ep)
                    item.save()

                    if item.unsaved_tags is not None:
                        item.tags = item.unsaved_tags

                    finding_count += 1

                create_notification(
                    event='results_added',
                    title=str(finding_count) + " findings for " + engagement.product.name,
                    finding_count=finding_count,
                    test=t,
                    engagement=engagement,
                    url=request.build_absolute_uri(
                        reverse('view_test', args=(t.id, ))))
                return True

            except SyntaxError:
                print('There appears to be an error in the XML report, please check and try again.')
                return False

        # The execution is threaded. Each endpoint has their own thread.
        class threadedScan(threading.Thread):
            def __init__(self, scan_queue):
                threading.Thread.__init__(self)
                self.scan_queue = scan_queue

            def run(self):
                (ttid, endpoint, engagement) = self.scan_queue.get()
                runTool(ttid, endpoint, engagement)
                self.scan_queue.task_done()

        if not options:
            print("Must specify an argument: Product-Tool Configuration ID.")
            sys.exit(0)

        scSettings = Tool_Product_Settings.objects.filter(pk=ttid)
        if len(scSettings) <= 0:
            print("Product-Tool Configuration ID not found.")
            sys.exit(0)

        endpoints = Endpoint.objects.filter(product=scSettings.product.id)
        if len(endpoints) <= 0:
            print("Connected product has no endpoints configured that are tagged with `tool_export`.")
            sys.exit(0)
        
        if eid > 0:
            engagement = Engagement.objects.filter(id=eid)
            if len(engagement) <= 0:
                print("Engagement ID invalid. Use 0 if you don't want to add it to a specific one.")
                sys.exit(0)

        scan_queue = Queue.Queue()
        has_exportable = False
        for e in endpoints:
            tags = e.endpoint_params.tags.objects.filter(value="tool-export")

            if len(endpoints) > 0:
                scan_queue.put((ttid, e, eid))
                t = threadedScan(scan_queue)
                t.setDaemon(True)
                t.start()

        scan_queue.join()


def run_on_demand_scan(ttid):
    call_command('run_tool', ttid)
    return True
