import Queue
import sys
import threading

from django.core.management import call_command
from django.core.management.base import BaseCommand

from dojo.models import Product, \
     Tool_Product_Settings, Endpoint, Tool_Product_History, \
     Engagement, Finding, Test_Type, Development_Environment, \
     Test, User, BurpRawRequestResponse, UserContactInfo
from dojo.tools.factory import import_parser_factory
from django.conf import settings
from dojo.utils import timezone, create_notification, prepare_for_view
from django.core.urlresolvers import reverse
from time import strftime

from urlparse import urlparse, urlunsplit, parse_qs
import requests, base64, subprocess, paramiko, StringIO, re, traceback


class Command(BaseCommand):
    help = "Details:\n\tExecutes an on-demand scan for a product-tool configuration for each endpoint of its connected product, or the cronjob to run all tool configurations associated with an engagament"

    def add_arguments(self, parser):
        parser.add_argument('-c', '--config', type=int, help='Provide an ID to execute an on-demand scan for a product-tool configuration', )
        parser.add_argument('-e', '--engagement', type=int, help='For an on-demand scan, you can provide an engagement ID to import the test result into', )

    def handle(self, *args, **options):
        ttid = options['config'] or 0
        eid = options['engagement'] or 0

        # Run the tool for a specific product-tool configuration ID, endpoint and engagement ID (0 = create one)
        def runTool(ttid, endpoint, eid):
            scan_settings = Tool_Product_Settings.objects.get(pk=ttid)
            tool_config = scan_settings.tool_configuration
            tool_config.password = prepare_for_view(tool_config.password)
            endpoint_url = urlunsplit((endpoint.protocol or 'http', endpoint.host, endpoint.path or '/', endpoint.query or '', endpoint.fragment or ''))
            dummy_user = User.objects.get(id=settings.TOOL_RUN_CONFIG['dummy-user'])

            if scan_settings.url == "" and scan_settings.tool_configuration:
                scan_settings.url = scan_settings.tool_configuration.url

            url_settings = urlparse(scan_settings.url)
            scan_history = Tool_Product_History(product=scan_settings, status="Pending", last_scan=timezone.now())

            if url_settings.scheme not in ["http", "https", "ssh"]:
                scan_history.status = "Failed"
                scan_history.save()
                self.stdout.write("Failed tool run for ID " + str(ttid) + " due to invalid URL scheme")
                return False
            elif settings.ALLOW_TOOL_RUN[url_settings.scheme] is False or (url_settings.scheme == "ssh" and url_settings.netloc == "localhost" and settings.ALLOW_TOOL_RUN["ssh-localhost"] is False):
                scan_history.status = "Denied"
                scan_history.save()
                self.stdout.write("Denied tool run for ID " + str(ttid) + " because " + url_settings.scheme + " connections for the specified host are disabled in settings.py")
                return False
            else:
                scan_history.status = "Running"
                scan_history.save()

            if tool_config.scan_type:
                if eid == 0:
                    engagement = Engagement()
                    product = Product.objects.get(id=scan_settings.product.id)
                    engagement.name = "RunTool Import - " + strftime("%a, %d %b %Y %X", timezone.now().timetuple())
                    engagement.threat_model = False
                    engagement.api_test = False
                    engagement.pen_test = False
                    engagement.check_list = False
                    engagement.target_start = timezone.now()
                    engagement.target_end = timezone.now()
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
                    target_start=timezone.now(),
                    target_end=timezone.now(),
                    environment=environment,
                    lead=dummy_user,
                    percent_complete=0)
                t.full_clean()
                t.save()

            result = ""
            if url_settings.scheme in ["http", "https"]:
                http_headers = {}

                if tool_config.authentication_type == "API":
                    http_headers = {settings.TOOL_RUN_CONFIG['http-api-header']: tool_config.api_key}
                elif tool_config.authentication_type == "Password":
                    http_headers = {"Authorization": base64.b64encode('%s:%s' % (tool_config.username, tool_config.password))}

                try:
                    result = requests.get(scan_settings.url, headers=http_headers).text
                except Exception as e:
                    self.stdout.write("Error during HTTP request: " + str(e))
                    result = ""

            # ssh://host/folder/file.extension?param connects to the host and runs the file in the query with the parameter provided
            elif url_settings.scheme == "ssh":
                call_params = [url_settings.path]

                if url_settings.query != "":
                    url_qs = parse_qs(url_settings.query)
                    for key, val in url_qs.iteritems():
                        call_params.append('--' + escapeshell(key) + '="' + escapeshell(val) + '"')

                if url_settings.fragment != "":
                    call_params.append(escapeshell(url_settings.fragment))

                call_params.append(endpoint_url)
                if settings.DEBUG:
                    self.stdout.write('Cmd: ' + ' '.join(call_params))

                # On localhost it is directly executed
                if url_settings.netloc == "localhost":
                    try:
                        result = subprocess.check_output(call_params)
                    except Exception as e:
                        self.stdout.write("Error during execution of ssh://localhost: " + str(e))
                        result = ""
                else:
                    # Otherwise we connect via SSH
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    sshPort = url_settings.port or 22

                    if tool_config.authentication_type == "Password":
                        try:
                            ssh_client.connect(url_settings.netloc, sshPort, tool_config.username, tool_config.password)
                        except Exception as e:
                            self.stdout.write(str(e))

                    elif tool_config.authentication_type == "SSH":
                        tool_config.ssh = prepare_for_view(tool_config.ssh)
                        sshKey = StringIO.StringIO(tool_config.ssh)

                        try:
                            key = paramiko.RSAKey.from_private_key(sshKey, tool_config.password)
                            ssh_client.connect(url_settings.netloc, sshPort, tool_config.username, pkey=key)
                        except Exception:
                            self.stdout.write("Private key is not a valid RSA key. Generate it via ssh-keygen -t rsa.")
                            self.stdout.write(str(e))

                    try:
                        stdin, stdout, stderr = ssh_client.exec_command(' '.join(call_params))
                        result = stdout.read().decode('ascii')
                        ssh_client.close()
                    except Exception:
                        result = ""

            if tool_config.scan_type:
                t.percent_complete = 100
                t.target_end = timezone.now()
                t.save()

            if result == "":
                scan_history.status = "Failed"
                scan_history.save()
                return False

            if not tool_config.scan_type:
                scan_history.status = "Completed"
                scan_history.save()
                self.stdout.write("No parsing enabled, so only echoing the result")
                self.stdout.write(result)
                return True

            if eid == 0:
                engagement.target_end = timezone.now()

            engagement.run_tool_test = True
            engagement.save()

            parse_result = StringIO.StringIO(result)
            try:
                parser = import_parser_factory(parse_result, t)
            except ValueError:
                self.stdout.write("Import of parser factory failed")
                return False

            try:
                finding_count = 0
                for item in parser.items:
                    sev = item.severity
                    if sev == 'Information' or sev == 'Informational':
                        sev = 'Info'

                    if Finding.SEVERITIES[sev] > Finding.SEVERITIES[settings.TOOL_RUN_CONFIG['min-severity']]:
                        continue

                    item.severity = sev
                    item.test = t
                    if item.date == timezone.now().date():
                        item.date = t.target_start

                    item.last_reviewed = timezone.now()
                    item.active = True
                    item.verified = False
                    item.reporter = dummy_user
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

                scan_history.status = "Completed"
                scan_history.save()

                create_notification(
                    event='results_added',
                    title=str(finding_count) + " findings for " + engagement.product.name,
                    finding_count=finding_count,
                    test=t,
                    engagement=engagement,
                    url=reverse('view_test', args=(t.id, )))
                return True

            except SyntaxError:
                scan_history.status = "Failed"
                scan_history.save()
                self.stdout.write('There appears to be an error in the report output, please check and try again.')
                return False

        # The execution is threaded. Each endpoint has their own thread.
        class threadedScan(threading.Thread):
            def __init__(self, scan_queue):
                threading.Thread.__init__(self)
                self.scan_queue = scan_queue

            def run(self):
                (ttid, endpoint, engagement) = self.scan_queue.get()
                try:
                    runTool(ttid, endpoint, engagement)
                except Exception as e:
                    print("Encountered exception during execution", e)
                    traceback.print_exc()
                self.scan_queue.task_done()

        # entry point for command
        # we need to make sure the user has the contactinfo set, otherwise it will crash during execution
        dummy_user = User.objects.get(id=settings.TOOL_RUN_CONFIG['dummy-user'])
        user_contact = UserContactInfo.objects.filter(user=settings.TOOL_RUN_CONFIG['dummy-user'])
        if len(user_contact) == 0:
            contact = UserContactInfo(user=dummy_user)
            contact.save()

        # differentiate between cronjob & on-demand scan
        if ttid == 0:
            # Cronjob for all open and scheduled engagements
            engagements = Engagement.objects.exclude(run_tool_test_engine=None).filter(run_tool_test=False, target_start__lte=timezone.now().date())
            if len(engagements) <= 0:
                self.stdout.write("No engagements open to start")
                sys.exit(0)

            scan_queue = Queue.Queue()
            for engagement in engagements:
                ttid = engagement.run_tool_test_engine.id
                eid = engagement.id

                endpoints = Endpoint.objects.filter(product=engagement.product.id, export_tool=True)
                if len(endpoints) <= 0:
                    self.stdout.write("Product-Tool config can't be executed because the product " + str(engagement.product.id)+" has no endpoints configured that are provided to tool runs.")
                else:
                    self.stdout.write("Started for product " + str(engagement.product.id))

            scan_queue.join()

        else:
            # On-demand scan for single product-tool config
            scSettings = Tool_Product_Settings.objects.filter(pk=ttid)
            if len(scSettings) <= 0:
                self.stdout.write("Product-Tool Configuration ID not found.")
                sys.exit(0)

            if not scSettings[0].tool_configuration.scan_type:
                self.stdout.write("Warning: This product tool configuration has no parsing configured.")

            endpoints = Endpoint.objects.filter(product=scSettings[0].product.id, export_tool=True)
            if len(endpoints) <= 0:
                self.stdout.write("Connected product has no endpoints configured that are provided to tool runs.")
                sys.exit(0)

            if eid > 0:
                engagement = Engagement.objects.filter(id=eid)
                if len(engagement) <= 0:
                    self.stdout.write("Engagement ID invalid. Use 0 if you don't want to add it to a specific one and instead create a new one.")
                    sys.exit(0)

            scan_queue = Queue.Queue()
            for e in endpoints:
                scan_queue.put((ttid, e, eid))
                t = threadedScan(scan_queue)
                t.setDaemon(True)
                t.start()

            scan_queue.join()


def run_on_demand_scan(ttid, eid):
    call_command('run_tool', config=int(ttid), engagement=int(eid))
    return True


# Python 2.7 doesn't have a good way to escape shell arguments
def escapeshell(string):
    return re.sub('[^\w \-_/:.]', '', string)
