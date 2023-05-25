#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et
#
# linksys.py -- program settings on a Linkys router
#
# This tool is designed to help you recover from the occasional episodes
# of catatonia that afflict Linksys boxes. It allows you to batch-program
# them rather than manually entering values to the Web interface.  Commands
# are taken from the command line first, then standard input.
#
# The somewhat spotty coverage of status queries is because I only did the
# ones that were either (a) easy, or (b) necessary.  If you want to know the
# status of the box, look at the web interface.
#
# This code has been tested against the following hardware:
#
#   Hardware    Firmware
#   ----------  ---------------------
#   BEFW11S4v2  1.44.2.1, Dec 20 2002
#
# The code is, of course, sensitive to changes in the names of CGI pages
# and field names.
#
# Note: to make the no-arguments form work, you'll need to have the following
# entry in your ~/.netrc file.  If you have changed the router IP address or
# name/password, modify accordingly.
#
# machine 192.168.1.1
#   login ""
#   password admin
#
# By Eric S. Raymond, August April 2003.  All rites reversed.

import sys, re, curl, exceptions

def print_stderr(arg):
    sys.stderr.write(arg)
    sys.stderr.write("\n")

class LinksysError(exceptions.Exception):
    def __init__(self, *args):
        self.args = args

class LinksysSession:
    months = 'Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec'

    WAN_CONNECT_AUTO = '1'
    WAN_CONNECT_STATIC = '2'
    WAN_CONNECT_PPOE = '3'
    WAN_CONNECT_RAS = '4'
    WAN_CONNECT_PPTP = '5'
    WAN_CONNECT_HEARTBEAT = '6'

    # Substrings to check for on each page load.
    # This may enable us to detect when a firmware change has hosed us.
    check_strings = {
        "":           "basic setup functions",
        "Passwd.htm": "For security reasons,",
        "DHCP.html":  "You can configure the router to act as a DHCP",
        "Log.html":   "There are some log settings and lists in this page.",
        "Forward.htm":"Port forwarding can be used to set up public services",
        }

    def __init__(self):
        self.actions = []
        self.host = "http://192.168.1.1"
        self.verbosity = False
        self.pagecache = {}

    def set_verbosity(self, flag):
        self.verbosity = flag

    # This is not a performance hack -- we need the page cache to do
    # sanity checks at configure time.
    def cache_load(self, page):
        if page not in self.pagecache:
            fetch = curl.Curl(self.host)
            fetch.set_verbosity(self.verbosity)
            fetch.get(page)
            self.pagecache[page] = fetch.body()
            if fetch.answered("401"):
                raise LinksysError("authorization failure.", True)
            elif not fetch.answered(LinksysSession.check_strings[page]):
                del self.pagecache[page]
                raise LinksysError("check string for page %s missing!" % os.path.join(self.host, page), False)
            fetch.close()
    def cache_flush(self):
        self.pagecache = {}

    # Primitives
    def screen_scrape(self, page, template):
        self.cache_load(page)
        match = re.compile(template).search(self.pagecache[page])
        if match:
            result = match.group(1)
        else:
            result = None
        return result
    def get_MAC_address(self, page, prefix):
        return self.screen_scrape("", prefix+r":[^M]*\(MAC Address: *([^)]*)")
    def set_flag(self, page, flag, value):
        if value:
            self.actions.append(page, flag, "1")
        else:
            self.actions.append(page, flag, "0")
    def set_IP_address(self, page, cgi, role, ip):
        ind = 0
        for octet in ip.split("."):
            self.actions.append(("", "F1", role + repr(ind+1), octet))
            ind += 1

    # Scrape configuration data off the main page
    def get_firmware_version(self):
        # This is fragile.  There is no distinguishing tag before the firmware
        # version, so we have to key off the pattern of the version number.
        # Our model is ">1.44.2.1, Dec 20 2002<"
        return self.screen_scrape("", ">([0-9.v]*, (" + \
                                  LinksysSession.months + ")[^<]*)<", )
    def get_LAN_MAC(self):
        return self.get_MAC_address("", r"LAN IP Address")
    def get_Wireless_MAC(self):
        return self.get_MAC_address("", r"Wireless")
    def get_WAN_MAC(self):
        return self.get_MAC_address("", r"WAN Connection Type")

    # Set configuration data on the main page
    def set_host_name(self, name):
        self.actions.append(("", "hostName", name))
    def set_domain_name(self, name):
        self.actions.append(("", "DomainName", name))
    def set_LAN_IP(self, ip):
        self.set_IP_address("", "ipAddr", ip)
    def set_LAN_netmask(self, ip):
        if not ip.startswith("255.255.255."):
            raise ValueError
        lastquad = ip.split(".")[-1]
        if lastquad not in ("0", "128", "192", "240", "252"):
            raise ValueError
        self.actions.append("", "netMask", lastquad)
    def set_wireless(self, flag):
        self.set_flag("", "wirelessStatus")
    def set_SSID(self, ssid):
        self.actions.append(("", "wirelessESSID", ssid))
    def set_SSID_broadcast(self, flag):
        self.set_flag("", "broadcastSSID")
    def set_channel(self, channel):
        self.actions.append(("", "wirelessChannel", channel))
    def set_WEP(self, flag):
        self.set_flag("", "WepType")
    # FIXME: Add support for setting WEP keys
    def set_connection_type(self, type):
        self.actions.append(("", "WANConnectionType", type))
    def set_WAN_IP(self, ip):
        self.set_IP_address("", "aliasIP", ip)
    def set_WAN_netmask(self, ip):
        self.set_IP_address("", "aliasMaskIP", ip)
    def set_WAN_gateway_address(self, ip):
        self.set_IP_address("", "routerIP", ip)
    def set_DNS_server(self, index, ip):
        self.set_IP_address("", "dns" + "ABC"[index], ip)

    # Set configuration data on the password page
    def set_password(self, str):
        self.actions.append("Passwd.htm","sysPasswd", str)
        self.actions.append("Passwd.htm","sysPasswdConfirm", str)
    def set_UPnP(self, flag):
        self.set_flag("Passwd.htm", "UPnP_Work")
    def reset(self):
        self.actions.append("Passwd.htm", "FactoryDefaults")

    # DHCP features
    def set_DHCP(self, flag):
        if flag:
            self.actions.append("DHCP.htm","dhcpStatus","Enable")
        else:
            self.actions.append("DHCP.htm","dhcpStatus","Disable")
    def set_DHCP_starting_IP(self, val):
        self.actions.append("DHCP.htm","dhcpS4", str(val))
    def set_DHCP_users(self, val):
        self.actions.append("DHCP.htm","dhcpLen", str(val))
    def set_DHCP_lease_time(self, val):
        self.actions.append("DHCP.htm","leaseTime", str(val))
    def set_DHCP_DNS_server(self, index, ip):
        self.set_IP_address("DHCP.htm", "dns" + "ABC"[index], ip)
    # FIXME: add support for setting WINS key

    # Logging features
    def set_logging(self, flag):
        if flag:
            self.actions.append("Log.htm", "rLog", "Enable")
        else:
            self.actions.append("Log.htm", "rLog", "Disable")
    def set_log_address(self, val):
        self.actions.append("DHCP.htm","trapAddr3", str(val))

    # The AOL parental control flag is not supported by design.

    # FIXME: add Filters and other advanced features

    def configure(self):
        "Write configuration changes to the Linksys."
        if self.actions:
            fields = []
            self.cache_flush()
            for (page, field, value) in self.actions:
                self.cache_load(page)
                if self.pagecache[page].find(field) == -1:
                    print_stderr("linksys: field %s not found where expected in page %s!" % (field, os.path.join(self.host, page)))
                    continue
                else:
                    fields.append((field, value))
            # Clearing the action list before fieldsping is deliberate.
            # Otherwise we could get permanently wedged by a 401.
            self.actions = []
            transaction = curl.Curl(self.host)
            transaction.set_verbosity(self.verbosity)
            transaction.get("Gozila.cgi", tuple(fields))
            transaction.close()

if __name__ == "__main__":
    import os, cmd

    class LinksysInterpreter(cmd.Cmd):
        """Interpret commands to perform LinkSys programming actions."""
        def __init__(self):
            cmd.Cmd.__init__(self)
            self.session = LinksysSession()
            if os.isatty(0):
                print("Type ? or `help' for help.")
                self.prompt = self.session.host + ": "
            else:
                self.prompt = ""
                print("Bar1")

        def flag_command(self, func, line):
            if line.strip() in ("on", "enable", "yes"):
                func(True)
            elif line.strip() in ("off", "disable", "no"):
                func(False)
            else:
                print_stderr("linksys: unknown switch value")
            return 0

        def do_connect(self, line):
            newhost = line.strip()
            if newhost:
                self.session.host = newhost
                self.session.cache_flush()
                self.prompt = self.session.host + ": "
            else:
                print(self.session.host)
            return 0
        def help_connect(self):
            print("Usage: connect [<hostname-or-IP>]")
            print("Connect to a Linksys by name or IP address.")
            print("If no argument is given, print the current host.")

        def do_status(self, line):
            self.session.cache_load("")
            if "" in self.session.pagecache:
                print("Firmware:", self.session.get_firmware_version())
                print("LAN MAC:", self.session.get_LAN_MAC())
                print("Wireless MAC:", self.session.get_Wireless_MAC())
                print("WAN MAC:", self.session.get_WAN_MAC())
                print(".")
            return 0
        def help_status(self):
            print("Usage: status")
            print("The status command shows the status of the Linksys.")
            print("It is mainly useful as a sanity check to make sure")
            print("the box is responding correctly.")

        def do_verbose(self, line):
            self.flag_command(self.session.set_verbosity, line)
        def help_verbose(self):
            print("Usage: verbose {on|off|enable|disable|yes|no}")
            print("Enables display of HTTP requests.")

        def do_host(self, line):
            self.session.set_host_name(line)
            return 0
        def help_host(self):
            print("Usage: host <hostname>")
            print("Sets the Host field to be queried by the ISP.")

        def do_domain(self, line):
            print("Usage: host <domainname>")
            self.session.set_domain_name(line)
            return 0
        def help_domain(self):
            print("Sets the Domain field to be queried by the ISP.")

        def do_lan_address(self, line):
            self.session.set_LAN_IP(line)
            return 0
        def help_lan_address(self):
            print("Usage: lan_address <ip-address>")
            print("Sets the LAN IP address.")

        def do_lan_netmask(self, line):
            self.session.set_LAN_netmask(line)
            return 0
        def help_lan_netmask(self):
            print("Usage: lan_netmask <ip-mask>")
            print("Sets the LAN subnetwork mask.")

        def do_wireless(self, line):
            self.flag_command(self.session.set_wireless, line)
            return 0
        def help_wireless(self):
            print("Usage: wireless {on|off|enable|disable|yes|no}")
            print("Switch to enable or disable wireless features.")

        def do_ssid(self, line):
            self.session.set_SSID(line)
            return 0
        def help_ssid(self):
            print("Usage: ssid <string>")
            print("Sets the SSID used to control wireless access.")

        def do_ssid_broadcast(self, line):
            self.flag_command(self.session.set_SSID_broadcast, line)
            return 0
        def help_ssid_broadcast(self):
            print("Usage: ssid_broadcast {on|off|enable|disable|yes|no}")
            print("Switch to enable or disable SSID broadcast.")

        def do_channel(self, line):
            self.session.set_channel(line)
            return 0
        def help_channel(self):
            print("Usage: channel <number>")
            print("Sets the wireless channel.")

        def do_wep(self, line):
            self.flag_command(self.session.set_WEP, line)
            return 0
        def help_wep(self):
            print("Usage: wep {on|off|enable|disable|yes|no}")
            print("Switch to enable or disable WEP security.")

        def do_wan_type(self, line):
            try:
                type=eval("LinksysSession.WAN_CONNECT_"+line.strip().upper())
                self.session.set_connection_type(type)
            except ValueError:
                print_stderr("linksys: unknown connection type.")
            return 0
        def help_wan_type(self):
            print("Usage: wan_type {auto|static|ppoe|ras|pptp|heartbeat}")
            print("Set the WAN connection type.")

        def do_wan_address(self, line):
            self.session.set_WAN_IP(line)
            return 0
        def help_wan_address(self):
            print("Usage: wan_address <ip-address>")
            print("Sets the WAN IP address.")

        def do_wan_netmask(self, line):
            self.session.set_WAN_netmask(line)
            return 0
        def help_wan_netmask(self):
            print("Usage: wan_netmask <ip-mask>")
            print("Sets the WAN subnetwork mask.")

        def do_wan_gateway(self, line):
            self.session.set_WAN_gateway(line)
            return 0
        def help_wan_gateway(self):
            print("Usage: wan_gateway <ip-address>")
            print("Sets the LAN subnetwork mask.")

        def do_dns(self, line):
            (index, address) = line.split()
            if index in ("1", "2", "3"):
                self.session.set_DNS_server(eval(index), address)
            else:
                print_stderr("linksys: server index out of bounds.")
            return 0
        def help_dns(self):
            print("Usage: dns {1|2|3} <ip-mask>")
            print("Sets a primary, secondary, or tertiary DNS server address.")

        def do_password(self, line):
            self.session.set_password(line)
            return 0
        def help_password(self):
            print("Usage: password <string>")
            print("Sets the router password.")

        def do_upnp(self, line):
            self.flag_command(self.session.set_UPnP, line)
            return 0
        def help_upnp(self):
            print("Usage: upnp {on|off|enable|disable|yes|no}")
            print("Switch to enable or disable Universal Plug and Play.")

        def do_reset(self, line):
            self.session.reset()
        def help_reset(self):
            print("Usage: reset")
            print("Reset Linksys settings to factory defaults.")

        def do_dhcp(self, line):
            self.flag_command(self.session.set_DHCP, line)
        def help_dhcp(self):
            print("Usage: dhcp {on|off|enable|disable|yes|no}")
            print("Switch to enable or disable DHCP features.")

        def do_dhcp_start(self, line):
            self.session.set_DHCP_starting_IP(line)
        def help_dhcp_start(self):
            print("Usage: dhcp_start <number>")
            print("Set the start address of the DHCP pool.")

        def do_dhcp_users(self, line):
            self.session.set_DHCP_users(line)
        def help_dhcp_users(self):
            print("Usage: dhcp_users <number>")
            print("Set number of address slots to allocate in the DHCP pool.")

        def do_dhcp_lease(self, line):
            self.session.set_DHCP_lease(line)
        def help_dhcp_lease(self):
            print("Usage: dhcp_lease <number>")
            print("Set number of address slots to allocate in the DHCP pool.")

        def do_dhcp_dns(self, line):
            (index, address) = line.split()
            if index in ("1", "2", "3"):
                self.session.set_DHCP_DNS_server(eval(index), address)
            else:
                print_stderr("linksys: server index out of bounds.")
            return 0
        def help_dhcp_dns(self):
            print("Usage: dhcp_dns {1|2|3} <ip-mask>")
            print("Sets primary, secondary, or tertiary DNS server address.")

        def do_logging(self, line):
            self.flag_command(self.session.set_logging, line)
        def help_logging(self):
            print("Usage: logging {on|off|enable|disable|yes|no}")
            print("Switch to enable or disable session logging.")

        def do_log_address(self, line):
            self.session.set_Log_address(line)
        def help_log_address(self):
            print("Usage: log_address <number>")
            print("Set the last quad of the address to which to log.")

        def do_configure(self, line):
            self.session.configure()
            return 0
        def help_configure(self):
            print("Usage: configure")
            print("Writes the configuration to the Linksys.")

        def do_cache(self, line):
            print(self.session.pagecache)
        def help_cache(self):
            print("Usage: cache")
            print("Display the page cache.")

        def do_quit(self, line):
            return 1
        def help_quit(self, line):
            print("The quit command ends your linksys session without")
            print("writing configuration changes to the Linksys.")
        def do_EOF(self, line):
            print("")
            self.session.configure()
            return 1
        def help_EOF(self):
            print("The EOF command writes the configuration to the linksys")
            print("and ends your session.")

        def default(self, line):
            """Pass the command through to be executed by the shell."""
            os.system(line)
            return 0

        def help_help(self):
            print("On-line help is available through this command.")
            print("? is a convenience alias for help.")

        def help_introduction(self):
            print("""\

This program supports changing the settings on Linksys blue-box routers.  This
capability may come in handy when they freeze up and have to be reset.  Though
it can be used interactively (and will command-prompt when standard input is a
terminal) it is really designed to be used in batch mode. Commands are taken
from the command line first, then standard input.

By default, it is assumed that the Linksys is at http://192.168.1.1, the
default LAN address.  You can connect to a different address or IP with the
'connect' command.  Note that your .netrc must contain correct user/password
credentials for the router.  The entry corresponding to the defaults is:

machine 192.168.1.1
    login ""
    password admin

Most commands queue up changes but don't actually send them to the Linksys.
You can force pending changes to be written with 'configure'.  Otherwise, they
will be shipped to the Linksys at the end of session (e.g.  when the program
running in batch mode encounters end-of-file or you type a control-D).  If you
end the session with `quit', pending changes will be discarded.

For more help, read the topics 'wan', 'lan', and 'wireless'.""")

        def help_lan(self):
            print("""\
The `lan_address' and `lan_netmask' commands let you set the IP location of
the Linksys on your LAN, or inside.  Normally you'll want to leave these
untouched.""")

        def help_wan(self):
            print("""\
The WAN commands become significant if you are using the BEFSR41 or any of
the other Linksys boxes designed as DSL or cable-modem gateways.  You will
need to use `wan_type' to declare how you expect to get your address.

If your ISP has issued you a static address, you'll need to use the
`wan_address', `wan_netmask', and `wan_gateway' commands to set the address
of the router as seen from the WAN, the outside. In this case you will also
need to use the `dns' command to declare which remote servers your DNS
requests should be forwarded to.

Some ISPs may require you to set host and domain for use with dynamic-address
allocation.""")

        def help_wireless_desc(self):
            print("""\
The channel, ssid, ssid_broadcast, wep, and wireless commands control
wireless routing.""")

        def help_switches(self):
            print("Switches may be turned on with 'on', 'enable', or 'yes'.")
            print("Switches may be turned off with 'off', 'disable', or 'no'.")
            print("Switch commands include: wireless, ssid_broadcast.")

        def help_addresses(self):
            print("An address argument must be a valid IP address;")
            print("four decimal numbers separated by dots, each ")
            print("between 0 and 255.")

        def emptyline(self):
            pass

    interpreter = LinksysInterpreter()
    for arg in sys.argv[1:]:
        interpreter.onecmd(arg)
    fatal = False
    while not fatal:
        try:
            interpreter.cmdloop()
            fatal = True
        except LinksysError:
            message, fatal = sys.exc_info()[1].args
            print("linksys: " + message)

# The following sets edit modes for GNU EMACS
# Local Variables:
# mode:python
# End:
