#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et
#
# sfquery -- Source Forge query script using the ClientCGI high-level interface
#
# Retrieves a SourceForge XML export object for a given project.
# Specify the *numeric* project ID. the user name, and the password,
# as arguments. If you have a valid ~/.netrc entry for sourceforge.net,
# you can just give the project ID.
#
# By Eric S. Raymond, August 2002.  All rites reversed.

import sys, netrc
import curl

class SourceForgeUserSession(curl.Curl):
    # SourceForge-specific methods.  Sensitive to changes in site design.
    def login(self, name, password):
        "Establish a login session."
        self.post("account/login.php", (("form_loginname", name),
                                        ("form_pw", password),
                                        ("return_to", ""),
                                        ("stay_in_ssl", "1"),
                                        ("login", "Login With SSL")))
    def logout(self):
        "Log out of SourceForge."
        self.get("account/logout.php")
    def fetch_xml(self, numid):
        self.get("export/xml_export.php?group_id=%s" % numid)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        project_id = '28236'    # PyCurl project ID
    else:
        project_id = sys.argv[1]
    # Try to grab authenticators out of your .netrc
    try:
        auth = netrc.netrc().authenticators("sourceforge.net")
        name, account, password = auth
    except:
        if len(sys.argv) < 4:
            print("Usage: %s <project id> <username> <password>" % sys.argv[0])
            raise SystemExit
        name = sys.argv[2]
        password = sys.argv[3]
    session = SourceForgeUserSession("https://sourceforge.net/")
    session.set_verbosity(0)
    session.login(name, password)
    # Login could fail.
    if session.answered("Invalid Password or User Name"):
        sys.stderr.write("Login/password not accepted (%d bytes)\n" % len(session.body()))
        sys.exit(1)
    # We'll see this if we get the right thing.
    elif session.answered("Personal Page For: " + name):
        session.fetch_xml(project_id)
        sys.stdout.write(session.body())
        session.logout()
        sys.exit(0)
    # Or maybe SourceForge has changed its site design so our check strings
    # are no longer valid.
    else:
        sys.stderr.write("Unexpected page (%d bytes)\n"%len(session.body()))
        sys.exit(1)

