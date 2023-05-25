#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

# We should ignore SIGPIPE when using pycurl.NOSIGNAL - see
# the libcurl tutorial for more info.
try:
    import signal
    from signal import SIGPIPE, SIG_IGN
except ImportError:
    pass
else:
    signal.signal(SIGPIPE, SIG_IGN)

try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO
try:
    import xmlrpclib
except ImportError:
    import xmlrpc.client as xmlrpclib
import pycurl
import sys

PY3 = sys.version_info[0] > 2


class CURLTransport(xmlrpclib.Transport):
    """Handles a cURL HTTP transaction to an XML-RPC server."""

    xmlrpc_h = [ "Content-Type: text/xml" ]

    def __init__(self, username=None, password=None):
        self.c = pycurl.Curl()
        self.c.setopt(pycurl.POST, 1)
        self.c.setopt(pycurl.NOSIGNAL, 1)
        self.c.setopt(pycurl.CONNECTTIMEOUT, 30)
        self.c.setopt(pycurl.HTTPHEADER, self.xmlrpc_h)
        if username != None and password != None:
            self.c.setopt(pycurl.USERPWD, '%s:%s' % (username, password))
        self._use_datetime = False

    def request(self, host, handler, request_body, verbose=0):
        b = StringIO()
        self.c.setopt(pycurl.URL, 'http://%s%s' % (host, handler))
        self.c.setopt(pycurl.POSTFIELDS, request_body)
        self.c.setopt(pycurl.WRITEFUNCTION, b.write)
        self.c.setopt(pycurl.VERBOSE, verbose)
        self.verbose = verbose
        try:
           self.c.perform()
        except pycurl.error:
            v = sys.exc_info()[1]
            if PY3:
                v = v.args
            raise xmlrpclib.ProtocolError(
                host + handler,
                v[0], v[1], None
                )
        b.seek(0)
        return self.parse_response(b)


if __name__ == "__main__":
    ## Test
    server = xmlrpclib.ServerProxy("http://betty.userland.com",
                                   transport=CURLTransport())
    print(server)
    try:
        print(server.examples.getStateName(41))
    except xmlrpclib.Error:
        v = sys.exc_info()[1]
        print("ERROR", v)
