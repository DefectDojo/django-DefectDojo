#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

import pycurl
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

buffer = BytesIO()
c = pycurl.Curl()
c.setopt(c.URL, 'http://pycurl.io/')
c.setopt(c.WRITEDATA, buffer)
c.perform()

# HTTP response code, e.g. 200.
print('Status: %d' % c.getinfo(c.RESPONSE_CODE))
# Elapsed time for the transfer.
print('Time: %f' % c.getinfo(c.TOTAL_TIME))

# getinfo must be called before close.
c.close()
