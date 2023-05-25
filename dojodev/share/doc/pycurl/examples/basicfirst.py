#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et
import sys
import pycurl

PY3 = sys.version_info[0] > 2


class Test:
    def __init__(self):
        self.contents = ''
        if PY3:
            self.contents = self.contents.encode('ascii')

    def body_callback(self, buf):
        self.contents = self.contents + buf


sys.stderr.write("Testing %s\n" % pycurl.version)

t = Test()
c = pycurl.Curl()
c.setopt(c.URL, 'https://curl.haxx.se/dev/')
c.setopt(c.WRITEFUNCTION, t.body_callback)
c.perform()
c.close()

print(t.contents)
