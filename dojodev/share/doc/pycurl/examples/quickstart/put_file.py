#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

import pycurl

c = pycurl.Curl()
c.setopt(c.URL, 'https://httpbin.org/put')

c.setopt(c.UPLOAD, 1)
file = open(__file__)
c.setopt(c.READDATA, file)

c.perform()
c.close()
# File must be kept open while Curl object is using it
file.close()
