#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

import pycurl

c = pycurl.Curl()
# Redirects to https://www.python.org/.
c.setopt(c.URL, 'http://www.python.org/')
# Follow redirect.
c.setopt(c.FOLLOWLOCATION, True)
c.perform()
c.close()
