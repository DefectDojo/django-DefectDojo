#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

import pycurl

c = pycurl.Curl()
c.setopt(c.URL, 'https://httpbin.org/post')

c.setopt(c.HTTPPOST, [
    ('fileupload', (
        # upload the contents of this file
        c.FORM_FILE, __file__,
        # specify a different file name for the upload
        c.FORM_FILENAME, 'helloworld.py',
        # specify a different content type
        c.FORM_CONTENTTYPE, 'application/x-python',
    )),
])

c.perform()
c.close()
