# Based on the simple libcurl SMTP example:
# https://github.com/bagder/curl/blob/master/docs/examples/smtp-mail.c
# There are other SMTP examples in that directory that you may find helpful.

from . import localhost
import pycurl
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO
import sys

PY3 = sys.version_info[0] > 2

mail_server = 'smtp://%s' % localhost
mail_from = 'sender@example.org'
mail_to = 'addressee@example.net'

c = pycurl.Curl()
c.setopt(c.URL, mail_server)
c.setopt(c.MAIL_FROM, mail_from)
c.setopt(c.MAIL_RCPT, [mail_to])

message = '''\
From: %s
To: %s
Subject: PycURL SMTP example

SMTP example via PycURL
''' % (mail_from, mail_to)

if PY3:
    message = message.encode('ascii')

# libcurl does not perform buffering, therefore
# we need to wrap the message string into a BytesIO or StringIO.
io = BytesIO(message)
c.setopt(c.READDATA, io)

# If UPLOAD is not set, libcurl performs SMTP VRFY.
# Setting UPLOAD to True sends a message.
c.setopt(c.UPLOAD, True)

# Observe SMTP conversation.
c.setopt(c.VERBOSE, True)
c.perform()
