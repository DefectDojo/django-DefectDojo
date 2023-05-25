import pycurl

sftp_server = 'sftp://web.sourceforge.net'

c = pycurl.Curl()
c.setopt(c.URL, sftp_server)
c.setopt(c.VERBOSE, True)

def keyfunction(known_key, found_key, match):
    return c.KHSTAT_FINE

c.setopt(c.SSH_KNOWNHOSTS, '.known_hosts')
c.setopt(c.SSH_KEYFUNCTION, keyfunction)

c.perform()
