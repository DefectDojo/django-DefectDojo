# Exposing rich exception information from callbacks example

import pycurl, random, socket

class ConnectionRejected(Exception):
    pass

def opensocket(curl, purpose, curl_address):
    if random.random() < 0.5:
        curl.exception = ConnectionRejected('Rejecting connection attempt in opensocket callback')
        return pycurl.SOCKET_BAD
    
    family, socktype, protocol, address = curl_address
    s = socket.socket(family, socktype, protocol)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s

c = pycurl.Curl()
c.setopt(c.URL, 'http://pycurl.io')
c.exception = None
c.setopt(c.OPENSOCKETFUNCTION,
    lambda purpose, address: opensocket(c, purpose, address))

try:
    c.perform()
except pycurl.error as e:
    if e.args[0] == pycurl.E_COULDNT_CONNECT and c.exception:
        print(c.exception)
    else:
        print(e)
