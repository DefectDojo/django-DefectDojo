import urlparse
import sys

url = urlparse.urlparse(sys.argv[1])
path = url.path[1:]
path = path.split('?', 2)[0]
print url.scheme + ":" + path + ":" + url.username + ":" + url.password + ":" + url.hostname + ":" + str(url.port)
