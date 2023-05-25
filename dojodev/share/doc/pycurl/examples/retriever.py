#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

#
# Usage: python retriever.py <file with URLs to fetch> [<# of
#          concurrent connections>]
#

import sys, threading
try:
    import Queue
except ImportError:
    import queue as Queue
import pycurl

# We should ignore SIGPIPE when using pycurl.NOSIGNAL - see
# the libcurl tutorial for more info.
try:
    import signal
    from signal import SIGPIPE, SIG_IGN
except ImportError:
    pass
else:
    signal.signal(SIGPIPE, SIG_IGN)


# Get args
num_conn = 10
try:
    if sys.argv[1] == "-":
        urls = sys.stdin.readlines()
    else:
        urls = open(sys.argv[1]).readlines()
    if len(sys.argv) >= 3:
        num_conn = int(sys.argv[2])
except:
    print("Usage: %s <file with URLs to fetch> [<# of concurrent connections>]" % sys.argv[0])
    raise SystemExit


# Make a queue with (url, filename) tuples
queue = Queue.Queue()
for url in urls:
    url = url.strip()
    if not url or url[0] == "#":
        continue
    filename = "doc_%03d.dat" % (len(queue.queue) + 1)
    queue.put((url, filename))


# Check args
assert queue.queue, "no URLs given"
num_urls = len(queue.queue)
num_conn = min(num_conn, num_urls)
assert 1 <= num_conn <= 10000, "invalid number of concurrent connections"
print("PycURL %s (compiled against 0x%x)" % (pycurl.version, pycurl.COMPILE_LIBCURL_VERSION_NUM))
print("----- Getting", num_urls, "URLs using", num_conn, "connections -----")


class WorkerThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while 1:
            try:
                url, filename = self.queue.get_nowait()
            except Queue.Empty:
                raise SystemExit
            fp = open(filename, "wb")
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, url)
            curl.setopt(pycurl.FOLLOWLOCATION, 1)
            curl.setopt(pycurl.MAXREDIRS, 5)
            curl.setopt(pycurl.CONNECTTIMEOUT, 30)
            curl.setopt(pycurl.TIMEOUT, 300)
            curl.setopt(pycurl.NOSIGNAL, 1)
            curl.setopt(pycurl.WRITEDATA, fp)
            try:
                curl.perform()
            except:
                import traceback
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
            curl.close()
            fp.close()
            sys.stdout.write(".")
            sys.stdout.flush()


# Start a bunch of threads
threads = []
for dummy in range(num_conn):
    t = WorkerThread(queue)
    t.start()
    threads.append(t)


# Wait for all threads to finish
for thread in threads:
    thread.join()
