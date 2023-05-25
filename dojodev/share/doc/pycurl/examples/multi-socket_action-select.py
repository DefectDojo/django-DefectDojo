#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vi:ts=4:et

# Retrieves a single URL using the CurlMulti.socket_action calls, using
# select as the I/O polling mechanism:
#
# First, create a Multi object, and set socket and timer callbacks on it.
# Observed side effect: this causes the timer callback to be immediately
# invoked with the zero value for the timeout.
#
# The timer callback is very simple - it stores the timeout value passed
# into it in the global state for future use by the select calls that
# we will be making.
#
# The socket callback is more complicated. Its job is to add and remove
# socket handles to/from the data structure that we use for waiting for
# activity on them. The callback is invoked with a socket handle and the
# needed action (add for reading, add for writing or remove).
# Since this script utilizes the select call for waiting for activity,
# the socket callback updates the list of sockets which we should be
# polling for readability and the list that we should be polling for
# writability, which are then passed to the select call (and both of the
# sets are passed as the sockets to wait for errors/exceptions on).
#
# Next, create a Curl object (mapping to a libcurl easy handle), set the URL
# we are going to retrieve as well as any transfer options. This script sets
# the timeout to 5 seconds to be able to test failing transfers easily.
#
# Add the Curl object to the Multi object.
#
# Invoke Multi.socket_action to start the retrieval operation.
# Observed side effect: this causes the timer callback to be invoked
# with a greater than zero value for the timeout.
#
# By now we should have initialized our own state, which this script does
# prior to invoking any libcurl functions. Importantly, the state includes
# the timeout value that was communicated to us by libcurl.
#
# Run a loop which waits for activity on any of the sockets used by libcurl.
# The sockets are set that the socket callback has produced as of the
# present moment; the timeout is the most recent timeout value received by
# the timer callback.
#
# Importantly, the loop should not simply sleep for the entire
# timeout interval, as that would cause the transfer to take a very long time.
# It is *required* to use something like a select call to wait for activity
# on any of the sockets currently active for *up to* the timeout value.
#
# The loop terminates when the number of active transfers (handles in libcurl
# parlance) reaches zero. This number is provided by each socket_action
# call, which is why each call (even the ones that are called due to
# timeout being reached, as opposed to any socket activity) must update
# the number of running handles.
#
# After the loop terminates, clean up everything: remove the easy object from
# the multi object, close the easy object, close the multi object.

import sys, select
import pycurl
from io import BytesIO

if len(sys.argv) > 1:
    url = sys.argv[1]
else:
    url = 'https://www.python.org'

state = {
    'rlist': [],
    'wlist': [],
    'running': None,
    'timeout': None,
    'result': None,
    # If the transfer failed, code and msg will be filled in.
    'code': None,
    'msg': None,
}

def socket_fn(what, sock_fd, multi, socketp):
    if what == pycurl.POLL_IN or what == pycurl.POLL_INOUT:
        state['rlist'].append(sock_fd)
    elif what == pycurl.POLL_OUT or what == pycurl.POLL_INOUT:
        state['wlist'].append(sock_fd)
    elif what == pycurl.POLL_REMOVE:
        if sock_fd in state['rlist']:
            state['rlist'].remove(sock_fd)
        if sock_fd in state['wlist']:
            state['wlist'].remove(sock_fd)
    else:
        raise Exception("Unknown value of what: %s" % what)

def work(timeout):
    rready, wready, xready = select.select(
        state['rlist'], state['wlist'], set(state['rlist']) | set(state['wlist']), timeout)
    
    if len(rready) == 0 and len(wready) == 0 and len(xready) == 0:
        # The number of running handles must be updated after each
        # call to socket_action, which includes those with the SOCKET_TIMEOUT
        # argument (otherwise e.g. a transfer which failed due to
        # exceeding the connection timeout would hang).
        _, running = multi.socket_action(pycurl.SOCKET_TIMEOUT, 0)
    else:
        for sock_fd in rready:
            # socket_action returns a tuple whose first element is always the
            # CURLE_OK value (0), ignore it and use the second element only.
            _, running = multi.socket_action(sock_fd, pycurl.CSELECT_IN)
        for sock_fd in wready:
            _, running = multi.socket_action(sock_fd, pycurl.CSELECT_OUT)
        for sock_fd in xready:
            _, running = multi.socket_action(sock_fd, pycurl.CSELECT_ERR)
    
    # Since we are only performing a single transfer, we could call
    # Multi.info_read after the I/O loop terminates.
    # In practice, you would probably use socket_action with multiple
    # transfers, and you may want to be notified about transfer completion
    # as soon as the result is available.
    if state['running'] is not None and running != state['running']:
        # Some handle has completed.
        #
        # Note that socket_action was potentially called multiple times
        # in this function (e.g. if both a read handle became ready and a
        # different write handle became ready), therefore it is possible
        # that multiple handles have completed. In this particular script
        # we are only performing a single transfer (one
        # Curl object / easy handle), therefore only one transfer can ever
        # possibly complete.
        qmsg, successes, failures = multi.info_read()
        # We should have retrieved all of the available statuses, leaving
        # none in the queue.
        assert qmsg == 0
        
        # We have only one transfer.
        assert len(successes) == 1 and len(failures) == 0 or \
            len(successes) == 0 and len(failures) == 1
        
        if successes:
            state['result'] = True
        if failures:
            state['result'] = False
            # The failures array contains tuples of
            # (easy object, CURLE code, error message).
            _easy, state['code'], state['msg'] = failures[0]
    
    state['running'] = running

def timer_fn(timeout_ms):
    if timeout_ms < 0:
        # libcurl passes a negative timeout value when no further
        # calls should be made.
        state['timeout'] = None
    state['timeout'] = timeout_ms / 1000.0

multi = pycurl.CurlMulti()
multi.setopt(pycurl.M_SOCKETFUNCTION, socket_fn)
multi.setopt(pycurl.M_TIMERFUNCTION, timer_fn)

easy = pycurl.Curl()
easy.setopt(pycurl.URL, url)
# Uncomment to see what libcurl is doing throughout the transfer.
#easy.setopt(pycurl.VERBOSE, 1)
easy.setopt(pycurl.CONNECTTIMEOUT, 5)
easy.setopt(pycurl.LOW_SPEED_TIME, 5)
easy.setopt(pycurl.LOW_SPEED_LIMIT, 1)
_io = BytesIO()
easy.setopt(pycurl.WRITEDATA, _io)

multi.add_handle(easy)

handles = multi.socket_action(pycurl.SOCKET_TIMEOUT, 0)
# This should invoke the timer function with a timeout value.

while True:
    if state['running'] == 0:
        break
    else:
        # By the time we get here, timer function should have been already
        # invoked at least once so that we have a libcurl-supplied
        # timeout value. But in case this hasn't happened, default the timeout
        # to 1 second.
        timeout = state['timeout']
        if timeout is None:
            raise Exception('Need to poll for I/O but the timeout is not set!')
        work(timeout)

multi.remove_handle(easy)
easy.close()
multi.close()

# Uncomment to print the retrieved contents.
#print(_io.getvalue().decode())

if state['result'] is None:
    raise Exception('Script finished without a result!')
if state['result']:
    print('Transfer successful, retrieved %d bytes' % len(_io.getvalue()))
else:
    print('Transfer failed with code %d: %s' % (state['code'], state['msg']))
