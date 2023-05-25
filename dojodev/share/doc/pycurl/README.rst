PycURL -- A Python Interface To The cURL library
================================================

.. image:: https://github.com/pycurl/pycurl/workflows/CI/badge.svg
	   :target: https://github.com/pycurl/pycurl/actions

PycURL is a Python interface to `libcurl`_, the multiprotocol file
transfer library. Similarly to the urllib_ Python module,
PycURL can be used to fetch objects identified by a URL from a Python program.
Beyond simple fetches however PycURL exposes most of the functionality of
libcurl, including:

- Speed - libcurl is very fast and PycURL, being a thin wrapper above
  libcurl, is very fast as well. PycURL `was benchmarked`_ to be several
  times faster than requests_.
- Features including multiple protocol support, SSL, authentication and
  proxy options. PycURL supports most of libcurl's callbacks.
- Multi_ and share_ interfaces.
- Sockets used for network operations, permitting integration of PycURL
  into the application's I/O loop (e.g., using Tornado_).

.. _was benchmarked: http://stackoverflow.com/questions/15461995/python-requests-vs-pycurl-performance
.. _requests: http://python-requests.org/
.. _Multi: https://curl.haxx.se/libcurl/c/libcurl-multi.html
.. _share: https://curl.haxx.se/libcurl/c/libcurl-share.html
.. _Tornado: http://www.tornadoweb.org/


Requirements
------------

- Python 3.5-3.10.
- libcurl 7.19.0 or better.


Installation
------------

Download source and binary distributions from `PyPI`_.
Binary wheels are now available for 32 and 64 bit Windows versions.

Please see `INSTALL.rst`_ for installation instructions. If installing from
a Git checkout, please follow instruction in the `Git Checkout`_ section
of INSTALL.rst.

.. _PyPI: https://pypi.python.org/pypi/pycurl
.. _INSTALL.rst: http://pycurl.io/docs/latest/install.html
.. _Git Checkout: http://pycurl.io/docs/latest/install.html#git-checkout


Documentation
-------------

Documentation for the most recent PycURL release is available on
`PycURL website <http://pycurl.io/docs/latest/>`_.

Documentation for the development version of PycURL
is available `here <http://pycurl.io/docs/dev/>`_.

To build documentation from source, run ``make docs``.
Building documentation requires `Sphinx <http://sphinx-doc.org/>`_ to
be installed, as well as pycurl extension module built as docstrings are
extracted from it. Built documentation is stored in ``build/doc``
subdirectory.


Support
-------

For support questions please use `curl-and-python mailing list`_.
`Mailing list archives`_ are available for your perusal as well.

Although not an official support venue, `Stack Overflow`_ has been
popular with some PycURL users.

Bugs can be reported `via GitHub`_. Please use GitHub only for bug
reports and direct questions to our mailing list instead.

.. _curl-and-python mailing list: http://cool.haxx.se/mailman/listinfo/curl-and-python
.. _Stack Overflow: http://stackoverflow.com/questions/tagged/pycurl
.. _Mailing list archives: https://curl.haxx.se/mail/list.cgi?list=curl-and-python
.. _via GitHub: https://github.com/pycurl/pycurl/issues


Automated Tests
---------------

PycURL comes with an automated test suite. To run the tests, execute::

    make test

The suite depends on packages `pytest`_ and `bottle`_, as well as `vsftpd`_.

Some tests use vsftpd configured to accept anonymous uploads. These tests
are not run by default. As configured, vsftpd will allow reads and writes to
anything the user running the tests has read and write access. To run
vsftpd tests you must explicitly set PYCURL_VSFTPD_PATH variable like so::

    # use vsftpd in PATH
    export PYCURL_VSFTPD_PATH=vsftpd

    # specify full path to vsftpd
    export PYCURL_VSFTPD_PATH=/usr/local/libexec/vsftpd

.. _pytest: https://pytest.org/
.. _bottle: http://bottlepy.org/
.. _vsftpd: http://vsftpd.beasts.org/


Test Matrix
-----------

The test matrix is a separate framework that runs tests on more esoteric
configurations. It supports:

- Testing against Python 2.4, which bottle does not support.
- Testing against Python compiled without threads, which requires an out of
  process test server.
- Testing against locally compiled libcurl with arbitrary options.

To use the test matrix, first start the test server from Python 2.5+ by
running::

    python -m tests.appmanager

Then in a different shell, and preferably in a separate user account,
run the test matrix::

    # run ftp tests, etc.
    export PYCURL_VSFTPD_PATH=vsftpd
    # create a new work directory, preferably not under pycurl tree
    mkdir testmatrix
    cd testmatrix
    # run the matrix specifying absolute path
    python /path/to/pycurl/tests/matrix.py

The test matrix will download, build and install supported Python versions
and supported libcurl versions, then run pycurl tests against each combination.
To see what the combinations are, look in
`tests/matrix.py <tests/matrix.py>`_.


Contribute
----------

For smaller changes:

#. Fork `the repository`_ on Github.
#. Create a branch off **master**.
#. Make your changes.
#. Write a test which shows that the bug was fixed or that the feature
   works as expected.
#. Send a pull request.
#. Check back after 10-15 minutes to see if tests passed on Travis CI.
   PycURL supports old Python and libcurl releases and their support is tested
   on Travis.

For larger changes:

#. Join the `mailing list`_.
#. Discuss your proposal on the mailing list.
#. When consensus is reached, implement it as described above.

Please contribute binary distributions for your system to the
`downloads repository`_.


License
-------

::

    Copyright (C) 2001-2008 by Kjetil Jacobsen <kjetilja at gmail.com>
    Copyright (C) 2001-2008 by Markus F.X.J. Oberhumer <markus at oberhumer.com>
    Copyright (C) 2013-2022 by Oleg Pudeyev <code at olegp.name>

    All rights reserved.

    PycURL is dual licensed under the LGPL and an MIT/X derivative license
    based on the cURL license.  A full copy of the LGPL license is included
    in the file COPYING-LGPL.  A full copy of the MIT/X derivative license is
    included in the file COPYING-MIT.  You can redistribute and/or modify PycURL
    according to the terms of either license.

.. _PycURL: http://pycurl.io/
.. _libcurl: https://curl.haxx.se/libcurl/
.. _urllib: http://docs.python.org/library/urllib.html
.. _`the repository`: https://github.com/pycurl/pycurl
.. _`mailing list`: http://cool.haxx.se/mailman/listinfo/curl-and-python
.. _`downloads repository`: https://github.com/pycurl/downloads
