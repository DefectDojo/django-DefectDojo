.. _install:

PycURL Installation
===================

NOTE: You need Python and libcurl installed on your system to use or
build pycurl.  Some RPM distributions of curl/libcurl do not include
everything necessary to build pycurl, in which case you need to
install the developer specific RPM which is usually called curl-dev.


Distutils
---------

Build and install pycurl with the following commands::

    (if necessary, become root)
    tar -zxvf pycurl-$VER.tar.gz
    cd pycurl-$VER
    python setup.py install

$VER should be substituted with the pycurl version number, e.g. 7.10.5.

Note that the installation script assumes that 'curl-config' can be
located in your path setting.  If curl-config is installed outside
your path or you want to force installation to use a particular
version of curl-config, use the '--curl-config' command line option to
specify the location of curl-config.  Example::

    python setup.py install --curl-config=/usr/local/bin/curl-config

If libcurl is linked dynamically with pycurl, you may have to alter the
LD_LIBRARY_PATH environment variable accordingly.  This normally
applies only if there is more than one version of libcurl installed,
e.g. one in /usr/lib and one in /usr/local/lib.


SSL
^^^

PycURL requires that the SSL library that it is built against is the same
one libcurl, and therefore PycURL, uses at runtime. PycURL's ``setup.py``
uses ``curl-config`` to attempt to figure out which SSL library libcurl
was compiled against, however this does not always work. If PycURL is unable
to determine the SSL library in use it will print a warning similar to
the following::

    src/pycurl.c:137:4: warning: #warning "libcurl was compiled with SSL support, but configure could not determine which " "library was used; thus no SSL crypto locking callbacks will be set, which may " "cause random crashes on SSL requests" [-Wcpp]

It will then fail at runtime as follows::

    ImportError: pycurl: libcurl link-time ssl backend (openssl) is different from compile-time ssl backend (none/other)

To fix this, you need to tell ``setup.py`` what SSL backend is used::

    python setup.py --with-[openssl|gnutls|nss|mbedtls|wolfssl|sectransp] install

Note: as of PycURL 7.21.5, setup.py accepts ``--with-openssl`` option to
indicate that libcurl is built against OpenSSL/LibreSSL/BoringSSL.
``--with-ssl`` is an alias
for ``--with-openssl`` and continues to be accepted for backwards compatibility.

You can also ask ``setup.py`` to obtain SSL backend information from installed
libcurl shared library, as follows:

    python setup.py --libcurl-dll=libcurl.so

An unqualified ``libcurl.so`` would use the system libcurl, or you can
specify a full path.


easy_install / pip
------------------

::

    easy_install pycurl
    pip install pycurl

If you need to specify an alternate curl-config, it can be done via an
environment variable::

    export PYCURL_CURL_CONFIG=/usr/local/bin/curl-config
    easy_install pycurl

The same applies to the SSL backend, if you need to specify it (see the SSL
note above)::

    export PYCURL_SSL_LIBRARY=[openssl|gnutls|nss|mbedtls|sectransp]
    easy_install pycurl


pip and cached pycurl package
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you have already installed pycurl and are trying to reinstall it via
pip with different SSL options for example, pip may reinstall the package it
has previously compiled instead of recompiling pycurl with newly specified
options. More details are given in `this Stack Overflow post`_.

To force pip to recompile pycurl, run::

    # upgrade pip if necessary
    pip install --upgrade pip

    # remove current pycurl
    pip uninstall pycurl

    # set PYCURL_SSL_LIBRARY
    export PYCURL_SSL_LIBRARY=nss

    # recompile and install pycurl
    pip install --compile pycurl

.. _this Stack Overflow post: http://stackoverflow.com/questions/21487278/ssl-error-installing-pycurl-after-ssl-is-set


Windows
-------

There are currently no official binary Windows packages. You can build PycURL
from source or use third-party binary packages.


Building From Source
^^^^^^^^^^^^^^^^^^^^

Building PycURL from source is not for the faint of heart due to the multitude
of possible dependencies and each of these dependencies having its own
directory structure, configuration style, parameters and quirks.
Additionally different dependencies have different
settings for MSVCRT usage, and an application must have all of its parts
agreeing on a single setting. If you decide to build PycURL from source
it is advisable to look through the ``winbuild.py``
script - it is used to build the official binaries and contains a wealth
of information for compiling PycURL's dependencies on Windows.

If you are compiling PycURL from source it is recommended to compile all of its
dependencies from source as well. Using precompiled libraries may lead to
multiple MSVCRT versions mixed in the resulting PycURL binary, which will
not be good.

If PycURL is to be linked statically against its dependencies, OpenSSL must
be patched to link to the DLL version of MSVCRT. There is a patch for this in
``winbuild`` directory of PycURL source.

For a minimum build you will just need libcurl source. Follow its Windows
build instructions to build either a static or a DLL version of the library,
then configure PycURL as follows to use it::

    python setup.py --curl-dir=c:\dev\curl-7.33.0\builds\libcurl-vc-x86-release-dll-ipv6-sspi-spnego-winssl --use-libcurl-dll

Note that ``--curl-dir`` must point not to libcurl source but rather to headers
and compiled libraries.

If libcurl and Python are not linked against the same exact C runtime
(version number, static/dll, single-threaded/multi-threaded) you must use
``--avoid-stdio`` option (see below).

Additional Windows setup.py options:

- ``--use-libcurl-dll``: build against libcurl DLL, if not given PycURL will
  be built against libcurl statically.
- ``--libcurl-lib-name=libcurl_imp.lib``: specify a different name for libcurl
  import library. The default is ``libcurl.lib`` which is appropriate for
  static linking and is sometimes the correct choice for dynamic linking as
  well. The other possibility for dynamic linking is ``libcurl_imp.lib``.
- ``--with-openssl``: use OpenSSL/LibreSSL/BoringSSL crypto locks when libcurl
  was built against these SSL backends.
- ``--with-ssl``: legacy alias for ``--with-openssl``.
- ``--openssl-lib-name=""``: specify a different name for OpenSSL import
  library containing CRYPTO_num_locks. For OpenSSL 1.1.0+ this should be set
  to an empty string as given here.
- ``--avoid-stdio``: on Windows, a process and each library it is using
  may be linked to its own version of the C runtime (MSVCRT).
  FILE pointers from one C runtime may not be passed to another C runtime.
  This option prevents direct passing of FILE pointers from Python to libcurl,
  thus permitting Python and libcurl to be linked against different C runtimes.
  This option may carry a performance penalty when Python file objects are
  given directly to PycURL in CURLOPT_READDATA, CURLOPT_WRITEDATA or
  CURLOPT_WRITEHEADER options. This option applies only on Python 2; on
  Python 3, file objects no longer expose C library FILE pointers and the
  C runtime issue does not exist. On Python 3, this option is recognized but
  does nothing. You can also give ``--avoid-stdio`` option in
  PYCURL_SETUP_OPTIONS environment variable as follows::

    PYCURL_SETUP_OPTIONS=--avoid-stdio pip install pycurl

A good ``setup.py`` target to use is ``bdist_wininst`` which produces an
executable installer that you can run to install PycURL.

You may find the following mailing list posts helpful:

- https://curl.haxx.se/mail/curlpython-2009-11/0010.html
- https://curl.haxx.se/mail/curlpython-2013-11/0002.html


winbuild.py
^^^^^^^^^^^

This script is used to build official PycURL Windows packages. You can
use it to build a full complement of packages with your own options or modify
it to build a single package you need.

Prerequisites:

- `Git for Windows`_.
- Appropriate `Python versions`_ installed.
- MS Visual C++ 9/2008 for Python <= 3.2, MS Visual C++ 10/2010 for
  Python 3.3 or 3.4, MS Visual C++ 14/2015 for Python 3.5 through 3.8.
  Express versions of Visual Studio work fine for this,
  although getting 64 bit compilers to wok in some Express versions involves
  jumping through several hoops.
- NASM if building libcurl against OpenSSL.
- ActivePerl if building libcurl against OpenSSL. The perl shipping with
  Git for Windows handles forward and backslashes in paths in a way that is
  incompatible with OpenSSL's build scripts.

.. _Git for Windows: https://git-for-windows.github.io/
.. _Python versions: http://python.org/download/

``winbuild.py`` assumes all programs are installed in their default locations,
if this is not the case edit it as needed. ``winbuild.py`` itself can be run
with any Python it supports.


Using PycURL With Custom Python Builds
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As of version 7.21.5, the official binary packages of PycURL are linked
statically against all of its dependencies except MSVCRT. This means that
as long as your custom Python build uses the same version of MSVC as the
corresponding official Python build as well as the same MSVCRT linking setting
(/MD et. al.), an official PycURL package should work.

If your Python build uses different MSVCRT settings or a different MSVC
version from the official Python builds, you will need to compile PycURL
from source.

If the C runtime library (MSVCRT.DLL) versions used by PycURL and Python
do not match, you will receive a message
like the following one when trying to import ``pycurl`` module::

    ImportError: DLL load failed: The specified procedure could not be found.

To identify which MSVCRT version your Python uses use the
`application profiling feature`_ of
`Dependency Walker`_ and look for `msvcrt.dll variants`_ being loaded.
You may find `the entire thread starting here`_ helpful.

.. _application profiling feature: https://curl.haxx.se/mail/curlpython-2014-05/0007.html
.. _Dependency Walker: http://www.dependencywalker.com/
.. _msvcrt.dll variants: https://curl.haxx.se/mail/curlpython-2014-05/0010.html
.. _the entire thread starting here: https://curl.haxx.se/mail/curlpython-2014-05/0000.html


Git Checkout
------------

In order to build PycURL from a Git checkout, some files need to be
generated. On Unix systems it is easiest to build PycURL with ``make``::

    make

To specify which curl or SSL backend to compile against, use the same
environment variables as easy_install/pip, namely ``PYCURL_CURL_CONFIG``
and ``PYCURL_SSL_LIBRARY``.

To generate generated files only you may run::

    make gen

This might be handy if you are on Windows. Remember to run ``make gen``
whenever you change sources.

To generate documentation, run::

    make docs

Generating documentation requires `Sphinx`_ to be installed.

.. _Sphinx: http://sphinx-doc.org/


A Note Regarding SSL Backends
-----------------------------

libcurl's functionality varies depending on which SSL backend it is compiled
against. For example, users have `reported`_ `problems`_ with GnuTLS backend.
As of this writing, generally speaking, OpenSSL backend has the most
functionality as well as the best compatibility with other software.

If you experience SSL issues, especially if you are not using OpenSSL
backend, you can try rebuilding libcurl and PycURL against another SSL backend.

.. _reported: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=515200
.. _problems: https://bugs.launchpad.net/ubuntu/+source/pycurl/+bug/1111673


SSL Certificate Bundle
----------------------

libcurl, and PycURL, by default verify validity of HTTPS servers' SSL
certificates. Doing so requires a CA certificate bundle, which libcurl
and most SSL libraries do not provide.

Here_ is a good resource on how to build your own certificate bundle.
certifie.com also has a `prebuilt certificate bundle`_.
To use the certificate bundle, use ``CAINFO`` or ``CAPATH`` PycURL
options.

.. _Here: http://certifie.com/ca-bundle/
.. _prebuilt certificate bundle: http://certifie.com/ca-bundle/ca-bundle.crt.txt
