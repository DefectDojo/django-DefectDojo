Release Notes
=============

PycURL 7.45.2 - 2022-12-16
--------------------------

This release fixes several minor issues and adds support for several libcurl
options.

PycURL 7.45.1 - 2022-03-13
--------------------------

This release fixes build when libcurl < 7.64.1 is used.

PycURL 7.45.0 - 2022-03-09
--------------------------

This release adds support for SecureTransport SSL backend (MacOS), adds
ability to unset a number of multi options, adds ability to duplicate easy
handles and permits pycurl classes to be subclassed.

PycURL 7.44.1 - 2021-08-15
--------------------------

This release repairs incorrect Python thread initialization logic which
caused operations to hang.

PycURL 7.44.0 - 2021-08-08
--------------------------

This release reinstates best effort Python 2 support, adds Python 3.9 and
Python 3.10 alpha support and implements support for several libcurl options.

Official Windows builds are currently not being produced.

PycURL 7.43.0.6 - 2020-09-02
----------------------------

This release improves SSL backend detection on various systems, adds support
for libcurl's multiple SSL backend functionality and adds support for several
libcurl options.

PycURL 7.43.0.5 - 2020-01-29
----------------------------

This release fixes a build issue on recent Pythons on CentOS/RHEL distributions.

It also brings back Windows binaries. Special thank you to Gisle Vanem for
contributing the nghttp2 makefile.


PycURL 7.43.0.4 - 2020-01-15
----------------------------

This release improves compatibility with Python 3.8 and removes support for
Python 2 and Python 3.4. It also adds wolfSSL support and thread safety of
the multi interface.


PycURL 7.43.0.3 - 2019-06-17
----------------------------

This release primarily fixes an OpenSSL-related installation issue, and
repairs the ability to use PycURL with newer libcurls compiled without FTP
support. Also, mbedTLS support has been contributed by Josef Schlehofer.


PycURL 7.43.0.2 - 2018-06-02
----------------------------

Highlights of this release:

1. Experimental perform_rs and perform_rb methods have been added to Curl
   objects. They return response body as a string and a byte string,
   respectively. The goal of these methods is to improve PycURL's usability
   for typical use cases, specifically removing the need to set up
   StringIO/BytesIO objects to store the response body.

2. getinfo_raw and errstr_raw methods have been added to Curl objects to
   return transfer information as byte strings, permitting applications to
   retrieve transfer information that is not decodable using Python's
   default encoding.

3. errstr and "fail or error" exceptions now replace undecodable bytes
   so as to provide usable strings; use errstr_raw to retrieve original
   byte strings.

4. There is no longer a need to keep references to Curl objects when they
   are used in CurlMulti objects - PycURL now maintains such references
   internally.

5. Official Windows builds now include HTTP/2 and international domain
   name support.

6. PycURL now officially supports BoringSSL.

7. A number of smaller improvements have been made and bugs fixed.


PycURL 7.43.0.1 - 2017-12-07
----------------------------

This release collects fixes and improvements made over the past two years,
notably updating Windows dependencies to address DNS resolution and
TLS connection issues.


PycURL 7.43.0 - 2016-02-02
--------------------------

Highlights of this release:

1. Binary wheels are now built for Windows systems.

2. setopt_string method added to Curl objects to permit setting string libcurl
   options that PycURL does not know about.

3. curl module can now be imported on Windows again.

4. OPENSOCKETFUNCTION callback is now invoked with the address as bytes on
   Python 3 as was documented.

5. Support for many libcurl options and constants was added.


PycURL 7.21.5 - 2016-01-05
--------------------------

Highlights of this release:

1. Socket callbacks are now fully implemented (``CURLOPT_OPENSOCKETFUNCTION``,
   ``CURLOPT_SOCKOPTFUNCTION``, ``CURLOPT_CLOSESOCKETFUNCTION``). Unfortunately
   this required changing ``OPENSOCKETFUNCTION`` API once again in a
   backwards-incompatible manner. Support for ``SOCKOPTFUNCTION`` and
   ``CLOSESOCKETFUNCTION`` was added in this release. ``OPENSOCKETFUNCTION``
   now supports Unix sockets.

2. Many other libcurl options and constants have been added to PycURL.

3. When ``pycurl`` module initialization fails, ``ImportError`` is raised
   instead of a fatal error terminating the process.

4. Usability of official Windows builds has been greatly improved:

   * Dependencies are linked statically, eliminating possible DLL conflicts.
   * OpenSSL is used instead of WinSSL.
   * libcurl is linked against C-Ares and libssh2.


PycURL 7.19.5.3 - 2015-11-03
----------------------------

PycURL 7.19.5.2 release did not include some of the test suite files in
its manifest, leading to inability to run the test suite from the sdist
tarball. This is now fixed thanks to Kamil Dudka.


PycURL 7.19.5.2 - 2015-11-02
----------------------------

Breaking change: DEBUGFUNCTION now takes bytes rather than (Unicode) string
as its argument on Python 3.

Breaking change: CURLMOPT_* option constants moved from Easy to Multi
class. They remain available in pycurl module.

SSL library detection improved again, --libcurl-dll option to setup.py added.

Options that required tuples now also accept lists, and vice versa.

This release fixes several memory leaks and one use after free issue.

Support for several new libcurl options and constants has been added.


PycURL 7.19.5.1 - 2015-01-06
----------------------------

This release primarily fixes build breakage against libcurl 7.19.4 through
7.21.1, such as versions shipped with CentOS.


PycURL 7.19.5 - 2014-07-12
--------------------------

PycURL C code has been significantly reorganized. Curl, CurlMulti and
CurlShare classes are now properly exported, instead of factory functions for
the respective objects. PycURL API has not changed.

Documentation has been transitioned to Sphinx and reorganized as well.
Both docstrings and standalone documentation are now more informative.

Documentation is no longer included in released distributions. It can be
generated from source by running `make docs`.

Tests are no longer included in released distributions. Instead the
documentation and quickstart examples should be consulted for sample code.

Official Windows builds now are linked against zlib.


PycURL 7.19.3.1 - 2014-02-05
----------------------------

This release restores PycURL's ability to automatically detect SSL library
in use in most circumstances, thanks to Andjelko Horvat.


PycURL 7.19.3 - 2014-01-09
--------------------------

This release brings official Python 3 support to PycURL.
Several GNU/Linux distributions provided Python 3 packages of PycURL
previously; these packages were based on patches that were incomplete and
in some places incorrect. Behavior of PycURL 7.19.3 and later may therefore
differ from behavior of unofficial Python 3 packages of previous PycURL
versions.

To summarize the behavior under Python 3, PycURL will accept ``bytes`` where
it accepted strings under Python 2, and will also accept Unicode strings
containing ASCII codepoints only for convenience. Please refer to
`Unicode`_ and `file`_ documentation for further details.

In the interests of compatibility, PycURL will also accept Unicode data on
Python 2 given the same constraints as under Python 3.

While Unicode and file handling rules are expected to be sensible for
all use cases, and retain backwards compatibility with previous PycURL
versions, please treat behavior of this versions under Python 3 as experimental
and subject to change.

Another potentially disruptive change in PycURL is the requirement for
compile time and runtime SSL backends to match. Please see the readme for
how to indicate the SSL backend to setup.py.

.. _Unicode: doc/unicode.html
.. _file: doc/files.html
