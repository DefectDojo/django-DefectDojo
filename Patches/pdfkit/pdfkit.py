# -*- coding: utf-8 -*-
import re
import subprocess
import sys
from collections import OrderedDict
from .source import Source
from .configuration import Configuration
import io
import codecs
try:
    # Python 2.x and 3.x support for checking string types
    assert basestring
    assert unicode
except NameError:
    basestring = str
    unicode = str


class PDFKit(object):
    """
    Main class that does all generation routine.

    :param url_or_file: str - either a URL, a path to a file or a string containing HTML
                       to convert
    :param type_: str - either 'url', 'file' or 'string'
    :param options: dict (optional) with wkhtmltopdf options, with or w/o '--'
    :param toc: dict (optional) - toc-specific wkhtmltopdf options, with or w/o '--'
    :param cover: str (optional) - url/filename with a cover html page
    :param configuration: (optional) instance of pdfkit.configuration.Configuration()
    """

    class ImproperSourceError(Exception):
        """Wrong source type for stylesheets"""

        def __init__(self, msg):
            self.msg = msg

        def __str__(self):
            return self.msg

    def __init__(self, url_or_file, type_, options=None, toc=None, cover=None,
                 css=None, configuration=None, cover_first=False):

        self.source = Source(url_or_file, type_)
        self.configuration = (Configuration() if configuration is None
                              else configuration)
        try:
            self.wkhtmltopdf = self.configuration.wkhtmltopdf.decode('utf-8')
        except AttributeError:
            self.wkhtmltopdf = self.configuration.wkhtmltopdf

        self.options = OrderedDict()
        if self.source.isString():
            self.options.update(self._find_options_in_meta(url_or_file))

        self.environ = self.configuration.environ

        if options is not None:
            self.options.update(options)

        self.toc = {} if toc is None else toc
        self.cover = cover
        self.cover_first = cover_first
        self.css = css
        self.stylesheets = []

    def _genargs(self, opts):
        """
        Generator of args parts based on options specification.

        Note: Empty parts will be filtered out at _command generator
        """
        for optkey, optval in self._normalize_options(opts):
            yield optkey

            if isinstance(optval, (list, tuple)):
                assert len(optval) == 2 and optval[0] and optval[1], 'Option value can only be either a string or a (tuple, list) of 2 items'
                yield optval[0]
                yield optval[1]
            else:
                yield optval

    def _command(self, path=None):
        """
        Generator of all command parts
        """
        if self.css:
            self._prepend_css(self.css)

        yield self.wkhtmltopdf

        for argpart in self._genargs(self.options):
            if argpart:
                yield argpart

        if self.cover and self.cover_first:
            yield 'cover'
            yield self.cover

        if self.toc:
            yield 'toc'
            for argpart in self._genargs(self.toc):
                if argpart:
                    yield argpart

        if self.cover and not self.cover_first:
            yield 'cover'
            yield self.cover

        # If the source is a string then we will pipe it into wkhtmltopdf
        # If the source is file-like then we will read from it and pipe it in
        if self.source.isString() or self.source.isFileObj():
            yield '-'
        else:
            if isinstance(self.source.source, basestring):
                yield self.source.to_s()
            else:
                for s in self.source.source:
                    yield s

        # If output_path evaluates to False append '-' to end of args
        # and wkhtmltopdf will pass generated PDF to stdout
        if path:
            yield path
        else:
            yield '-'

    def command(self, path=None):
        return list(self._command(path))

    @staticmethod
    def handle_error(exit_code, stderr):
        if exit_code == 0 or exit_code == 1:
            return

        # Sometimes wkhtmltopdf will exit with non-zero
        # even if it finishes generation.
        # If will display 'Done' in the second last line
        #if stderr.splitlines()[-2].strip() == 'Done':

        if 'cannot connect to X server' in stderr:
            raise IOError('%s\n'
                          'You will need to run wkhtmltopdf within a "virtual" X server.\n'
                          'Go to the link below for more information\n'
                          'https://github.com/JazzCore/python-pdfkit/wiki/Using-wkhtmltopdf-without-X-server' % stderr)

        if 'Error' in stderr:
            raise IOError('wkhtmltopdf reported an error:\n' + stderr)

        error_msg = stderr or 'Unknown Error'
        raise IOError("wkhtmltopdf exited with non-zero code {0}. error:\n{1}".format(exit_code, error_msg))

    def to_pdf(self, path=None):
        args = self.command(path)

        result = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environ
        )

        # If the source is a string then we will pipe it into wkhtmltopdf.
        # If we want to add custom CSS to file then we read input file to
        # string and prepend css to it and then pass it to stdin.
        # This is a workaround for a bug in wkhtmltopdf (look closely in README)
        if self.source.isString() or (self.source.isFile() and self.css):
            input = self.source.to_s().encode('utf-8')
        elif self.source.isFileObj():
            input = self.source.source.read().encode('utf-8')
        else:
            input = None

        stdout, stderr = result.communicate(input=input)
        stderr = stderr or stdout
        stderr = stderr.decode('utf-8', errors='replace')
        exit_code = result.returncode
        self.handle_error(exit_code, stderr)

        # Since wkhtmltopdf sends its output to stderr we will capture it
        # and properly send to stdout
        if '--quiet' not in args:
            sys.stdout.write(stderr)

        if not path:
            return stdout

        try:
            with codecs.open(path, encoding='utf-8') as f:
                # read 4 bytes to get PDF signature '%PDF'
                text = f.read(4)
                if text == '':
                    raise IOError('Command failed: %s\n'
                                  'Check whhtmltopdf output without \'quiet\' '
                                  'option' % ' '.join(args))
                return True
        except (IOError, OSError) as e:
            raise IOError('Command failed: %s\n'
                          'Check whhtmltopdf output without \'quiet\' option\n'
                          '%s ' % (' '.join(args), e))

    def _normalize_options(self, options):
        """ Generator of 2-tuples (option-key, option-value).
        When options spec is a list, generate a 2-tuples per list item.

        :param options: dict {option name: value}

        returns:
          iterator (option-key, option-value)
          - option names lower cased and prepended with
          '--' if necessary. Non-empty values cast to str
        """

        for key, value in list(options.items()):
            if '--' not in key:
                normalized_key = '--%s' % self._normalize_arg(key)
            else:
                normalized_key = self._normalize_arg(key)

            if isinstance(value, (list, tuple)):
                for optval in value:
                    yield (normalized_key, optval)
            else:
                yield (normalized_key, unicode(value) if value else value)

    def _normalize_arg(self, arg):
        return arg.lower()

    def _style_tag_for(self, stylesheet):
        return "<style>%s</style>" % stylesheet

    def _prepend_css(self, path):
        if self.source.isUrl() or isinstance(self.source.source, list):
            raise self.ImproperSourceError('CSS files can be added only to a single '
                                           'file or string')

        if not isinstance(path, list):
            path = [path]

        css_data = []
        for p in path:
            with codecs.open(p, encoding="UTF-8") as f:
                css_data.append(f.read())
        css_data = "\n".join(css_data)

        if self.source.isFile():
            with codecs.open(self.source.to_s(), encoding="UTF-8") as f:
                inp = f.read()
            self.source = Source(
                inp.replace('</head>', self._style_tag_for(css_data) + '</head>'),
                'string')

        elif self.source.isString():
            if '</head>' in self.source.to_s():
                self.source.source = self.source.to_s().replace(
                    '</head>', self._style_tag_for(css_data) + '</head>')
            else:
                self.source.source = self._style_tag_for(css_data) + self.source.to_s()

    def _find_options_in_meta(self, content):
        """Reads 'content' and extracts options encoded in HTML meta tags

        :param content: str or file-like object - contains HTML to parse

        returns:
          dict: {config option: value}
        """
        if (isinstance(content, io.IOBase)
                or content.__class__.__name__ == 'StreamReaderWriter'):
            content = content.read()

        found = {}

        for x in re.findall('<meta [^>]*>', content):
            if re.search('name=["\']%s' % self.configuration.meta_tag_prefix, x):
                name = re.findall('name=["\']%s([^"\']*)' %
                                  self.configuration.meta_tag_prefix, x)[0]
                found[name] = re.findall('content=["\']([^"\']*)', x)[0]

        return found
