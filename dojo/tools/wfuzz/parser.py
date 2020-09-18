from dojo.models import Endpoint, Finding

__author__ = 'SPoint42'


class wfuzzJSONParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return


