from __future__ import unicode_literals
from dump import _Dump


class Windows2003ServerDump(_Dump):
    def __init__(self, params):
        super(Windows2003ServerDump, self).__init__(params)
