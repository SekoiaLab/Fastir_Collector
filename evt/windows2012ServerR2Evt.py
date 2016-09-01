# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from logs import _EventLogs


class Windows2012ServerR2Evt(_EventLogs):
    def __init__(self, params):
        super(Windows2012ServerR2Evt, self).__init__(params)

    def csv_event_logs(self):
        super(Windows2012ServerR2Evt, self)._csv_event_logs(False)

    def json_event_logs(self):
        super(Windows2012ServerR2Evt, self)._json_event_logs(False)
