# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from logs import _EventLogs


class Windows7Evt(_EventLogs):
    def __init__(self, params):
        super(Windows7Evt, self).__init__(params)

    def csv_event_logs(self):
        super(Windows7Evt, self)._csv_event_logs(False)

    def json_event_logs(self):
        super(Windows7Evt, self)._json_event_logs(False)