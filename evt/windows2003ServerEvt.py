# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from logs import _EventLogs


class Windows2003ServerEvt(_EventLogs):
    def __init__(self, params):
        super(Windows2003ServerEvt, self).__init__(params)

    def csv_event_logs(self):
        super(Windows2003ServerEvt, self)._csv_event_logs(True)

    def json_event_logs(self):
        super(Windows2003ServerEvt, self)._json_event_logs(True)