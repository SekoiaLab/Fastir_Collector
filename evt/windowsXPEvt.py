# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from logs import _EventLogs


class WindowsXPEvt(_EventLogs):
    def __init__(self, params):
        super(WindowsXPEvt, self).__init__(params)

    def csv_event_logs(self):
        super(WindowsXPEvt, self)._csv_event_logs(True)

    def json_event_logs(self):
        super(WindowsXPEvt, self)._json_event_logs(True)
