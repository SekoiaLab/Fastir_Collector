# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from logs import _EventLogs


class WindowsVistaEvt(_EventLogs):
    def __init__(self, params):
        super(WindowsVistaEvt, self).__init__(params)

    def csv_event_logs(self):
        super(WindowsVistaEvt, self)._csv_event_logs(False)


    def json_event_logs(self):
        super(WindowsVistaEvt, self)._json_event_logs(False)
