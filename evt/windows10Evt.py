# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from logs import _EventLogs


class Windows10Evt(_EventLogs):
    def __init__(self, params):
        super(Windows10Evt, self).__init__(params)

    def csv_event_logs(self):
        super(Windows10Evt, self)._csv_event_logs(False)
