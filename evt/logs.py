# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import win32evtlog
from utils.utils import get_csv_writer, write_to_csv
import datetime
import os

# UserID is a SID to convert
hevt_to_write = {'Channel': '', 'EventID': '', 'Execution': 'ProcessID', 'Level': '', 'Provider': 'Name',
                 'Security': 'UserID', 'TimeCreated': 'SystemTime'}


class _EventLogs(object):
    def __init__(self, params):
        self.output_dir = params['output_dir']
        self.computer_name = params['computer_name']
        self.logger = params['logger']
        self.rand_ext = params['rand_ext']

    def _list_evt_vista(self, _, logtype):
        """Retrieves the contents of the event log for Windows Vista and later"""
        self.logger.info('Processing evtx : ' + logtype)
        try:
            win32evtlog.EvtExportLog(logtype,
                                     self.output_dir + '\\evt\\' + self.computer_name + '_' + logtype.replace('/', '_')
                                     + '.evtx',
                                     1)
        except win32evtlog.error:
            self.logger.error('Error while processing evtx : ' + logtype)

    def _list_evt_xp(self, server, logtype):
        """Retrieves the contents of the event log for Windows XP"""
        self.logger.info('Exporting logs for : ' + logtype)
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        sum_evt = 0
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            sum_evt += len(events)
            if events:
                for event in events:
                    data = event.StringInserts
                    date = datetime.datetime(event.TimeGenerated.year, event.TimeGenerated.month,
                                             event.TimeGenerated.day, event.TimeGenerated.hour,
                                             event.TimeGenerated.minute, event.TimeGenerated.second).strftime(
                        '%d/%m/%Y %H:%M:%S')

                    # print date + ' : ' + log_type + ' -> ' + log_data
                    if data:
                        yield unicode(event.EventCategory), unicode(event.SourceName), unicode(event.EventID), unicode(
                            event.EventType), date, list(data)
                    else:
                        yield unicode(event.EventCategory), unicode(event.SourceName), unicode(event.EventID), unicode(
                            event.EventType), date, []
            if sum_evt >= total:
                break

    def _csv_event_logs(self, is_win_xp):
        """Prints the event logs in a csv, the called method is different for WinXP and lower"""
        server = None  # name of the target computer to get event logs, None to get logs from current computer
        with open(self.output_dir + '\\' + self.computer_name + '_evts' + self.rand_ext, 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            if is_win_xp:
                for eventCategory, sourceName, eventID, eventType, date, log in self._list_evt_xp(server, 'Security'):
                    write_to_csv([self.computer_name, 'Logs', 'Security', eventCategory, sourceName, eventID, eventType,
                                  date] + log, csv_writer)
                for eventCategory, sourceName, eventID, eventType, date, log in self._list_evt_xp(server,
                                                                                                  'Application'):
                    write_to_csv(
                        [self.computer_name, 'Logs', 'Application', eventCategory, sourceName, eventID, eventType,
                         date] + log, csv_writer)
                for eventCategory, sourceName, eventID, eventType, date, log in self._list_evt_xp(server, 'System'):
                    write_to_csv([self.computer_name, 'Logs', 'System', eventCategory, sourceName, eventID, eventType,
                                  date] + log, csv_writer)
            else:
                # Exports everything from the event viewer
                evt_handle = win32evtlog.EvtOpenChannelEnum()
                os.mkdir(self.output_dir + r"\evt")
                while True:
                    # opening channel for enumeration
                    logtype = win32evtlog.EvtNextChannelPath(evt_handle)
                    if logtype is None:
                        break
                        # fw.write('"Computer Name"|"Type"|"Date"|"logtype"|"log data"\n')
                    self._list_evt_vista(server, logtype)
