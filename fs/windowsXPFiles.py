# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from fs import _FS


class WindowsXPFiles(_FS):
    def __init__(self, params):
        super(WindowsXPFiles, self).__init__(params)

    def __list_named_pipes(self):
        return super(WindowsXPFiles, self)._list_named_pipes()

    def _list_windows_prefetch(self):
        return super(WindowsXPFiles, self)._list_windows_prefetch()

    def _firefox_history(self):
        return super(WindowsXPFiles, self)._firefox_history(
            '\\Documents and Settings\\*\\Application Data\\Mozilla\\Firefox\\Profiles\\*.default\places.sqlite')

    def csv_print_list_named_pipes(self):
        super(WindowsXPFiles, self)._csv_list_named_pipes(self._list_named_pipes())

    def csv_print_list_windows_prefetch(self):
        super(WindowsXPFiles, self)._csv_windows_prefetch(self._list_windows_prefetch())

    def csv_skype_history(self):
        super(WindowsXPFiles, self)._skype_history(['Application Data\Skype'])

    def csv_ie_history(self):
        super(WindowsXPFiles, self)._ie_history(['Local Settings\*\History.IE5'])

    def csv_firefox_downloads(self):
        super(WindowsXPFiles, self)._firefox_downloads(
            ['Application Data\Mozilla\Firefox\Profiles\*.default\downloads.sqlite'])

    def csv_firefox_history(self):
        super(WindowsXPFiles, self)._csv_firefox_history(self._firefox_history())


    def json_print_list_named_pipes(self):
        super(WindowsXPFiles, self)._json_list_named_pipes(self._list_named_pipes())

    def json_print_list_windows_prefetch(self):
        super(WindowsXPFiles, self)._json_windows_prefetch(self._list_windows_prefetch())

    def json_skype_history(self):
        super(WindowsXPFiles, self)._skype_history(['Application Data\Skype'])

    def json_ie_history(self):
        super(WindowsXPFiles, self)._ie_history(['Local Settings\*\History.IE5'])

    def json_firefox_downloads(self):
        super(WindowsXPFiles, self)._firefox_downloads(
            ['Application Data\Mozilla\Firefox\Profiles\*.default\downloads.sqlite'])

    def json_firefox_history(self):
        super(WindowsXPFiles, self)._json_firefox_history(self._firefox_history())
