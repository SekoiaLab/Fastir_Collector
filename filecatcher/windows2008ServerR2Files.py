# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os

from fileCatcher import _FileCatcher
from utils.vss import _VSS


class Windows2008ServerR2Files(_FileCatcher):
    def __init__(self, params):
        super(Windows2008ServerR2Files, self).__init__(params)
        drive, p = os.path.splitdrive(self.systemroot)
        self.vss = _VSS._get_instance(params, drive)

    def _changeroot(self, dir):
        drive, p = os.path.splitdrive(dir)
        path_return = self.vss._return_root() + p
        return path_return

    def _list_files(self):
        return super(Windows2008ServerR2Files, self)._list_files

    def __list_named_pipes(self):
        return super(Windows2008ServerR2Files, self)._list_named_pipes()

    def _list_windows_prefetch(self):
        return super(Windows2008ServerR2Files, self)._list_windows_prefetch()

    def csv_print_infos_files(self):
        super(Windows2008ServerR2Files, self)._csv_infos_fs(self._list_files())

    def csv_print_list_named_pipes(self):
        super(Windows2008ServerR2Files, self)._csv_list_named_pipes(self._list_named_pipes())

    def csv_print_list_windows_prefetch(self):
        super(Windows2008ServerR2Files, self)._csv_windows_prefetch(self._list_windows_prefetch())

    def csv_skype_history(self):
        super(Windows2008ServerR2Files, self)._skype_history(['AppData\Roaming\Skype'])

    def csv_ie_history(self):
        super(Windows2008ServerR2Files, self)._ie_history(['AppData\Local\Microsoft\Windows\*\History.IE5',
                                                           'AppData\Local\Microsoft\Windows\*\Low\History.IE5'])

    def csv_firefox_downloads(self):
        # TODO: make sure it works
        super(Windows2008ServerR2Files, self)._firefox_downloads(
            ['AppData\Roaming\Mozilla\Firefox\Profiles\*.default\downloads.sqlite'])
