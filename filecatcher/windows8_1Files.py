# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import os

from filecatcher.fileCatcher import _FileCatcher
from utils.vss import _VSS


class Windows8_1Files(_FileCatcher):
    def __init__(self, params):
        super(Windows8_1Files, self).__init__(params)
        drive, p = os.path.splitdrive(self.systemroot)
        self.vss = _VSS._get_instance(params, drive)

    def _changeroot(self, dir):
        drive, p = os.path.splitdrive(dir)
        path_return = self.vss._return_root() + p
        return path_return

    def csv_print_infos_files(self):
        super(Windows8_1Files, self)._csv_infos_fs(self._list_files())

    def json_print_infos_files(self):
        super(Windows8_1Files, self)._json_infos_fs(self._list_files())
