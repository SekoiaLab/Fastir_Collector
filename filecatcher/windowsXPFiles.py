from __future__ import unicode_literals
from fileCatcher import _FileCatcher
from utils.vss import _VSS
import os


class WindowsXPFiles(_FileCatcher):
    def __init__(self, params):
        super(WindowsXPFiles, self).__init__(params)
        drive, p = os.path.splitdrive(self.systemroot)
        self.vss = None
        try:
            self.vss = _VSS._get_instance(params, drive)
        except Exception as e:
            self.logger.warn("Shadow Copy Erreur")

    def _changeroot(self, dir):
        if self.vss:
            drive, p = os.path.splitdrive(dir)
            path_return = self.vss._return_root() + p
            return path_return
        return dir

    def _list_files(self):
        return super(WindowsXPFiles, self)._list_files()

    def csv_print_infos_files(self):
        super(WindowsXPFiles, self)._csv_infos_fs(self._list_files())

    def json_print_infos_files(self):
        super(WindowsXPFiles, self)._json_infos_fs(self._list_files())