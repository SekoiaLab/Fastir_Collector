from __future__ import unicode_literals
from filecatcher.fileCatcher import _FileCatcher


class WindowsVistaFiles(_FileCatcher):
    def __init__(self, params):
        super(WindowsVistaFiles, self).__init__(params)

    def _list_files(self):
        return super(WindowsVistaFiles, self)._list_files

    def csv_print_infos_files(self):
        super(WindowsVistaFiles, self)._csv_infos_fs(self._list_files())

    def json_print_infos_files(self):
        super(WindowsVistaFiles, self)._json_infos_fs(self._list_files())
