from __future__ import unicode_literals
from memory.mem import _Memory


class Windows7Memory(_Memory):
    def __init__(self, params):
        super(Windows7Memory, self).__init__(params)

    def csv_all_modules_dll(self):
        super(Windows7Memory, self)._csv_all_modules_dll()

    def csv_all_modules_opened_files(self):
        super(Windows7Memory, self)._csv_all_modules_opened_files()
