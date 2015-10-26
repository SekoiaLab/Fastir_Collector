from __future__ import unicode_literals
from memory.mem import _Memory


class Windows8Memory(_Memory):
    def __init__(self, params):
        super(Windows8Memory, self).__init__(params)

    def csv_all_modules_dll(self):
        super(Windows8Memory, self)._csv_all_modules_dll()

    def csv_all_modules_opened_files(self):
        super(Windows8Memory, self)._csv_all_modules_opened_files()
