from __future__ import unicode_literals
from memory.mem import _Memory


class Windows10Memory(_Memory):
    def __init__(self, params):
        super(Windows10Memory, self).__init__(params)

    def csv_all_modules_dll(self):
        super(Windows10Memory, self)._csv_all_modules_dll()

    def csv_all_modules_opened_files(self):
        super(Windows10Memory, self)._csv_all_modules_opened_files()

    def json_all_modules_dll(self):
        super(Windows10Memory, self)._json_all_modules_dll()

    def json_all_modules_opened_files(self):
        super(Windows10Memory, self)._json_all_modules_opened_files()