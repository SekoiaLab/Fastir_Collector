from __future__ import unicode_literals
from memory.mem import _Memory


class Windows2012ServerR2Memory(_Memory):
    def __init__(self, params):
        super(Windows2012ServerR2Memory, self).__init__(params)

    def csv_all_modules_dll(self):
        super(Windows2012ServerR2Memory, self)._csv_all_modules_dll()

    def csv_all_modules_opened_files(self):
        super(Windows2012ServerR2Memory, self)._csv_all_modules_opened_files()