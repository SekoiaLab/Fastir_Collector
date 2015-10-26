from __future__ import unicode_literals
from memory.mem import _Memory


class WindowsXPMemory(_Memory):
    def __init__(self, params):
        super(WindowsXPMemory, self).__init__(params)

    def csv_all_modules_dll(self):
        super(WindowsXPMemory, self)._csv_all_modules_dll()

    def csv_all_modules_opened_files(self):
        super(WindowsXPMemory, self)._csv_all_modules_opened_files()