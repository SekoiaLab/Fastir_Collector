from __future__ import unicode_literals
from memory.mem import _Memory


class WindowsVistaMemory(_Memory):
    def __init__(self, params):
        super(WindowsVistaMemory, self).__init__(params)

    def csv_all_modules_dll(self):
        super(WindowsVistaMemory, self)._csv_all_modules_dll()

    def csv_all_modules_opened_files(self):
        super(WindowsVistaMemory, self)._csv_all_modules_opened_files()