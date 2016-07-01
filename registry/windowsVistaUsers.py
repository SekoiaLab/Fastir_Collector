from __future__ import unicode_literals
from registry.reg import _Reg


class WindowsVistaUserReg(_Reg):
    def __init__(self, params):
        _Reg.__init__(self, params)
        _Reg.init_win_vista_and_above(self)

    def csv_open_save_mru(self):
        super(WindowsVistaUserReg, self)._csv_open_save_mru(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU")

    def csv_user_assist(self):
        super(WindowsVistaUserReg, self)._csv_user_assist(-6, False)

    def csv_networks_list(self):
        super(WindowsVistaUserReg, self)._csv_networks_list(
            r'Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles')

    def json_open_save_mru(self):
        super(WindowsVistaUserReg, self)._json_open_save_mru(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU")

    def json_user_assist(self):
        super(WindowsVistaUserReg, self)._json_user_assist(0, False)

    def json_networks_list(self):
        super(WindowsVistaUserReg, self)._json_networks_list(
            r'Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles')