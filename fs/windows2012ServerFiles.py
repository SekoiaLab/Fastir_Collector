# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import os
from fs import _FS
from utils.vss import _VSS


class Windows2012ServerFiles(_FS):
    def __init__(self, params):
        super(Windows2012ServerFiles, self).__init__(params)
        self.userprofile = params['USERPROFILE']
        drive, p = os.path.splitdrive(self.systemroot)
        self.vss = _VSS._get_instance(params, drive)

    def __list_named_pipes(self):
        return super(Windows2012ServerFiles, self)._list_named_pipes()

    def _list_windows_prefetch(self):
        return super(Windows2012ServerFiles, self)._list_windows_prefetch()

    def _chrome_history(self):
        return super(Windows2012ServerFiles, self)._chrome_history(
            '\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History')

    def _firefox_history(self):
        return super(Windows2012ServerFiles, self)._firefox_history(
            '\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite')

    def csv_print_list_named_pipes(self):
        super(Windows2012ServerFiles, self)._csv_list_named_pipes(self._list_named_pipes())

    def csv_print_list_windows_prefetch(self):
        super(Windows2012ServerFiles, self)._csv_windows_prefetch(self._list_windows_prefetch())

    def csv_skype_history(self):
        super(Windows2012ServerFiles, self)._skype_history(['AppData\\Roaming\\Skype'])

    def csv_ie_history(self):
        super(Windows2012ServerFiles, self)._ie_history(['AppData\\Local\\Microsoft\\Windows\\*\\History.IE5',
                                                         'AppData\\Local\\Microsoft\\Windows\\*\\Low\\History.IE5'])

    def csv_firefox_downloads(self):
        # TODO: make sure it works
        super(Windows2012ServerFiles, self)._firefox_downloads(
            ['AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\downloads.sqlite'])

    def csv_firefox_history(self):
        super(Windows2012ServerFiles, self)._csv_firefox_history(self._firefox_history())

    def csv_chrome_history(self):
        super(Windows2012ServerFiles, self)._csv_chrome_history(self._chrome_history())

    def csv_get_startup_files(self):
        super(Windows2012ServerFiles, self)._csv_get_startup_files(
            self.userprofile + '\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*')

    def json_print_list_named_pipes(self):
        super(Windows2012ServerFiles, self)._json_list_named_pipes(self._list_named_pipes())

    def json_print_list_windows_prefetch(self):
        super(Windows2012ServerFiles, self)._json_windows_prefetch(self._list_windows_prefetch())

    def json_skype_history(self):
        super(Windows2012ServerFiles, self)._skype_history(['AppData\\Roaming\\Skype'])

    def json_ie_history(self):
        super(Windows2012ServerFiles, self)._ie_history(['AppData\\Local\\Microsoft\\Windows\\*\\History.IE5',
                                                         'AppData\\Local\\Microsoft\\Windows\\*\\Low\\History.IE5'])

    def json_firefox_downloads(self):
        # TODO: make sure it works
        super(Windows2012ServerFiles, self)._firefox_downloads(
            ['AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\downloads.sqlite'])

    def json_firefox_history(self):
        super(Windows2012ServerFiles, self)._json_firefox_history(self._firefox_history())

    def json_chrome_history(self):
        super(Windows2012ServerFiles, self)._json_chrome_history(self._chrome_history())

    def json_get_startup_files(self):
        super(Windows2012ServerFiles, self)._json_get_startup_files(
            self.userprofile + '\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*')
