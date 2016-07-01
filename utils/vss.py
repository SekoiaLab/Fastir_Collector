# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import win32com.client
import wmi
import mmap
import hashlib
import os


class _VSS(object):
    """
    _VSS is a singleton aimed at creating a shadow copy of the disk
    in order to access files that are locked by the system
    """

    # instances: static variable to save the current instance for each drive
    __instances = None

    @staticmethod
    def _get_instance(params, drive=os.environ['SYSTEMDRIVE']):
        if not _VSS.__instances:
            _VSS.__instances = {}
        if drive not in _VSS.__instances:
            _VSS.__instances[drive] = _VSS(params, drive + "\\")
        return _VSS.__instances[drive]

    @staticmethod
    def _close_instances():
        if _VSS.__instances:
            for instance in _VSS.__instances:
                _VSS.__instances[instance].delete()
            _VSS.__instances = None

    def __init__(self, params, volume):
        self.uid = self.create_shadow_copy(volume)
        self.sh = self.select_shadow_copy()
        self.logger = params['logger']
        self.logger.info('Create Shadow Copy for %s %s' % (volume, str(self.uid)))

    def _return_root(self):
        return unicode(self.sh.DeviceObject)

    def _search_a_file(self, path):
        drive, p = os.path.splitdrive(path)
        path_return = unicode(self.sh.DeviceObject) + p
        # print self.sh.DeviceObject
        return path_return

    @staticmethod
    def create_shadow_copy(volume):
        wmi_instance = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_ShadowCopy")
        createmethod = wmi_instance.Methods_("Create")
        createparams = createmethod.InParameters
        createparams.Properties_[1].value = volume
        createparams.Properties_[0].value = "ClientAccessible"
        results = wmi_instance.ExecMethod_("Create", createparams)
        uid = results.Properties_[1].value
        return uid

    def delete(self):
        self.logger.info('Delete Shadow Copy ' + str(self.uid))
        objWMIService = win32com.client.GetObject("winmgmts:\\\\.\\root\\cimv2")
        colItems = objWMIService.ExecQuery("Select * From Win32_ShadowCopy")
        for objItem in colItems:
            if objItem.ID == self.uid:
                objItem.Delete_()

    def select_shadow_copy(self):
        wmi_instance = wmi.WMI()
        list_shadowCopy = wmi_instance.Win32_ShadowCopy()
        for sh in list_shadowCopy:
            if sh.ID == self.uid:
                return sh

    @staticmethod
    def list_shadow_copy():
        wmi_instance = wmi.WMI()
        list_shadowCopy = wmi_instance.Win32_ShadowCopy()
        for sh in list_shadowCopy:
            print sh

    @staticmethod
    def process_hash_value(path):
        with open(path, 'rb') as f:
            try:
                mem_map = mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)
                sha256 = hashlib.sha256(mem_map)
                md5 = hashlib.md5(mem_map)
                sha1 = hashlib.sha1(mem_map)
                mem_map.close()
                return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
            except ValueError:
                return ""
