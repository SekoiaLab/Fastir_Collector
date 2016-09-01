from __future__ import unicode_literals
from _winreg import QueryInfoKey, OpenKey, EnumKey, EnumValue
import _winreg
import utils.utils
import importlib

pyregf = importlib.import_module("_x" + utils.utils.get_architecture() + ".pyregf")

HKEY_LOCAL_MACHINE = _winreg.HKEY_LOCAL_MACHINE
HKEY_CURRENT_USER = _winreg.HKEY_CURRENT_USER
HKEY_USERS = _winreg.HKEY_USERS


def get_userprofiles_from_reg():
    """Retrieves and returns the userprofiles from the registry"""
    # SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList contains a list of subkeys representing SIDs
    list_profiles = []
    users = get_registry_key(HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
    if users:
        for i in xrange(users.get_number_of_sub_keys()):
            user = users.get_sub_key(i)
            list_profiles.append(user.get_value_by_name("ProfileImagePath").get_data())
    return list_profiles


def get_str_type(reg_type):
    if reg_type == _winreg.REG_BINARY:
        return "REG_BINARY"
    elif reg_type == _winreg.REG_DWORD:
        return "REG_DWORD"
    elif reg_type == _winreg.REG_DWORD_BIG_ENDIAN:
        return "REG_DWORD_BIG_ENDIAN"
    elif reg_type == _winreg.REG_DWORD_LITTLE_ENDIAN:
        return "REG_DWORD_LITTLE_ENDIAN"
    elif reg_type == _winreg.REG_EXPAND_SZ:
        return "REG_EXPAND_SZ"
    elif reg_type == _winreg.REG_LINK:
        return "REG_LINK"
    elif reg_type == _winreg.REG_MULTI_SZ:
        return "REG_MULTI_SZ"
    elif reg_type == _winreg.REG_SZ:
        return "REG_SZ"


def get_registry_key(hive, path=""):
    try:
        OpenKey(hive, path)
        return RegistryKey(hive, path)
    except WindowsError:
        return None


class RegistryKey(object):
    def __init__(self, hive, path=""):
        self.path = path
        self.hive = hive
        if path != "":
            self.key = OpenKey(self.hive, path)
        else:
            self.key = self.hive

    def get_last_written_time(self):
        return utils.utils.convert_windate(QueryInfoKey(self.key)[2])

    def get_name(self):
        if self.path != "":
            return self.path.split("\\")[-1]
        return ""

    def get_sub_keys_names(self):
        l = []
        for i in xrange(self.get_number_of_sub_keys()):
            l.append(EnumKey(self.key, i))
        return l
    
    def get_number_of_sub_keys(self):
        return QueryInfoKey(self.key)[0]

    def get_number_of_values(self):
        return QueryInfoKey(self.key)[1]

    def get_sub_key(self, index):
        try:
            if self.path != "":
                return RegistryKey(self.hive, self.path + "\\" + EnumKey(self.key, index))
            else:
                return RegistryKey(self.hive, EnumKey(self.key, index))
        except WindowsError:
            return None

    def get_sub_key_by_name(self, name):
        try:
            OpenKey(self.key, name)
            if self.path != "":
                return RegistryKey(self.hive, self.path + "\\" + name)
            else:
                return RegistryKey(self.hive, name)
        except WindowsError:
            return None

    def get_sub_key_by_path(self, path):
        try:
            OpenKey(self.key, path)
            if self.path != "":
                return RegistryKey(self.hive, self.path + "\\" + path)
            else:
                return RegistryKey(self.hive, path)
        except WindowsError:
            return None

    def get_value(self, index):
        return RegValue(EnumValue(self.key, index), self.path)

    def get_value_by_name(self, name):
        for i in range(self.get_number_of_values()):
            value = EnumValue(self.key, i)
            if name == value[0]:
                return RegValue(value, name)
        return None

    def get_path(self):
        return self.path


class RegValue(object):
    def __init__(self, value, path):
        self.value = value
        self.path = path

    def get_data(self):
        return self.value[1]

    def get_name(self):
        return self.value[0]

    def get_type(self):
        return self.value[2]

    def get_path(self):
        return self.path

    def get_full_path(self):
        return self.path + "\\" + self.get_name()


class RegfFile(object):
    def __init__(self):
        self.file = pyregf.file()

    def get_root_key(self):
        return RegfKey(self.file.get_root_key(), "")

    def get_key_by_path(self, path):
        return RegfKey(self.file.get_key_by_path(path), path)

    def __getattr__(self, function):
        return getattr(self.file, function)


class RegfKey(object):
    def __init__(self, key, path):
        self.key = key
        self.path = path

    def get_last_written_time(self):
        return self.key.get_last_written_time().strftime('%Y-%m-%d %H:%M:%S')

    def get_sub_key(self, index):
        sub_key = self.key.get_sub_key(index)
        if self.path != "":
            return RegfKey(sub_key, self.path + "\\" + sub_key.get_name())
        else:
            return RegfKey(sub_key, sub_key.get_name())

    def get_sub_key_by_name(self, name):
        sub_key = self.key.get_sub_key_by_name(name)
        if sub_key:
            if self.path != "":
                return RegfKey(sub_key, self.path + "\\" + name)
            else:
                return RegfKey(sub_key, name)
        return None

    def get_sub_key_by_path(self, path):
        sub_key = self.key.get_sub_key_by_path(path)
        if sub_key:
            if self.path != "":
                return RegfKey(sub_key, self.path + "\\" + path)
            else:
                return RegfKey(sub_key, path)
        return None

    def get_value(self, index):
        return RegfValue(self.key.get_value(index), self.path)

    def get_value_by_name(self, name):
        for i in range(self.get_number_of_values()):
            value = self.key.get_value(i)
            if name == value[0]:
                return RegfValue(value, name)
        return None

    def get_path(self):
        return self.path

    def prepend_path_with_sid(self, sid):
        self.path = sid + "\\" + self.path

    def __getattr__(self, function):
        return getattr(self.key, function)


class RegfValue(object):
    def __init__(self, value, path):
        self.value = value
        self.path = path

    def get_path(self):
        return self.path

    def get_full_path(self):
        return self.path + "\\" + self.get_name()

    def __getattr__(self, function):
        return getattr(self.value, function)
