from __future__ import unicode_literals
import codecs
from utils.utils import convert_windate, dosdate, get_csv_writer, get_json_writer, write_list_to_json, write_dict_json, \
    write_list_to_csv, process_hashes
import registry_obj
from win32com.shell import shell
import struct
import construct
import StringIO
import os
from csv import reader
from utils.vss import _VSS
import re
from utils.utils import regex_patern_path
import os
from filecatcher.archives import _Archives
import datetime

KEY_VALUE_STR = 0
VALUE_NAME = 1
VALUE_DATA = 2
VALUE_TYPE = 3
VALUE_LAST_WRITE_TIME = 4
VALUE_PATH = 5

KEY_PATH = 1
KEY_LAST_WRITE_TIME = 2


def get_usb_key_info(key_name):
    """
    Extracts information about the USB keys from the registry
    :return: A list of USB key IDs
    """
    # HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}
    str_reg_key_usbinfo = r"SYSTEM\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}"

    # here is a sample of a key_name
    # ##?#USBSTOR#Disk&Ven_&Prod_USB_DISK_2.0&Rev_PMAP#07BC13025A3B03A1&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
    # the logic is : there are 6 "#" so we should split this string on "#" and get the USB id (index 5)
    index_usb_id = 5
    usb_id = key_name.split("#")[index_usb_id]
    # now we want only the left part of the which may contain another separator "&" -> 07BC13025A3B03A1&0
    usb_id = usb_id.split("&")[0]

    # next we look in the registry for such an id
    key_ids = ""
    reg_key_info = registry_obj.get_registry_key(registry_obj.HKEY_LOCAL_MACHINE, str_reg_key_usbinfo)
    if reg_key_info:
        for i in xrange(reg_key_info.get_number_of_sub_keys()):
            subkey = reg_key_info.get_sub_key(i)
            if usb_id in subkey.get_name():
                # example of a key_info_name
                # ##?#USB#VID_26BD&PID_9917#0702313E309E0863#{a5dcbf10-6530-11d2-901f-00c04fb951ed}
                # the pattern is quite similar, a "#" separated string, with 5 as key id and 4 as VID&PID, we need
                # those 2
                index_usb_id = 4
                key_ids = subkey.get_name().split("#")[index_usb_id]
                break
    return key_ids


def csv_user_assist_value_decode_win7_and_after(str_value_datatmp, count_offset):
    """The value in user assist has changed since Win7. It is taken into account here."""
    # 16 bytes data
    str_value_data_session = str_value_datatmp[0:4]
    str_value_data_session = unicode(struct.unpack("<I", str_value_data_session)[0])
    str_value_data_count = str_value_datatmp[4:8]
    str_value_data_count = unicode(struct.unpack("<I", str_value_data_count)[0] + count_offset + 1)
    str_value_data_focus = str_value_datatmp[12:16]
    str_value_data_focus = unicode(struct.unpack("<I", str_value_data_focus)[0])
    str_value_data_timestamp = str_value_datatmp[60:68]
    try:
        timestamp = struct.unpack("<Q", str_value_data_timestamp)[0]
        date_last_exec = convert_windate(timestamp)
    except ValueError:
        date_last_exec = None
    arr_data = [str_value_data_session, str_value_data_count, str_value_data_focus]
    if date_last_exec:
        arr_data.append(date_last_exec)
    else:
        arr_data.append("")
    return arr_data


def csv_user_assist_value_decode_before_win7(str_value_datatmp, count_offset):
    """
    The Count registry key contains values representing the programs
    Each value is separated as :
    first 4 bytes are session
    following 4 bytes are number of times the program has been run
    next 8 bytes are the timestamp of last execution
    each of those values are in big endian which have to be converted in little endian
    :return: An array containing these information
    """

    # 16 bytes data
    str_value_data_session = str_value_datatmp[0:4]
    str_value_data_session = unicode(struct.unpack("<I", str_value_data_session)[0])
    str_value_data_count = str_value_datatmp[4:8]
    str_value_data_count = unicode(struct.unpack("<I", str_value_data_count)[0] + count_offset + 1)
    str_value_data_timestamp = str_value_datatmp[8:16]
    try:
        timestamp = struct.unpack("<Q", str_value_data_timestamp)[0]
        date_last_exec = convert_windate(timestamp)
    except ValueError:
        date_last_exec = None
    arr_data = [str_value_data_session, str_value_data_count]
    if date_last_exec:
        arr_data.append(date_last_exec)
    else:
        arr_data.append("")
    return arr_data


def decode_itempos(itempos):
    """
    Decodes a single itempos and returns extracted information
    """
    itempos_io = StringIO.StringIO(itempos)
    itempos_struct = construct.Struct("itempos",
                                      construct.ULInt16("itempos_size"),
                                      construct.Padding(2),
                                      construct.ULInt32("filesize"),
                                      construct.Bytes("dos_date", 2),
                                      construct.Bytes("dos_time", 2),
                                      construct.ULInt16("file_attr"),
                                      construct.CString("filename")
                                      )
    parse_res = itempos_struct.parse_stream(itempos_io)
    if itempos_io.pos % 2 == 1:
        itempos_io.read(1)
    ext_struct = construct.Struct("ext",
                                  construct.ULInt16("ext_size"),
                                  construct.ULInt16("ext_version")
                                  )
    parse_ext = ext_struct.parse_stream(itempos_io)
    if parse_ext["ext_version"] >= 0x3:
        itempos2_struct = construct.Struct("itempos2",
                                           construct.Padding(2),  # 0004
                                           construct.Padding(2),  # BEEF
                                           construct.Bytes("creation_dos_date", 2),
                                           construct.Bytes("creation_dos_time", 2),
                                           construct.Bytes("access_dos_date", 2),
                                           construct.Bytes("access_dos_time", 2),
                                           construct.Padding(4)
                                           )
        parse_res2 = itempos2_struct.parse_stream(itempos_io)
    unicode_filename = ""
    if parse_ext["ext_version"] >= 0x7:
        itempos3_struct = construct.Struct("itempos3",
                                           construct.ULInt64("file_ref"),
                                           construct.Padding(8),
                                           construct.Padding(2)
                                           )
        parse_res3 = itempos3_struct.parse_stream(itempos_io)
        if parse_ext["ext_version"] >= 0x8:
            itempos4_struct = construct.Struct("itempos4",
                                               construct.Padding(4)
                                               )
            itempos4_struct.parse_stream(itempos_io)
        tmp = itempos_io.read()
        unicode_filename = tmp.decode("utf16")
        if not unicode_filename.endswith("\0"):
            unicode_filename = unicode_filename[:-2]  # ditch last unused 2 bytes and \0 char
    elif parse_ext["ext_version"] >= 0x3:
        unicode_filename = itempos_io.read().decode("utf16")
        if not unicode_filename.endswith("\0"):
            unicode_filename = unicode_filename[:-2]  # ditch last unused 2 bytes and \0 char

    timestamp_modified = dosdate(parse_res["dos_date"], parse_res["dos_time"]).strftime("%d/%m/%Y %H:%M:%S")
    timestamp_created = dosdate(parse_res2["creation_dos_date"], parse_res2["creation_dos_time"]).strftime(
        "%d/%m/%Y %H:%M:%S")
    timestamp_access = dosdate(parse_res2["access_dos_date"], parse_res2["access_dos_time"]).strftime(
        "%d/%m/%Y %H:%M:%S")

    return [unicode(parse_res["itempos_size"]), unicode(parse_res["filesize"]), timestamp_modified,
            parse_res["filename"], timestamp_created, timestamp_access, unicode_filename]


def decode_shellbag_itempos_data(data):
    """
    @see: http://www.williballenthin.com/forensics/shellbags/
    :param data: The data of the registry key that needs decoding
    :return: A list of readable filenames
    """
    header_len = 0x10
    unused_len = 0x14
    padding_len = 0x8
    tmp_data = data[header_len:]
    decoded_itempos = []
    while True:
        tmp_data = tmp_data[padding_len:]  # padding
        itempos_len = struct.unpack("<h", tmp_data[:2])[0]
        if itempos_len == 0:
            # end of shellbags
            break
        elif itempos_len == unused_len:
            # SHITEMID, unknown usage
            tmp_data = tmp_data[itempos_len:]
            continue
        itempos = tmp_data[:itempos_len]
        tmp_data = tmp_data[itempos_len:]
        decoded_itempos.append(decode_itempos(itempos))
    return decoded_itempos


def append_reg_values(hive_list, key):
    for i in xrange(key.get_number_of_values()):
        value = key.get_value(i)
        hive_list.append(("VALUE", value.get_name(), value.get_data(), value.get_type(), key.get_last_written_time(),
                          value.get_path()))


def decode_recent_docs_mru(value):
    """
    Decodes recent docs MRU list
    Returns an array with 1st element being the filename, the second element being the symbolic link name
    """
    value_decoded = []
    index = value.find(b"\x00\x00")
    try:
        decoded = value[0:index + 1].decode("utf-16-le")
    except UnicodeDecodeError:
        try:
            decoded = value[0:index + 1].decode("utf-8")
        except UnicodeDecodeError:
            decoded = "".join([c for c in value[0:index + 1]])

    value_decoded.append(decoded)
    # index+3 because the last char also ends with \x00 + null bytes \x00\x00, +14 is the offset for the link name
    index_end_link_name = value.find(b"\x00", index + 3 + 14)
    value_decoded.append(value[index + 3 + 14:index_end_link_name])
    return value_decoded


def construct_list_from_key(hive_list, key, is_recursive=True):
    """
    Constructs the hive list. Recursive method if is_recursive=True.
    Keyword arguments:
    hive_list -- (List) the list to append to
    key -- (RegistryKey) the key to dump in the list
    """
    hive_list.append(("KEY", key.get_path(), key.get_last_written_time()))
    append_reg_values(hive_list, key)
    for i in xrange(key.get_number_of_sub_keys()):
        try:
            sub_key = key.get_sub_key(i)
        except TypeError:
            # hack for programs using unicode in registry
            for j in xrange(len(hive_list) - 1, 0, -1):
                if hive_list[j][KEY_VALUE_STR] == "KEY":
                    # get the first VALUE item in the list
                    j += 1
                    break
            if hive_list[j][VALUE_NAME] == "":
                tmp = hive_list[j]
                list_names = key.get_sub_keys_names()
                value_name = ""
                for name in list_names:
                    if "\x00" in name:
                        # invalid registry name
                        value_name = "\\x" + "\\x".join("{:02x}".format(ord(c)) for c in name)
                # replace the name of the first VALUE item by the name of the invalid registry name
                hive_list[j] = (tmp[KEY_VALUE_STR], value_name, tmp[VALUE_DATA], tmp[VALUE_TYPE],
                                tmp[VALUE_LAST_WRITE_TIME], tmp[VALUE_PATH])
            sub_key = None
        if sub_key and is_recursive:
            construct_list_from_key(hive_list, sub_key, is_recursive)


class _Reg(object):
    def __init__(self, params):
        if params["output_dir"] and params["computer_name"]:
            self.computer_name = params["computer_name"]
            self.output_dir = params["output_dir"]
        if params['destination']:
            self.destination = params['destination']
        if params["custom_registry_keys"]:
            self.exec_custom_registry_keys = True
            self.custom_registry_keys = params["custom_registry_keys"]
            self.registry_recursive = params["registry_recursive"]
        else:
            self.exec_custom_registry_keys = False
        self.logger = params["logger"]
        self.systemroot = params['system_root']
        # get logged off users hives
        self.user_hives = []
        self.vss = None
        self.rand_ext = params['rand_ext']
        self.get_autoruns = params['get_autoruns']

    def init_win_xp(self):
        users = registry_obj.get_registry_key(registry_obj.HKEY_LOCAL_MACHINE,
                                              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        if users:
            for i in xrange(users.get_number_of_sub_keys()):
                user = users.get_sub_key(i)
                path = user.get_value_by_name("ProfileImagePath").get_data() + r"\NTUSER.DAT"
                try:
                    regf_file = registry_obj.RegfFile()
                    regf_file.open(path)
                    self.user_hives.append((user.get_name(), regf_file.get_root_key()))
                except IOError:  # user is logged on or not a user
                    pass

    def init_win_vista_and_above(self):
        users = registry_obj.get_registry_key(registry_obj.HKEY_LOCAL_MACHINE,
                                              r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        drive, p = os.path.splitdrive(self.systemroot)
        params = {"logger": self.logger}
        self.vss = _VSS._get_instance(params, drive)
        if users:
            for i in xrange(users.get_number_of_sub_keys()):
                user = users.get_sub_key(i)
                tmp = user.get_value_by_name("ProfileImagePath").get_data()
                path = tmp.replace(drive, self.vss._return_root()) + r"\NTUSER.DAT"
                path_usrclass = tmp.replace(drive,
                                            self.vss._return_root()) + r"\AppData\Local\Microsoft\Windows\\UsrClass.dat"
                try:
                    regf_file = registry_obj.RegfFile()
                    regf_file.open(path)
                    regf_file_usrclass = registry_obj.RegfFile()
                    regf_file_usrclass.open(path_usrclass)
                    self.user_hives.append(
                        (user.get_name(), regf_file.get_root_key(), regf_file_usrclass.get_root_key()))
                except IOError:  # not a user
                    pass

    def _generate_hklm_csv_list(self, to_csv_list, csv_type, path, is_recursive=True):
        """
        Generates a generic list suitable for CSV output.
        Extracts information from HKEY_LOCAL_MACHINE hives.
        """
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_LOCAL_MACHINE, path, is_recursive=is_recursive)
        for item in hive_list:
            if item[KEY_VALUE_STR] in ("VALUE", "ROOT_KEY"):
                try:
                    value_data = item[VALUE_DATA].decode('UTF-16')
                    if '\x00' not in value_data:
                        value_data = item[VALUE_DATA]
                except:
                    value_data = item[VALUE_DATA]

                to_csv_list.append((self.computer_name,
                                    csv_type,
                                    item[VALUE_LAST_WRITE_TIME],
                                    "HKEY_LOCAL_MACHINE",
                                    item[VALUE_PATH],
                                    item[VALUE_NAME],
                                    item[KEY_VALUE_STR],
                                    registry_obj.get_str_type(item[VALUE_TYPE]),
                                    value_data))

    def _generate_hku_csv_list(self, to_csv_list, csv_type, path, is_recursive=True):
        """
        Generates a generic list suitable for CSV output.
        Extracts information from HKEY_USERS hives.
        """
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, path, is_recursive=is_recursive)
        for item in hive_list:
            if item[KEY_VALUE_STR] == "VALUE":

                try:
                    value_data = item[VALUE_DATA].decode('UTF-16')
                    if '\x00' not in value_data:
                        value_data = item[VALUE_DATA]
                except:
                    value_data = item[VALUE_DATA]

                to_csv_list.append((self.computer_name,
                                    csv_type,
                                    item[VALUE_LAST_WRITE_TIME],
                                    "HKEY_USERS",
                                    item[VALUE_PATH],
                                    item[VALUE_NAME],
                                    item[KEY_VALUE_STR],
                                    registry_obj.get_str_type(item[VALUE_TYPE]),
                                    value_data))

    def _get_list_from_users_registry_key(self, key_path, is_recursive=True, is_usrclass=False):
        """
        Extracts information from HKEY_USERS. Since logged off users hives are not mounted by Windows, it is necessary
        to open each NTUSER.DAT files, except for currently logged on users.
        On Windows Vista and later, HKEY_USERS\ID\Software\Classes is in UsrClass.dat.
        On Windows Vista and later, shadow copies are used in order to bypass the lock on HKCU.
        :param key_path: the registry key to list
        :param is_recursive: whether the function should also list subkeys
        :return: a list of all extracted keys/values
        """
        hive_list = []
        key_users = registry_obj.get_registry_key(registry_obj.HKEY_USERS)
        if key_users:
            for i in xrange(key_users.get_number_of_sub_keys()):
                key_user = key_users.get_sub_key(i)
                key_data = key_user.get_sub_key_by_path(key_path)
                if key_data:
                    construct_list_from_key(hive_list, key_data, is_recursive)
        # same thing for logged off users (NTUSER.DAT, UsrClass.dat)
        for sid, root_key_ntuser, root_key_usrclass in self.user_hives:
            if is_usrclass:
                cur_root_key = root_key_usrclass
            else:
                cur_root_key = root_key_ntuser
            key_data = cur_root_key.get_sub_key_by_path(key_path)
            if key_data:
                key_data.prepend_path_with_sid(sid)
                construct_list_from_key(hive_list, key_data, is_recursive)
        return hive_list

    def _get_list_from_registry_key(self, hive, key_path, is_recursive=True, is_usrclass=False):
        """
        Creates a list of all nodes and values from a registry key path.
        Keyword arguments:
        hive -- (String) the hive name
        key_path -- (String) the path of the key from which the list should be created
        """
        if hive == registry_obj.HKEY_USERS:
            return self._get_list_from_users_registry_key(key_path, is_recursive, is_usrclass)
        hive_list = []
        root_key = registry_obj.get_registry_key(hive, key_path)
        if root_key:
            hive_list.append(("ROOT_KEY", root_key.get_name(), "", "", root_key.get_last_written_time(),
                              root_key.get_path()))
            append_reg_values(hive_list, root_key)
            for i in xrange(root_key.get_number_of_sub_keys()):
                sub_key = root_key.get_sub_key(i)
                if sub_key:
                    construct_list_from_key(hive_list, sub_key, is_recursive)
        return hive_list

    def __get_user_assist(self, count_offset, is_win7_or_further):
        """
            Extracts information from UserAssist registry key which contains information about executed programs
            The count offset is for Windows versions before 7, where it would start at 6
            """
        self.logger.info("Extracting user assist")
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\\UserAssist"
        count = "\Count"
        # logged on users
        users = registry_obj.RegistryKey(registry_obj.HKEY_USERS)
        hive_list = []
        for i in xrange(users.get_number_of_sub_keys()):
            user = users.get_sub_key(i)
            user_assist_key = user.get_sub_key_by_path(path)
            if user_assist_key:
                for j in xrange(user_assist_key.get_number_of_sub_keys()):
                    # getting Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
                    path_no_sid = "\\".join(user_assist_key.get_sub_key(j).get_path().split("\\")[1:])
                    hive_list += self._get_list_from_registry_key(registry_obj.HKEY_USERS, path_no_sid + count)
        if is_win7_or_further:
            to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                            "ATTR_TYPE", "ATTR_DATA", "DATA_SESSION", "DATA_COUNT", "DATA_FOCUS", "DATA_LAST_EXEC")]
        else:
            to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                            "ATTR_TYPE", "ATTR_DATA", "DATA_SESSION", "DATA_COUNT", "DATA_LAST_EXEC")]
        for item in hive_list:
            if item[KEY_VALUE_STR] == "VALUE":
                str_value_name = codecs.decode(item[VALUE_NAME], "rot_13")
                str_value_datatmp = item[VALUE_DATA]
                # some data are less than 16 bytes for some reason...
                if len(str_value_datatmp) < 16:
                    to_csv_list.append((self.computer_name,
                                        "userassist",
                                        item[VALUE_LAST_WRITE_TIME],
                                        "HKEY_USERS",
                                        item[VALUE_PATH],
                                        item[VALUE_NAME],
                                        item[KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[VALUE_TYPE]),
                                        str_value_name))
                else:
                    if is_win7_or_further:
                        data = csv_user_assist_value_decode_win7_and_after(str_value_datatmp, count_offset)
                    else:
                        data = csv_user_assist_value_decode_before_win7(str_value_datatmp, count_offset)
                    to_csv_list.append((self.computer_name,
                                        "user_assist",
                                        item[VALUE_LAST_WRITE_TIME],
                                        "HKEY_USERS",
                                        item[VALUE_PATH],
                                        item[VALUE_NAME],
                                        item[KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[VALUE_TYPE]),
                                        str_value_name) + tuple(data))
        return to_csv_list

    def _get_network_list(self, key):
        to_csv_list = []
        self._generate_hklm_csv_list(to_csv_list, 'network _list', key, is_recursive=True)
        result = {}
        for item in to_csv_list[1:]:
            if not item[4] in result:
                result[item[4]] = {'Profilename': '', 'DateCreated': '', 'DateLastConnected': '', 'Description': ''}
            if item[5] == 'ProfileName':
                result[item[4]]['Profilename'] = item[8]
            elif item[5] == 'Description':
                result[item[4]]['Description'] = item[8]
            elif item[5] == 'DateCreated':
                list_item = struct.unpack('<HHHHHHHH', item[8])
                result[item[4]]['DateCreated'] = datetime.datetime(list_item[0], list_item[1], list_item[3]
                                                                   , list_item[4], list_item[5],
                                                                   list_item[6]).isoformat()
            elif item[5] == 'DateLastConnected':
                list_item = struct.unpack('<HHHHHHHH', item[8])
                try:
                    result[item[4]]['DateLastConnected'] = datetime.datetime(list_item[0], list_item[1],
                                                                             list_item[3], list_item[4],
                                                                             list_item[5], list_item[6]).isoformat()
                except:
                    pass
        return result

    def _json_networks_list(self, key):

        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_network_list.json' % self.computer_name), 'ab') as output:
                json_writer = get_json_writer(output)
                result = self._get_network_list(key)
                for v in result.values():
                    write_dict_json(v, json_writer)

    def _csv_networks_list(self, key):
        with open(os.path.join(self.output_dir, '%s_network_list_%s' % (self.computer_name, self.rand_ext)),
                  'wb') as output:
            csv_writer = get_csv_writer(output)
            network_list_result = self._get_network_list(key)
            arr_data = [v.values() for v in network_list_result.values()]
            arr_data.insert(0, network_list_result.values()[0].keys())
            write_list_to_csv(arr_data, csv_writer)

    def _csv_user_assist(self, count_offset, is_win7_or_further):

        with open(self.output_dir + "\\" + self.computer_name + "_user_assist" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_user_assist(count_offset, is_win7_or_further), csv_writer)

    def _json_user_assist(self, count_offset, is_win7_or_further):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_user_asist.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_user_assist(count_offset, is_win7_or_further), json_writer)

    def _get_files_and_hashes(self, csv_files):
        csv_files_transform = []
        arch = _Archives(os.path.join(self.output_dir, self.computer_name + '_autoruns.zip'), self.logger)
        for COMPUTER_NAME, TYPE, LAST_WRITE_TIME, HIVE, KEY_PATH, \
            ATTR_NAME, REG_TYPE, ATTR_TYPE, ATTR_DATA in csv_files:
            m = re.match(regex_patern_path, ATTR_DATA)
            md5 = sha1 = sha256 = 'N\/A'
            if m:
                path = m.group(0).split('/')[0].strip()
                if os.path.isfile(path):
                    if self.vss:
                        path = self.vss._return_root() + os.path.splitdrive(path)[1]
                        md5, sha1, sha256 = self.vss.process_hash_value(path)
                        arch.record(path)
                    else:
                        try:
                            md5, sha1, sha256 = process_hashes(path)
                            arch.record(path)
                        except:
                            pass
            csv_files_transform.append((COMPUTER_NAME, TYPE, LAST_WRITE_TIME, HIVE, KEY_PATH, ATTR_NAME, REG_TYPE,
                                        ATTR_TYPE, ATTR_DATA, md5, sha1, sha256))
        return csv_files_transform

    def __get_open_save_mru(self, str_opensave_mru):
        """Extracts OpenSaveMRU containing information about files selected in the Open and Save view"""
        # TODO : Win XP
        self.logger.info("Extracting open save MRU")
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, str_opensave_mru)
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        for item in hive_list:
            if item[KEY_VALUE_STR] == 'VALUE':
                if item[VALUE_NAME] != "MRUListEx":
                    pidl = shell.StringAsPIDL(item[VALUE_DATA])
                    path = shell.SHGetPathFromIDList(pidl)
                    to_csv_list.append((self.computer_name,
                                        "opensaveMRU",
                                        item[VALUE_LAST_WRITE_TIME],
                                        "HKEY_USERS",
                                        item[VALUE_PATH],
                                        item[VALUE_NAME],
                                        item[KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[VALUE_TYPE]), path))
        return to_csv_list

    def _csv_open_save_mru(self, str_opensave_mru):

        with open(self.output_dir + "\\" + self.computer_name + "_opensaveMRU" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_open_save_mru(str_opensave_mru), csv_writer)

    def _json_open_save_mru(self, str_opensave_mru):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_opensaveMRU.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_open_save_mru(str_opensave_mru), json_writer)

    def __get_powerpoint_mru(self, str_powerpoint_mru):
        """Extracts PowerPoint user mru"""
        # TODO : Win XP
        self.logger.info("Extracting PowerPoint MRU")
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, str_powerpoint_mru)
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        for item in hive_list:
            if item[KEY_VALUE_STR] == 'VALUE':
                if item[VALUE_NAME] != "MRUListEx":
                    pidl = shell.StringAsPIDL(item[VALUE_DATA])
                    path = shell.SHGetPathFromIDList(pidl)
                    to_csv_list.append((self.computer_name,
                                        "PowerPointMRU",
                                        item[VALUE_LAST_WRITE_TIME],
                                        "HKEY_USERS",
                                        item[VALUE_PATH],
                                        item[VALUE_NAME],
                                        item[KEY_VALUE_STR],
                                        registry_obj.get_str_type(item[VALUE_TYPE]), path))
        return to_csv_list

    def _csv_PowerPoint_mru(self, str_powerpoint_mru):

        with open(self.output_dir + "\\" + self.computer_name + "_powerpointMRU" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_powerpoint_mru(str_powerpoint_mru), csv_writer)

    def _json_powerpoint_mru(self, str_powerpoint_mru):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_powerpointMRU.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_powerpoint_mru(str_powerpoint_mru), json_writer)

    def __get_registry_services(self):
        self.logger.info("Extracting services")
        path = r"System\CurrentControlSet\Services"
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        self._generate_hklm_csv_list(to_csv_list, "registry_services", path)
        return to_csv_list

    def csv_registry_services(self):
        """Extracts services"""

        with open(self.output_dir + "\\" + self.computer_name + "_registry_services" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_registry_services(), csv_writer)

    def json_registry_services(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_registry_services.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_registry_services(), json_writer)

    def __get_recents_docs(self):
        """Extracts information about recently opened files saved location and opened date"""
        self.logger.info("Extracting recent docs")
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        hive_list = self._get_list_from_registry_key(registry_obj.HKEY_USERS, path)
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        for item in hive_list:
            if item[KEY_VALUE_STR] == "VALUE":
                if item[VALUE_NAME] != "MRUListEx":
                    values_decoded = decode_recent_docs_mru(item[VALUE_DATA])
                    for value_decoded in values_decoded:
                        to_csv_list.append((self.computer_name,
                                            "recent_docs",
                                            item[VALUE_LAST_WRITE_TIME],
                                            "HKEY_USERS",
                                            item[VALUE_PATH],
                                            item[VALUE_NAME],
                                            item[KEY_VALUE_STR],
                                            registry_obj.get_str_type(item[VALUE_TYPE]),
                                            value_decoded))
        return to_csv_list

    def csv_recent_docs(self):
        with open(self.output_dir + "\\" + self.computer_name + "_recent_docs" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_recents_docs(), csv_writer)

    def json_recent_docs(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_recent_docs.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_recents_docs(), json_writer)

    def __get_install_folder(self):
        """Extracts information about folders which are created at installation"""
        self.logger.info("Extracting installer folders")
        path = r"Software\Microsoft\Windows\CurrentVersion\Installer\Folders"
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        self._generate_hklm_csv_list(to_csv_list, "installer_folder", path)
        return to_csv_list

    def csv_installer_folder(self):

        with open(self.output_dir + "\\" + self.computer_name + "_installer_folder" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_install_folder(), csv_writer)

    def json_installer_folder(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_installer_folder.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_install_folder(), json_writer)

    def __get_shell_bags(self):
        """
            Extracts shellbags: size, view, icon and position of graphical windows
            In particular, executed graphical programs will leave a key here
            """
        self.logger.info("Extracting shell bags")
        paths = [r"Software\Microsoft\Windows\Shell\Bags",
                 r"Software\Microsoft\Windows\Shell\BagMRU"]
        paths_usrclass = [r"Local Settings\Software\Microsoft\Windows\Shell\Bags",
                          r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU"]
        hive_list = []
        for path in paths:
            hive_list += self._get_list_from_registry_key(registry_obj.HKEY_USERS, path)
        for path in paths_usrclass:
            hive_list += self._get_list_from_registry_key(registry_obj.HKEY_USERS, path, is_usrclass=True)
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        for item in hive_list:
            if "ItemPos" in item[VALUE_NAME]:
                try:
                    data = decode_shellbag_itempos_data(item[VALUE_DATA])
                except IndexError:
                    self.logger.error("Error in shellbag data format for " + item[VALUE_NAME])
                    data = None
                if data:
                    if item[KEY_VALUE_STR] == "VALUE":
                        for data in data:
                            for d in data:
                                to_csv_list.append((self.computer_name,
                                                    "shellbags",
                                                    item[VALUE_LAST_WRITE_TIME],
                                                    "HKEY_USERS",
                                                    item[VALUE_PATH],
                                                    item[VALUE_NAME],
                                                    item[KEY_VALUE_STR],
                                                    registry_obj.get_str_type(item[VALUE_TYPE]),
                                                    d))
                else:
                    if item[KEY_VALUE_STR] == "VALUE":
                        to_csv_list.append((self.computer_name,
                                            "shellbags",
                                            item[VALUE_LAST_WRITE_TIME],
                                            "HKEY_USERS",
                                            item[VALUE_PATH],
                                            item[VALUE_NAME],
                                            item[KEY_VALUE_STR],
                                            registry_obj.get_str_type(item[VALUE_TYPE]),
                                            item[VALUE_DATA]))
        return to_csv_list

    def csv_shell_bags(self):

        with open(self.output_dir + "\\" + self.computer_name + "_shellbags" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_shell_bags(), csv_writer)

    def json_shell_bags(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_shellbag.json' % self.computer_name), "wb") as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_shell_bags(), json_writer)

    def __get_startup_programs(self):
        """Extracts programs running at startup from various keys"""
        self.logger.info("Extracting startup programs")
        software = "Software"
        wow = r"\Wow6432Node"
        ts_run = (r"\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software"
                  r"\Microsoft\Windows\CurrentVersion\Run")
        ts_run_once = (r"\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software"
                       r"\Microsoft\Windows\CurrentVersion\RunOnce")
        paths = [r"\Microsoft\Windows\CurrentVersion\Run",
                 r"\Microsoft\Windows\CurrentVersion\RunOnce",
                 r"\Microsoft\Windows\CurrentVersion\RunOnceEx",
                 r"\Microsoft\Windows\CurrentVersion\RunServices",
                 r"\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                 r"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                 ts_run,
                 ts_run_once]
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        for path in paths:
            full_path = software + path
            self._generate_hklm_csv_list(to_csv_list, "startup", full_path)
            full_path = software + wow + path
            self._generate_hklm_csv_list(to_csv_list, "startup", full_path)

        paths = [r"\Microsoft\Windows\CurrentVersion\Run",
                 r"\Microsoft\Windows\CurrentVersion\RunOnce",
                 r"\Microsoft\Windows\CurrentVersion\RunOnceEx",
                 r"\Microsoft\Windows\CurrentVersion\RunServices",
                 r"\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                 r"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                 ts_run,
                 ts_run_once]
        for path in paths:
            full_path = software + path
            self._generate_hku_csv_list(to_csv_list, "startup", full_path)
            full_path = software + wow + path
            self._generate_hku_csv_list(to_csv_list, "startup", full_path)
        if self.get_autoruns:
            to_csv_list = self._get_files_and_hashes(to_csv_list[1:])
            to_csv_list.insert(0,
                               ("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                                "ATTR_TYPE", "ATTR_DATA", "MD5", "SHA1", "SHA256")
                               )
        return to_csv_list

    def csv_startup_programs(self):

        with open(self.output_dir + "\\" + self.computer_name + "_startup" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_startup_programs(), csv_writer)

    def json_startup_programs(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_startup.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_startup_programs(), json_writer)

    def __get_installed_components(self):
        """
            Extracts installed components key
            When an installed component key is in HKLM but not in HKCU, the path specified in HKLM will be added in HKCU
            and will be executed by the system
            """
        self.logger.info("Extracting installed components")
        path = r"Software\Microsoft\Active Setup\Installed Components"
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        self._generate_hklm_csv_list(to_csv_list, "installed_components", path)
        return to_csv_list

    def csv_installed_components(self):

        with open(self.output_dir + "\\" + self.computer_name + "_installed_components" + self.rand_ext,
                  "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_installed_components(), csv_writer)

    def json_installed_components(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_installed_components.json' % self.computer_name),
                      'wb') as ouput:
                json_writer = get_json_writer(ouput)
                write_list_to_json(self.__get_installed_components(), json_writer)

    def __get_winlogon_values(self):
        """
            Extracts winlogon values, in particular UserInit, where the specified executable will be executed at
            system startup
            """
        self.logger.info("Extracting winlogon values")
        path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        self._generate_hklm_csv_list(to_csv_list, "winlogon_values", path)
        self._generate_hku_csv_list(to_csv_list, "winlogon_values", path)
        return to_csv_list

    def csv_winlogon_values(self):

        with open(self.output_dir + "\\" + self.computer_name + "_winlogon_values" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_winlogon_values(), csv_writer)

    def json_winlogon_values(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_winlogon_values.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_winlogon_values(), json_writer)

    def __get_windows_values(self):
        """
            Extracts windows values, in particular AppInit_DLLs, where any DLL specified here will be loaded by any
            application
            """
        self.logger.info("Extracting windows values")
        paths = [r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                 r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"]
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        for path in paths:
            self._generate_hklm_csv_list(to_csv_list, "windows_values", path)
            # self._generate_hku_csv_list(to_csv_list, "windows_values", path)
        return to_csv_list

    def csv_windows_values(self):

        with open(self.output_dir + "\\" + self.computer_name + "_windows_values" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_windows_values(), csv_writer)

    def json_windows_value(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_windows_value.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_windows_values(), json_writer)

    def __get_usb_history(self):
        """Extracts information about USB devices that have been connected since the system installation"""
        self.logger.info("Extracting USB history")
        hive_list = self._get_list_from_registry_key(
            registry_obj.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            is_recursive=False)
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "KEY_VALUE", "USB_ID")]
        for item in hive_list:
            if item[KEY_VALUE_STR] == "KEY":
                usb_decoded = get_usb_key_info(item[KEY_PATH])
                to_csv_list.append((self.computer_name,
                                    "USBHistory",
                                    item[KEY_LAST_WRITE_TIME],
                                    "HKEY_LOCAL_MACHINE",
                                    item[KEY_PATH],
                                    item[KEY_VALUE_STR],
                                    usb_decoded))
        return to_csv_list

    def csv_usb_history(self):
        with open(self.output_dir + "\\" + self.computer_name + "_USBHistory" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_usb_history(), csv_writer)

    def json_usb_history(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_USBHistory.json' % self.computer_name), "wb") as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_usb_history(), json_writer)

    def __get_run_mru_start(self):
        """Extracts run MRU, containing the last 26 oommands executed using the RUN command"""
        self.logger.info("Extracting Run MRU")
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        to_csv_list = [("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                        "ATTR_TYPE", "ATTR_DATA")]
        self._generate_hku_csv_list(to_csv_list, "run_MRU_start", path)
        return to_csv_list

    def csv_run_mru_start(self):

        with open(self.output_dir + "\\" + self.computer_name + "_run_MRU_start" + self.rand_ext, "wb") as output:
            csv_writer = get_csv_writer(output)
            write_list_to_csv(self.__get_run_mru_start(), csv_writer)

    def json_run_mru_start(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_run_mru_start.json' % self.computer_name), 'wb') as output:
                json_writer = get_json_writer(output)
                write_list_to_json(self.__get_run_mru_start(), json_writer)

    def __get_custom_registry_keys(self):
        """
            Extracts custom registry keys, the user specifies whether it should be recursive or not.
            The list of registry keys to extract should be comma-separated
            """
        if self.exec_custom_registry_keys:
            self.logger.info("Extracting custom registry keys")
            to_csv_list = [
                ("COMPUTER_NAME", "TYPE", "LAST_WRITE_TIME", "HIVE", "KEY_PATH", "ATTR_NAME", "REG_TYPE",
                 "ATTR_TYPE", "ATTR_DATA")]
            for paths in reader([self.custom_registry_keys]):  # used as a kind of unpack
                for path in paths:
                    temp = path.split("\\")
                    hive = temp[0].upper()
                    path = "\\".join(temp[1:])
                    if hive in ("HKLM", "HKEY_LOCAL_MACHINE"):
                        self._generate_hklm_csv_list(to_csv_list, "custom_registry_key", path,
                                                     is_recursive=self.registry_recursive)
                    elif hive in ("HKU", "HKEY_USERS"):
                        self._generate_hku_csv_list(to_csv_list, "custom_registry_key", path,
                                                    is_recursive=self.registry_recursive)
                    else:  # error
                        self.logger.warn("Must specify HKLM/HKEY_LOCAL_MACHINE or HKU/HKEY_USERS as hive")
                        return
            return to_csv_list

    def csv_custom_registry_keys(self):

        with open(self.output_dir + "\\" + self.computer_name + "_custom_registry_keys" + self.rand_ext,
                  "wb") as output:
            csv_writer = get_csv_writer(output)
            to_csv_list = self.__get_custom_registry_keys()
            if to_csv_list:
                write_list_to_csv(to_csv_list, csv_writer)

    def json_custom_registry_keys(self):
        if self.destination == 'local':
            with open(os.path.join(self.output_dir, '%s_custom_registry.json' % self.computer_name), 'wb') as output:
                to_json_list = self.__get_custom_registry_keys()
                if to_json_list:
                    json_writer = get_json_writer(output)
                    write_list_to_json(to_json_list, json_writer)
