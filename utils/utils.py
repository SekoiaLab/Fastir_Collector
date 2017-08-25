# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import win32wnet
import win32netcon
import win32api
import win32file
import win32security
import win32con
import win32service
import os
import sys
import datetime
import glob
import hashlib
from string import ascii_uppercase
import zipfile
import wmi
import shutil
import traceback
import csv
import cStringIO
import codecs
import locale
import ctypes
import json
import binascii

regex_patern_path = '^(.*/)?(?:$|(.+?)(?:(\.[^.]*$)|$))'
EXCEL_CELL_SIZE = 30000  # real limit is 32767, but


class UnicodeJsonDumper:
    """
    This class always write JSON as an array of object.
    A close() call at the end of the function is mandatory, otherwise generated
    JSON is note valid.
    """
    def __init__(self, output):
        self.output = output
        self.first = True

    def list_to_json(self, list_json):
        """
        Alternative method which bypasses inner state to directly write a collection in file.
        Should only be used for small datasets, as it is fully stored in memory.
        :param list_json: An array of elements where the first one is the name of the fields.
        """
        headers = list_json[0]
        to_write = []
        for entry in list_json[1:]:
            json_dict = {h: entry[index] for index, h in enumerate(headers)}
            to_write.append(encode_json_dict(json_dict))
        json.dump(to_write, self.output)

    def dump_json(self, entry):
        # encodings = encodings = ["ascii", "utf-8", "latin1", "utf-16le", sys.stdin.encoding]
        to_write = encode_json_dict(entry)
        if self.first:
            self.output.write('[')
        else:
            self.output.write(',')
        json.dump(to_write, self.output)
        self.first = False

    def close_current(self):
        """
        Close the array of JSON objects.
        As the file stream is managed outside of this object, don't close the
        output and reinitialise the inner state.
        """
        if not self.first:
            self.output.write(']')
            self.first = True


class UnicodeWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.
    """

    def __init__(self, f, excel=False, dialect=csv.excel, encoding="utf-8", **kwds):
        # Redirect output to a queue
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()
        self.excel = excel

    def writerow(self, row):
        columns = []
        for s in row:
            if s:
                encoding, value = find_encoding(s)
                if encoding:
                    try:
                        columns.append(value.decode(encoding).encode("utf-8", "ignore"))
                    except UnicodeEncodeError:
                        columns.append('0x' + binascii.b2a_hex(s).encode("utf-8", "ignore"))
                        # columns.append("".join([a for a in s]).encode("utf-8", "ignore"))
                else:
                    # last hope
                    columns.append("".join([a for a in s]).encode("utf-8", "ignore"))
            else:
                columns.append("")

        if self.excel:
            for index, c in enumerate(columns):
                if len(c) > EXCEL_CELL_SIZE:
                    try:
                        columns[index] = c[:EXCEL_CELL_SIZE] + ' [...]'
                    except UnicodeDecodeError:
                        columns[index] = (c[:EXCEL_CELL_SIZE].decode('utf8') + ' [...]').encode('utf8')

        self.writer.writerow(columns)

        # Fetch UTF-8 output from the queue ...
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        # ... and reencode it into the target encoding
        data = self.encoder.encode(data)
        # write to the target stream
        self.stream.write(data)
        # empty queue
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def find_encoding(value):
    encodings = ["ascii", "utf-8", "latin1", "utf-16le", sys.stdin.encoding]
    for encoding in encodings:
        try:
            if type(value) != "str" and type(value) != "unicode":
                value = str(value).decode(encoding)
            elif type(value) == "str":
                value = value.decode(encoding)
            return encoding, value

        except UnicodeEncodeError:
            pass
        except UnicodeDecodeError:
            pass
    return None, None


def encode_json_dict(jdict):
    """Encode all values in a dict to allow json serialization"""
    to_write = {}
    for k, v in jdict.items():
        if v:
            encoding, value = find_encoding(v)
            if encoding:
                try:
                    to_write[k] = value.decode(encoding).encode('utf-8', 'ignore')
                except UnicodeEncodeError:
                    to_write[k] = '0x' + binascii.b2a_hex(v).encode('UTF-8', 'ignore')
            else:
                to_write[k] = ''.join([a for a in v]).encode('utf-8', 'ignore')
    return to_write


def decode_output_cmd(output):
    return output.decode(locale.getpreferredencoding())


def mount_share(share_path, param_username, param_password):
    """Uses the pywin32 library to mount a share and updates the filename"""
    # check if such a path has already been mounted
    print "Mounting the share " + share_path
    handle = win32wnet.WNetOpenEnum(win32netcon.RESOURCE_CONNECTED, win32netcon.RESOURCETYPE_DISK, 0, None)
    resources = win32wnet.WNetEnumResource(handle)
    is_mounted = False
    used_letters = ""
    letter = None
    for resource in resources:
        if share_path == resource.lpRemoteName and resource.lpLocalName:
            # found a mounted drive with the same path so we set the correct letter
            # lpLocalName is None when the mount does not redirect a local device
            # we do not want to consider such a mount
            is_mounted = True
            letter = resource.lpLocalName
        if resource.lpLocalName:
            used_letters += resource.lpLocalName  # append so we can search a free letter later
    win32wnet.WNetCloseEnum(handle)
    if not is_mounted:
        for letter in ascii_uppercase[::-1]:
            if letter not in used_letters:
                letter += ":"
                break
        net_resource = win32wnet.NETRESOURCE()
        net_resource.dwType = win32netcon.RESOURCETYPE_DISK
        net_resource.lpLocalName = letter
        net_resource.lpRemoteName = share_path
        net_resource.lpProvider = None
        win32wnet.WNetAddConnection2(net_resource, param_username, param_password)
        print("Share successfully mounted with letter %s " % letter)
    return letter


def unmount_share(letter):
    """Unmount the share designed by the letter"""
    if letter:
        print("Unmounting share %s" % letter)
        try:
            win32wnet.WNetCancelConnection2(letter, 1, 1)  # force unmap
            print("Share %s successfully unmounted" % letter)
        except win32wnet.error:
            print("Cannot unmount specified share")


def change_to_MKTime(seconds):
    """Change time by QueryInfoKey to mktime."""  # Time difference is 134774 days = days from 1.1.1600 -> 31.12.1968
    diff = 11644473600
    seconds /= pow(10, 7)
    mktime = seconds - diff
    return mktime


def convert_windate(timestamp):
    try:
        return datetime.datetime.fromtimestamp(change_to_MKTime(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return 0


# Code from https://github.com/williballenthin/python-evtx/blob/master/Evtx/BinaryParser.py#L80
def dosdate(_dosdate, _dostime):
    """
    _dosdate: 2 bytes, little endian.
    _dostime: 2 bytes, little endian.
    returns: datetime.datetime or datetime.datetime.min on error
    """
    try:
        t = ord(_dosdate[1]) << 8
        t |= ord(_dosdate[0])
        day = t & 0b0000000000011111
        month = (t & 0b0000000111100000) >> 5
        year = (t & 0b1111111000000000) >> 9
        year += 1980

        t = ord(_dostime[1]) << 8
        t |= ord(_dostime[0])
        sec = t & 0b0000000000011111
        sec *= 2
        minute = (t & 0b0000011111100000) >> 5
        hour = (t & 0b1111100000000000) >> 11

        return datetime.datetime(year, month, day, hour, minute, sec)
    except:
        return datetime.datetime.min


def convert_string_to_hex(string):
    return "".join(c.encode("hex") for c in string)


def get_local_drives():
    """Returns a list containing letters from local drives"""
    drive_list = win32api.GetLogicalDriveStrings()
    drive_list = drive_list.split("\x00")[0:-1]  # the last element is ""
    list_local_drives = []
    for letter in drive_list:
        if win32file.GetDriveType(letter) == win32file.DRIVE_FIXED:
            list_local_drives.append(letter)
    return list_local_drives


def get_removable_drives():
    """Returns a list containing letters from removable drives"""
    drive_list = win32api.GetLogicalDriveStrings()
    drive_list = drive_list.split("\x00")[0:-1]  # the last element is ""
    list_removable_drives = []
    for letter in drive_list:
        if win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE:
            list_removable_drives.append(letter)
    return list_removable_drives


def sid2username(sid):
    """Convert an object sid to a string account name"""
    account = win32security.LookupAccountSid(None, sid)
    return account[0]


def str_sid2username(str_sid):
    """Convert a string sid to a string account name"""
    try:
        sid = win32security.ConvertStringSidToSid(str_sid)
        return sid2username(sid)
    except:
        return ""


def check_outlook_d(path):
    """Checks the existence of the Outlook common filepath in the given path
        Returns the path if it exists, None otherwise"""
    application_data = path + "\\Local Settings\\Application Data\\Microsoft\\Outlook"
    if os.path.exists(application_data):
        return application_data
    appdata = path + "\\AppData\\Local\\Microsoft\\Outlook"
    if os.path.exists(appdata):
        return appdata
    return None


def look_for_outlook_dirs(paths_to_search):
    """Takes a list of paths to search for Outlook, will return a list of valid Outlook paths
        A good practice is to take the output from get_userprofiles_from_reg() function
        Returns the path if it exists, None otherwise"""
    valid_paths = []
    if paths_to_search:
        for path in paths_to_search:
            path = check_outlook_d(path)
            if path:
                valid_paths.append(path)
    return valid_paths


def look_for_files(dir_to_look):
    """Looks for windows in a given directory. Supports the * wildcard character"""
    found_files = []
    if "*" in dir_to_look:
        found_files += glob.glob(dir_to_look)
    elif os.path.exists(dir_to_look):
        found_files.append(dir_to_look)
    return found_files


def zip_from_object(files_to_zip, zip_object, logger):
    """Zips a list of windows given the zip object"""
    for file_to_zip in files_to_zip:
        try:
            zip_object.write(file_to_zip)
        except OSError:
            logger.warn("file not found " + file_to_zip)
        except IOError as err:
            if err.errno == 13:  # Permission denied
                logger.warn("Permission denied for : " + file_to_zip)


def zip_archive(files_to_zip, zip_path, filename, logger, file_mode="w"):
    """Uses the global variable to save the zip file. Creates a zip archive containing windows given in parameters.
        The file mode is write by default. It can also be "a" for append."""
    computer_name = os.environ["COMPUTERNAME"]
    zip_fullname = zip_path + "\\" + computer_name + "_" + filename + ".zip"
    with zipfile.ZipFile(zip_fullname, file_mode) as myzip:
        zip_from_object(files_to_zip, myzip, logger)


def clean(path, computer_name):
    list_file_erase = glob.glob(path + "/" + computer_name + "*.csv")
    for l in list_file_erase:
        os.remove(l)


def is_locked(filename):
    try:
        open(filename, "r").read(1)
    except IOError:
        return True
    return False


def is_open(filename):
    handle = win32file.CreateFile(filename, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING,
                                  win32file.FILE_ATTRIBUTE_NORMAL, 0)
    if handle:
        return True
    else:
        return False


def is_allowed(filename):
    try:
        open(filename, "r").read(1)
        return True
    except IOError as e:
        errorcode, desc = e.args
        if errorcode == 13:
            return False
        else:
            return True


def is_running(name):
    c = wmi.WMI()
    service = c.Win32_Service(Name=name)[0]
    if service.State == "Running":
        return service, True
    else:
        return service, False


def copy_file(root, path, dest):
    try:
        dirs, f = os.path.split(dest + path.replace(root, ""))
        os.makedirs(dirs)
        shutil.copy(path, dest + path.replace(root, ""))
        return dest + path.replace(root, "")
    except WindowsError:
        pass


def check_permissions(path, logger):
    logger.info("I am", win32api.GetUserNameEx(win32con.NameSamCompatible))
    logger.info(path)
    sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
    owner_sid = sd.GetSecurityDescriptorOwner()
    name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
    logger.info("File owned by %s\\%s" % (domain, name))


def write_to_output(str_to_write, output, logger):
    """Writes content to a file, encoding the string in UTF-8 for compatibility issues"""
    try:
        output.write(str_to_write.encode("utf-8"))
    except UnicodeError:
        logger.error(traceback.format_exc())


def get_terminal_decoded_string(string):
    return string.decode(sys.stdout.encoding, "ignore")


def get_json_writer(json_file):
    return UnicodeJsonDumper(json_file)


def get_csv_writer(csvfile):
    return UnicodeWriter(csvfile, quoting=csv.QUOTE_ALL)


def get_excel_csv_writer(csvfile):
    return UnicodeWriter(csvfile, excel=True, quoting=csv.QUOTE_ALL)


def write_to_csv(arr_data, csv_writer):
    """Writes contents to a CSV file using UTF-8"""
    csv_writer.writerow(arr_data)


def write_list_to_csv(arr_data, csv_writer):
    """Writes a list"s contents to a CSV file using UTF-8"""
    csv_writer.writerows(arr_data)


def write_list_to_json(arr_data, json_writer):
    """Write list data in json files using UTF-8"""
    json_writer.list_to_json(arr_data)


def write_to_json(header, arr_data, json_writer):
    """Write data in json files using UTF-8"""
    try:
        json_writer.dump_json({
            h: arr_data[index] for index, h in enumerate(header)
        })
    except IndexError:
        json_writer.dump_json({
            header[index]: d for index, d in enumerate(arr_data)
        })


def write_dict_json(arr_data, json_writer):
    json_writer.dump_json(arr_data)
    json_writer.close_current()


def close_json_writer(json_writer):
    json_writer.close_current()


def get_architecture():
    if sys.maxsize > 2 ** 32:
        return "64"
    else:
        return "86"


def get_winpmem_name():
    return "winpmem_x" + get_architecture() + ".sys"


def create_driver_service(logger):
    """Creates the service for winpmem"""
    # Must have absolute path here.
    if hasattr(sys, "frozen"):
        driver = os.path.join(sys._MEIPASS, get_winpmem_name())
    else:
        driver = os.path.join(os.getcwd(), get_winpmem_name())

    h_scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CREATE_SERVICE)

    try:
        h_svc = win32service.CreateService(
                h_scm, "pmem", "pmem",
                win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START,
                win32service.SERVICE_ERROR_IGNORE,
                driver,
                None, 0, None, None, None)
    except win32service.error, e:
        logger.error(e)
        h_svc = win32service.OpenService(h_scm, "pmem",
                                         win32service.SERVICE_ALL_ACCESS)
    return h_svc


def start_service(h_svc, logger):
    """Starts the winpmem service"""
    # Make sure the service is stopped.
    try:
        win32service.ControlService(h_svc, win32service.SERVICE_CONTROL_STOP)
    except win32service.error:
        pass

    try:
        win32service.StartService(h_svc, [])
    except win32service.error, e:
        logger.error(str(e) + ": will try to continue")


def stop_and_delete_driver_service(h_svc):
    """Stops the winpmem service and delete it"""
    try:
        win32service.ControlService(h_svc, win32service.SERVICE_CONTROL_STOP)
    except win32service.error:
        pass
    win32service.DeleteService(h_svc)
    win32service.CloseServiceHandle(h_svc)


def process_size(size_str):
    unities = {"k": 1024L, "M": 1024L * 1024L, "G": 1024L * 1024L * 1024L}
    suffix = size_str[len(size_str) - 1:]
    value = size_str[:len(size_str) - 1]
    return long(value) * unities[suffix]


def record_sha256_logs(fr, fw):
    with open(fw, "a") as hash_file:
        m = process_sha256(fr)
        hash_file.write(fr + "," + m + "\n")
        hash_file.close()


def process_hashes(path):
    content = open(path, "rb").read()
    return hashlib.md5(content).hexdigest(), hashlib.sha1(content).hexdigest(), hashlib.sha256(content).hexdigest()


def process_md5(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def process_sha1(path):
    with open(path, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()


def process_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def rot13(s):
    chars = "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz"
    trans = "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    rot_char = lambda c: trans[chars.find(c)] if chars.find(c) > -1 else c
    return ''.join(rot_char(c) for c in s)


class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [('dwOSVersionInfoSize', ctypes.c_ulong),
                ('dwMajorVersion', ctypes.c_ulong),
                ('dwMinorVersion', ctypes.c_ulong),
                ('dwBuildNumber', ctypes.c_ulong),
                ('dwPlatformId', ctypes.c_ulong),
                ('szCSDVersion', ctypes.c_wchar * 128),
                ('wServicePackMajor', ctypes.c_ushort),
                ('wServicePackMinor', ctypes.c_ushort),
                ('wSuiteMask', ctypes.c_ushort),
                ('wProductType', ctypes.c_byte),
                ('wReserved', ctypes.c_byte)]


_WIN_Release = {
    (5, 1, 1): 'XP',
    (5, 2, 1): 'XP',
    (6, 0, 1): 'Vista',
    (6, 1, 1): '7',
    (6, 2, 1): '8',
    (6, 3, 1): '8_1',
    (10, 0, 1): '10',
    (5, 2, 2): '2003Server',
    (5, 2, 3): '2003Server',
    (6, 0, 2): '2008Server',
    (6, 0, 3): '2008Server',
    (6, 1, 2): '2008ServerR2',
    (6, 1, 3): '2008ServerR2',
    (6, 2, 2): '2012Server',
    (6, 2, 3): '2012Server',
    (6, 3, 2): '2012ServerR2',
    (6, 3, 3): '2012ServerR2',
}


def get_os_version():
    """
    Get's the OS major and minor versions.  Returns a tuple of
    (OS_MAJOR, OS_MINOR, OS_PRODUCT_TYPE).
    """
    os_version = OSVERSIONINFOEXW()
    os_version.dwOSVersionInfoSize = ctypes.sizeof(os_version)
    retcode = ctypes.windll.Ntdll.RtlGetVersion(ctypes.byref(os_version))
    if retcode != 0:
        raise Exception("Failed to get OS version")

    t = (os_version.dwMajorVersion, os_version.dwMinorVersion, os_version.wProductType)
    if t in _WIN_Release:
        return _WIN_Release[t]


def change_char_set_os_environ(environ):
    return {k: environ[k].decode(sys.getfilesystemencoding()) for k in environ.keys()}
