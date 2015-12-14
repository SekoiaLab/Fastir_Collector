# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import glob
import logging
import os
import sqlite3
import traceback
import ctypes
import struct

from utils.utils import get_int_from_reversed_string, look_for_outlook_dirs, \
    look_for_files, zip_archive, get_csv_writer, write_to_csv, record_sha256_logs
from registry.registry_obj import get_userprofiles_from_reg
from utils.utils_rawstring import sekoiamagic
from win32com.shell import shell, shellcon


class _FS(object):
    def __init__(self, params):
        self.userprofiles = None
        self.public = None
        self.systemroot = params['system_root']
        self.computer_name = params['computer_name']
        self.output_dir = params['output_dir']
        self.logger = params['logger']

    def _list_named_pipes(self):
        for p in look_for_files('\\\\.\\pipe\\*'):
            yield p

    def __decode_section_a(self, format_version, content, section_a):
        hash_table = dict()
        if format_version == 17:
            hash_table['start_time'] = get_int_from_reversed_string(content[section_a:section_a + 4])
            hash_table['duration'] = get_int_from_reversed_string(content[section_a + 4:section_a + 4 + 4])
            hash_table['average_duration'] = ''
            hash_table['filename_offset'] = get_int_from_reversed_string(content[section_a + 8:section_a + 8 + 4])
            hash_table['filename_nb_char'] = get_int_from_reversed_string(content[section_a + 12:section_a + 12 + 4])
        else:
            hash_table['start_time'] = get_int_from_reversed_string(content[section_a:section_a + 4])
            hash_table['duration'] = get_int_from_reversed_string(content[section_a + 4:section_a + 4 + 4])
            hash_table['average_duration'] = get_int_from_reversed_string(content[section_a + 8:section_a + 8 + 4])
            hash_table['filename_offset'] = get_int_from_reversed_string(content[section_a + 12:section_a + 12 + 4])
            hash_table['filename_nb_char'] = get_int_from_reversed_string(content[section_a + 16:section_a + 16 + 4])
        return hash_table

    def __decode_section_c(self, content, section_c, length_c):
        offset = 0
        str_start = 0
        list_str = []
        while offset < length_c:
            if content[section_c + offset] == b'\0' and content[section_c + offset + 1] == b'\0':
                list_str.append(content[section_c + str_start:section_c + offset + 2].decode('utf-16-le'))
                str_start = offset + 2
            offset += 2
        return list_str

    def _list_windows_prefetch(self, is_compressed=False):
        """Outputs windows prefetch files in a csv"""
        """See http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format"""
        prefetch_path = self.systemroot + '\Prefetch\*.pf'
        list_prefetch_files = look_for_files(prefetch_path)

        for prefetch_file in list_prefetch_files:
            content = ''
            with open(prefetch_file, 'rb') as file_input:
                content = file_input.read()
            try:
                if is_compressed:
                    header = content[:8]
                    content = content[8:]
                    signature, uncompressed_size = struct.unpack('<LL', header)
                    algo = (signature & 0x0F000000) >> 24
                    RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
                    RtlGetCompressionWorkSpaceSize = ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize
                    CompressBufferWorkSpaceSize = ctypes.c_uint32()
                    CompressFragmentWorkSpaceSize = ctypes.c_uint32()
                    RtlGetCompressionWorkSpaceSize(algo, ctypes.byref(CompressBufferWorkSpaceSize),
                                                   ctypes.byref(CompressFragmentWorkSpaceSize))
                    Compressed = (ctypes.c_ubyte * len(content)).from_buffer_copy(content)
                    Uncompressed = (ctypes.c_ubyte * uncompressed_size)()
                    FinalUncompressedSize = ctypes.c_uint32()
                    Workspace = (ctypes.c_ubyte * CompressFragmentWorkSpaceSize.value)()
                    ntstatus = RtlDecompressBufferEx(
                            ctypes.c_uint16(algo),
                            ctypes.byref(Uncompressed),
                            ctypes.c_uint32(uncompressed_size),
                            ctypes.byref(Compressed),
                            ctypes.c_uint32(len(content)),
                            ctypes.byref(FinalUncompressedSize),
                            ctypes.byref(Workspace))
                    uncompressed = list(Uncompressed)
                    content = b"".join([chr(c) for c in uncompressed])
                format_version = content[:4]
                format_version = get_int_from_reversed_string(format_version)
                # scca_sig = content[0x4:][:4]
                unknown_values = content[0x0008:0x0008 + 4]
                unknown_values = ' '.join(c.encode('hex') for c in unknown_values)
                file_size = content[0x000c:0x000c + 4]
                file_size = get_int_from_reversed_string(file_size)
                exec_name = content[0x0010:0x0010 + 60]
                for i in range(30):  # 60 / 2
                    if 2 * i + 1 < len(exec_name):
                        if exec_name[2 * i] == '\x00' and exec_name[2 * i + 1] == '\x00':
                            exec_name = exec_name[:2 * (i + 1)].decode('utf-16-le')
                prefetch_hash = content[0x004c:0x004c + 4]
                tc = os.path.getctime(prefetch_file)
                tm = os.path.getmtime(prefetch_file)

                section_a = get_int_from_reversed_string(content[0x0054:0x0054 + 4])
                num_entries_a = get_int_from_reversed_string(content[0x0058:0x0058 + 4])
                section_b = get_int_from_reversed_string(content[0x005c:0x005c + 4])
                num_entries_b = get_int_from_reversed_string(content[0x0060:0x0060 + 4])
                section_c = get_int_from_reversed_string(content[0x0064:0x0064 + 4])
                length_c = get_int_from_reversed_string(content[0x0068:0x0068 + 4])
                section_d = get_int_from_reversed_string(content[0x006c:0x006c + 4])
                num_entries_d = get_int_from_reversed_string(content[0x0070:0x0070 + 4])
                length_d = get_int_from_reversed_string(content[0x0074:0x0074 + 4])

                if format_version == 17:
                    latest_exec_date = content[0x0078:0x0078 + 8]
                    exec_count = get_int_from_reversed_string(content[0x0090:0x0090 + 4])

                # section a
                elif format_version == 23:
                    latest_exec_date = content[0x0080:0x0080 + 8]
                    exec_count = get_int_from_reversed_string(content[0x0098:0x0098 + 4])
                else:
                    # format version 26
                    latest_exec_date = []
                    for i in range(8):
                        latest_exec_date.append(content[0x0088 + i * 8:0x0088 + (i + 1) * 8])
                    exec_count = get_int_from_reversed_string(content[0x00D0:0x00D0 + 4])

                hash_table_a = self.__decode_section_a(format_version, content, section_a)

                list_str_c = self.__decode_section_c(content, section_c, length_c)
                yield prefetch_file, format_version, file_size, exec_name, datetime.datetime.fromtimestamp(
                    tc), datetime.datetime.fromtimestamp(tm), exec_count, hash_table_a, list_str_c
            except:
                logging.error(traceback.format_exc())

    def _filtered_magic(self, f):
        mime = sekoiamagic(f)
        return (mime in self.mime_filter, mime in self.mime_zip, mime)

    def __enum_directory(self, path):
        files_list = []
        for dirname, subdirnames, filenames in os.walk(path):
            for subdirname in subdirnames:
                files_list.append(os.path.join(dirname, subdirname))
            for filename in filenames:
                files_list.append(os.path.join(dirname, filename))
        return files_list

    def __data_from_userprofile(self, zipname, directories_to_search):
        """Retrieves data from userprofile.
        Creates a zip archive containing windows from the directories given in parameters."""
        userprofiles = get_userprofiles_from_reg()
        # File mode is write and truncate for the first iteration, append after
        file_mode = 'w'
        for userprofile in userprofiles:
            if userprofile.startswith('%'):
                usrp_tokens = userprofile.split('\\')
                prefix = usrp_tokens[0]
                env = prefix.replace('%', '')
                userprofile = userprofile.replace(prefix, os.environ[env])
            for directory_to_search in directories_to_search:
                full_path = userprofile + '\\' + directory_to_search
                # construct the list of windows in the directory_to_search for the zip function
                list_directories = look_for_files(full_path)
                for directory in list_directories:
                    list_files = self.__enum_directory(directory)
                    zip_archive(list_files, self.output_dir, zipname, self.logger, file_mode)
                    file_mode = 'a'

    def _skype_history(self, directories_to_search):
        self.__data_from_userprofile("skype", directories_to_search)

    def _ie_history(self, directories_to_search):
        self.__data_from_userprofile("IEHistory", directories_to_search)

    def _firefox_downloads(self, directories_to_search):
        self.__data_from_userprofile("FirefoxDownloads", directories_to_search)

    def _firefox_history(self, path):
        path = os.path.join(self.systemroot, path)
        for p in glob.glob(path):
            p_tokens = p.split('\\')
            user = p_tokens[2]
            profile = p_tokens[len(p_tokens) - 2]
            con = sqlite3.connect(p)
            cur = con.cursor()
            for time, url in cur.execute(
                    ("SELECT datetime(moz_historyvisits.visit_date/1000000, 'unixepoch', 'localtime'), moz_places.url "
                     "FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;")):
                yield time, url, user, profile

    def _chrome_history(self, path):
        path = os.path.join(self.systemroot, path)
        for p in glob.glob(path):
            p_tokens = p.split('\\')
            user = p_tokens[2]
            profile = p_tokens[len(p_tokens) - 2]
            con = sqlite3.connect(p)
            cur = con.cursor()
            for time, url, title in cur.execute(
                    ('SELECT datetime(((visits.visit_time/1000000)-11644473600), "unixepoch"), '
                     'urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url;')):
                yield time, url, title, user, profile

    def _csv_list_named_pipes(self, pipes):
        with open(self.output_dir + '\\' + self.computer_name + '_named_pipes.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(("COMPUTER_NAME", "TYPE", "NAME"), csv_writer)
            for pipe in pipes:
                write_to_csv([self.computer_name, 'named_pipes', pipe], csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_named_pipes.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def _csv_windows_prefetch(self, wpref):
        with open(self.output_dir + '\\' + self.computer_name + '_prefetch.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(("COMPUTER_NAME", "TYPE", "FILE", "VERSION", "SIZE", "EXEC_NAME", "CREATE_TIME",
                          "MODIFICATION_TIME", "RUN_COUNT", "START_TIME", "DURATION", "AVERAGE_DURATION",
                          "DLL_LIST"), csv_writer)
            for pref_file, format_version, file_size, exec_name, tc, tm, run_count, hash_table_a, list_str_c in wpref:
                str_c = ''
                for s in list_str_c:
                    str_c += s.replace('\0', '') + ';'

                write_to_csv([self.computer_name, 'prefetch', pref_file,
                              unicode(format_version), unicode(file_size), exec_name.replace('\00', ''),
                              unicode(tc), unicode(tm), unicode(run_count), unicode(hash_table_a['start_time']),
                              unicode(hash_table_a['duration']), unicode(hash_table_a['average_duration']), str_c],
                             csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_prefetch.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def _csv_firefox_history(self, fhistory):
        with open(self.output_dir + '\\' + self.computer_name + '_firefox_history.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            for time, url, user, profile in fhistory:
                write_to_csv([self.computer_name, 'firefox_history', time, url, user, profile], csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_firefox_history.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def _csv_chrome_history(self, chistory):
        with open(self.output_dir + '\\' + self.computer_name + '_chrome_history.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(("COMPUTER_NAME", "TYPE", "TIME", "URL", "TITLE", "USER", "PROFILE"), csv_writer)
            for time, url, title, user, profile in chistory:
                write_to_csv([self.computer_name, 'chrome_history', time, url, title, user, profile], csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_chrome_history.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def csv_recycle_bin(self):
        """Exports the filenames contained in the recycle bin"""
        with open(self.output_dir + '\\' + self.computer_name + '_recycle_bin.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(("COMPUTER_NAME", "TYPE", "NAME_1", "NAME_2"), csv_writer)
            idl = shell.SHGetSpecialFolderLocation(0, shellcon.CSIDL_BITBUCKET)
            desktop = shell.SHGetDesktopFolder()
            files = desktop.BindToObject(idl, None, shell.IID_IShellFolder)

            for bin_file in files:
                write_to_csv(
                    [self.computer_name, 'recycle_bin', files.GetDisplayNameOf(bin_file, shellcon.SHGDN_NORMAL),
                     files.GetDisplayNameOf(bin_file, shellcon.SHGDN_FORPARSING)], csv_writer)
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_recycle_bin.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def get_e_mail_attachments(self):
        """Checks OST and PST windows in correct directories and zip it in a given archive"""
        outlook_dirs = look_for_outlook_dirs(get_userprofiles_from_reg())
        for outlook_dir in outlook_dirs:
            outlook_pst_files = look_for_files(outlook_dir + '\\*.pst')
            outlook_ost_files = look_for_files(outlook_dir + '\\*.ost')
            if len(outlook_pst_files) > 0:
                zip_archive(outlook_pst_files, self.output_dir, 'pst', self.logger)
            if len(outlook_ost_files) > 0:
                zip_archive(outlook_ost_files, self.output_dir, 'ost', self.logger)