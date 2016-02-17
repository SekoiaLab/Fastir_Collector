from __future__ import unicode_literals

from Tkinter import Tk
from ctypes import Structure
from ctypes import sizeof, windll, c_long, c_int, POINTER, pointer, c_char, c_void_p, c_uint
from ctypes.wintypes import DWORD, HMODULE, BYTE
from multiprocessing import Process, Queue, forking
import os
import sys
import traceback

import psutil
from utils.utils import get_csv_writer, write_to_csv, record_sha256_logs
import win32clipboard
import win32api


# if get_architecture()=='86':
# print 'toto'
# import dnscache_ext
# const variable
TH32CS_SNAPPROCESS = 2
TH32CS_SNAPMODULE = 0x00000008
STANDARD_RIGHTS_REQUIRED = 0x000F0000
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004


class MODULEENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('th32ModuleID', DWORD),
                ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD),
                ('ProccntUsage', DWORD),
                ('modBaseAddr', POINTER(BYTE)),
                ('modBaseSize', DWORD),
                ('hModule', HMODULE),
                ('szModule', c_char * 256),
                ('szExePath', c_char * 260)]


class PROCESSENTRY32(Structure):
    _fields_ = [('dwSize', c_uint),
                ('cntUsage', c_uint),
                ('th32ProcessID', c_uint),
                ('th32DefaultHeapID', c_uint),
                ('th32ModuleID', c_uint),
                ('cntThreads', c_uint),
                ('th32ParentProcessID', c_uint),
                ('pcPriClassBase', c_long),
                ('dwFlags', c_uint),
                ('szExeFile', c_char * 260),
                ('th32MemoryBase', c_long),
                ('th32AccessKey', c_long)]

# CreateToolhelp32Snapshot
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [c_int, c_int]
# Process32First
Process32First = windll.kernel32.Process32First
Process32First.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32First.rettype = c_int
# Process32Next
Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32Next.rettype = c_int
# OpenProcess
OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [c_void_p, c_int, c_long]
OpenProcess.rettype = c_long
# GetPriorityClass
GetPriorityClass = windll.kernel32.GetPriorityClass
GetPriorityClass.argtypes = [c_void_p]
GetPriorityClass.rettype = c_long
# CloseHandle
CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [c_void_p]
CloseHandle.rettype = c_int
# Module32First
Module32First = windll.kernel32.Module32First
Module32First.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
Module32First.rettype = c_int
# Module32Next
Module32Next = windll.kernel32.Module32Next
Module32Next.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
Module32Next.rettype = c_int
# GetLastError
GetLastError = windll.kernel32.GetLastError
GetLastError.rettype = c_long


def timer_open_files(proc, q):
    try:
        q.put(proc.open_files())
    except:
        q.put(traceback.format_exc())


class _Popen(forking.Popen):
    def __init__(self, *args, **kw):
        if hasattr(sys, 'frozen'):
            # We have to set original _MEIPASS2 value from sys._MEIPASS
            # to get --onefile mode working.
            # Last character is stripped in C-loader. We have to add
            # '/' or '\\' at the end.
            os.putenv('_MEIPASS2', sys._MEIPASS + os.sep)
        try:
            super(_Popen, self).__init__(*args, **kw)
        finally:
            if hasattr(sys, 'frozen'):
                # On some platforms (e.g. AIX) 'os.unsetenv()' is not
                # available. In those cases we cannot delete the variable
                # but only set it to the empty string. The bootloader
                # can handle this case.
                if hasattr(os, 'unsetenv'):
                    os.unsetenv('_MEIPASS2')
                else:
                    os.putenv('_MEIPASS2', '')


class Process(Process):
    _Popen = _Popen


class _Memory(object):
    def __init__(self, params):
        self.output_dir = params['output_dir']
        self.computer_name = params['computer_name']
        self.logger = params['logger']

    def _GetProcessModules(self, ProcessID, isPrint):
        me32 = MODULEENTRY32()
        me32.dwSize = sizeof(MODULEENTRY32)
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID)

        ret = Module32First(hModuleSnap, pointer(me32))
        if ret == 0:
            errCode = GetLastError()
            self.logger.warn('GetProcessModules() Error on Module32First[%d] with PID : %d' % (errCode, ProcessID))
            self.logger.warn(win32api.FormatMessage(errCode))
            CloseHandle(hModuleSnap)
            return []

        modules = []
        while ret:
            if isPrint:
                self.logger.info("   executable	 = %s" % me32.szExePath)
            modules.append(me32.szExePath)

            ret = Module32Next(hModuleSnap, pointer(me32))
        CloseHandle(hModuleSnap)
        return modules

    def _csv_all_modules_dll(self):
        """Outputs all processes and their opened dll in a csv"""
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        pe32 = PROCESSENTRY32()
        pe32.dwSize = sizeof(PROCESSENTRY32)
        ret = Process32First(hProcessSnap, pointer(pe32))

        with open(self.output_dir + '\\' + self.computer_name + '_processes_dll.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(["COMPUTER_NAME", "TYPE", "PID", "PROCESS_NAME", "MODULE"], csv_writer)
            while ret:
                modules = self._GetProcessModules(pe32.th32ProcessID, False)
                if len(modules) > 0:
                    process_name = modules.pop(0)  # first element is the name of the process
                    for module in modules:
                        write_to_csv([self.computer_name, 'processes_dll', unicode(pe32.th32ProcessID), process_name, module],
                                     csv_writer)

                ret = Process32Next(hProcessSnap, pointer(pe32))
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_processes_dll.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def _csv_all_modules_opened_files(self):
        """Outputs all processes and their opened files in a csv"""
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        pe32 = PROCESSENTRY32()
        pe32.dwSize = sizeof(PROCESSENTRY32)
        ret = Process32First(hProcessSnap, pointer(pe32))

        with open(self.output_dir + '\\' + self.computer_name + '_processes_opened_files.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(["COMPUTER_NAME", "TYPE", "PID", "PROCESS_NAME", "FILENAME"], csv_writer)
            while ret:
                try:
                    p = psutil.Process(pe32.th32ProcessID)
                    process_name = p.name()
                    self.logger.info(
                        'Getting opened files for : ' + process_name + '(' + unicode(pe32.th32ProcessID) + ')')
                    # We need open a subprocess because get_open_files may hang forever
                    q = Queue()
                    process = Process(target=timer_open_files, args=(p, q,))
                    process.start()
                    # We wait for 2 seconds
                    process.join(2)
                    if process.is_alive():
                        # If the subprocess is still alive, assume it is hanged and kill it
                        q.close()
                        process.terminate()
                    else:
                        # Otherwise, continue normal processing
                        opened_files = q.get()
                        if isinstance(opened_files, list):
                            for opened_file in opened_files:
                                write_to_csv(
                                    [self.computer_name, 'processes_opened_files', unicode(pe32.th32ProcessID), process_name,
                                     opened_file[0]], csv_writer)
                except psutil.AccessDenied:
                    self.logger.warn('Could not open handle for PID : ' + unicode(pe32.th32ProcessID))

                ret = Process32Next(hProcessSnap, pointer(pe32))
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_processes_opened_files.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

    def csv_clipboard(self):
        """Exports the clipboard contents"""
        # TODO : what happens if clipboard contents is a CSV string ?
        self.logger.info('Getting clipboard contents')
        with open(self.output_dir + '\\' + self.computer_name + '_clipboard.csv', 'wb') as output:
            csv_writer = get_csv_writer(output)
            write_to_csv(["COMPUTER_NAME", "TYPE", "DATA"], csv_writer)

            r = None    #initialize the local variable r
            try:
                r = Tk()  # Using Tk instead because it supports exotic characters
                data = r.selection_get(selection='CLIPBOARD')
                r.destroy()
                write_to_csv([self.computer_name, 'clipboard', unicode(data)], csv_writer)
            except:
                if r != None:   # Verify that r exist before calling destroy
                    r.destroy()
                win32clipboard.OpenClipboard()
                clip = win32clipboard.EnumClipboardFormats(0)
                while clip:
                    try:
                        format_name = win32clipboard.GetClipboardFormatName(clip)
                    except win32api.error:
                        format_name = "?"
                    self.logger.info('format ' + unicode(clip) + ' ' + unicode(format_name))
                    if clip == 15:  # 15 seems to be a list of filenames
                        filenames = win32clipboard.GetClipboardData(clip)
                        for filename in filenames:
                            write_to_csv([self.computer_name, 'clipboard', filename], csv_writer)
                    clip = win32clipboard.EnumClipboardFormats(clip)
                win32clipboard.CloseClipboard()
        record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_clipboard.csv',
                           self.output_dir + '\\' + self.computer_name + '_sha256.log')

        # 	def csv_dns_cache(self):
        # 		if get_architecture()=='86':
        # 			with open(self.output_dir + '\\' + self.computer_name + '_dnscache.csv','wb') as output:
        # 				csv_writer=get_csv_writer(output)
        # 				for entry in dnscache_ext.dnscache().split('\r\n'):
        # 					if ':' in entry:
        # 						token=entry.split(':')
        # 						fqdn=token[0]
        # 						ip_addr=token[1]
        # 						write_to_csv([fqdn,ip_addr], csv_writer)
        #
        # 			record_sha256_logs(self.output_dir + '\\' + self.computer_name + '_dnscache.csv',self.output_dir+'\\' + self.computer_name+'_sha256.log')
