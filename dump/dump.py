from __future__ import unicode_literals

from StringIO import StringIO
import binascii
import os
import struct
import time
import win32file
import yaml

from _analyzemft.mftsession import _MftSession
from disk_analysis import DiskAnalysis
from environment_settings import Partitions, Disks, OperatingSystem, \
    EnvironmentVariable
from mbr import Mbr
from settings import LONGLONGSIZE, BYTESIZE, WORDSIZE
from utils.utils import get_local_drives, create_driver_service, start_service, stop_and_delete_driver_service
from utils.utils_rawstring import decodeATRHeader, decode_data_runs, get_physical_drives
from winpmem import _Image


class _Dump(object):
    def __init__(self, params):
        self.computer_name = params['computer_name']
        self.output_dir = params['output_dir']
        self.logger = params['logger']
        self.mft_export = yaml.load(params['mft_export'])
        if 'rekall' in params:
            self.plugins = params['rekall']

    def csv_mft(self):
        """Exports the MFT from each local drives and creates a csv from it."""
        local_drives = get_local_drives()
        for local_drive in local_drives:
            self.logger.info('Exporting MFT for drive : ' + local_drive)
            ntfsdrive = file('\\\\.\\' + local_drive.replace('\\', ''), 'rb')
            if os.name == 'nt':
                # poor win can't seek a drive to individual bytes..only 1 sector at a time..
                # convert MBR to stringio to make it seekable
                ntfs = ntfsdrive.read(512)
                ntfsfile = StringIO(ntfs)
            else:
                ntfsfile = ntfsdrive

                # parse the MBR for this drive to get the bytes per sector,sectors per cluster and MFT location.
            # bytes per sector
            ntfsfile.seek(0x0b)
            bytesPerSector = ntfsfile.read(WORDSIZE)
            bytesPerSector = struct.unpack(b'<h', binascii.unhexlify(binascii.hexlify(bytesPerSector)))[0]

            # sectors per cluster

            ntfsfile.seek(0x0d)
            sectorsPerCluster = ntfsfile.read(BYTESIZE)
            sectorsPerCluster = struct.unpack(b'<b', binascii.unhexlify(binascii.hexlify(sectorsPerCluster)))[0]

            # get mftlogical cluster number
            ntfsfile.seek(0x30)
            cno = ntfsfile.read(LONGLONGSIZE)
            mftClusterNumber = struct.unpack(b'<q', binascii.unhexlify(binascii.hexlify(cno)))[0]

            # MFT is then at NTFS + (bytesPerSector*sectorsPerCluster*mftClusterNumber)
            mftloc = long(bytesPerSector * sectorsPerCluster * mftClusterNumber)
            ntfsdrive.seek(0)
            ntfsdrive.seek(mftloc)
            mftraw = ntfsdrive.read(1024)

            # We've got the MFT record for the MFT itself.
            # parse it to the DATA section, decode the data runs and send the MFT over TCP
            mftDict = {}
            mftDict['attr_off'] = struct.unpack(b"<H", mftraw[20:22])[0]
            ReadPtr = mftDict['attr_off']
            with open(self.output_dir + '\\' + self.computer_name + '_mft_' + local_drive[0] + '.mft', 'wb') as output:
                while ReadPtr < len(mftraw):
                    ATRrecord = decodeATRHeader(mftraw[ReadPtr:])
                    if ATRrecord['type'] == 0x80:
                        dataruns = mftraw[ReadPtr + ATRrecord['run_off']:ReadPtr + ATRrecord['len']]
                        prevCluster = None
                        prevSeek = 0
                        for length, cluster in decode_data_runs(dataruns):
                            if prevCluster == None:
                                ntfsdrive.seek(cluster * bytesPerSector * sectorsPerCluster)
                                prevSeek = ntfsdrive.tell()
                                r_data = ntfsdrive.read(length * bytesPerSector * sectorsPerCluster)
                                output.write(r_data)
                                prevCluster = cluster
                            else:
                                ntfsdrive.seek(prevSeek)
                                newpos = prevSeek + (cluster * bytesPerSector * sectorsPerCluster)
                                ntfsdrive.seek(newpos)
                                prevSeek = ntfsdrive.tell()
                                r_data = ntfsdrive.read(length * bytesPerSector * sectorsPerCluster)
                                output.write(r_data)
                                prevCluster = cluster
                        break
                    if ATRrecord['len'] > 0:
                        ReadPtr = ReadPtr + ATRrecord['len']
            # export on csv
            if self.mft_export:
                session = _MftSession(self.logger,
                                      self.output_dir + '\\' + self.computer_name + '_mft_' + local_drive[0] + '.mft',
                                      self.output_dir + '\\' + self.computer_name + '_mft_' + local_drive[0] + '.csv')
                session.open_files()
                session.process_mft_file()

    def csv_export_dd(self):
        """Dumps the disk image"""
        for d, size in get_physical_drives():
            already = 0
            buff = 65536
            with open(self.output_dir + '\\' + self.computer_name + '.dd', 'wb') as fw:
                with open(d, 'rb') as fr:
                    while already < int(size):
                        already = already + buff
                        r = fr.read(buff)
                        fw.write(r)

    def csv_export_ram(self):
        """Dump ram using winpmem"""
        hSvc = create_driver_service(self.logger)
        start_service(hSvc, self.logger)
        try:
            fd = win32file.CreateFile(
                "\\\\.\\pmem",
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_NORMAL,
                None)
            try:
                t = time.time()
                image = _Image(fd)
                self.logger.info("Imaging to " + self.output_dir + '\\' + self.computer_name + '_memdump.raw')
                image.DumpWithRead(self.output_dir + '\\' + self.computer_name + '_memdump.raw')
                self.logger.info("Completed in %s seconds" % (time.time() - t))
            finally:
                win32file.CloseHandle(fd)
        finally:
            stop_and_delete_driver_service(hSvc)

    def csv_mbr(self):
        """Extract MBR and BootLoader"""
        informations = DiskAnalysis(self.output_dir)
        partition = Partitions(self.output_dir, self.logger)
        disk = Disks()
        operatingSystem = OperatingSystem()
        envVar = EnvironmentVariable()
        mbr = Mbr(self.output_dir)
        informations.os = operatingSystem.os_information(informations.currentMachine)
        informations.listDisks = disk.get_disk_information(informations.currentMachine)
        self.logger.info('MBR Extracting')
        for d in informations.listDisks:
            informations.mbrDisk = mbr.mbr_parsing(d.deviceID)
            mbr.boot_loader_disassembly()
        self.logger.info('BootLoader Extracting')
        informations.envVarList = os.environ
        informations.listPartitions = partition.partition_information(informations.currentMachine)
        informations.save_informations()
