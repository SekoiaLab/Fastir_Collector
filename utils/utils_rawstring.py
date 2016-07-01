from settings_rawstring import STARTSTR
import struct
import binascii
import wmi
import win32file


def sekoiamagic(filename):
    fh = open(filename, 'r', 0)
    s = fh.read(32)

    if s.startswith('MZ'):
        fh.seek(128, 0)
        x = fh.read(4)
        if x == 'PE\0\0':
            return 'application/x-ms-pe'  # ??
        # Je l'ai aussi trouve a l'offset 248 ou 256
        fh.seek(248, 0)
        x = fh.read(4)
        if x == 'PE\0\0':
            return 'application/x-ms-pe'  # ??
        fh.seek(256, 0)
        x = fh.read(4)
        if x == 'PE\0\0':
            return 'application/x-ms-pe'  # ??

        fh.seek(30, 0)
        x = fh.read(64)
        if x.startswith('Copyright 1989-1990 PKWARE Inc.'):
            return 'application/x-zip'
        if x.startswith('PKLITE Copr.'):
            return 'application/x-zip'
        fh.seek(36, 0)
        x = fh.read(64)
        if x.startswith("LHa's SFX") or x.startswith("LHA's SFX"):
            return 'application/x-lha'
        return 'application/x-ms-dos-executable'

    fh.seek(2080, 0)
    x = fh.read(32)
    if x.startswith('Microsoft Excel 5.0 Worksheet'):
        return 'application/vnd.ms-excel'

    if s.startswith('1\276\0\0') or s.startswith('PO^Q`') or \
            s.startswith('\3767\0#') or s.startswith('\333\245-\0\0\0'):
        fh.seek(2112, 0)
        x = fh.read(8)
        if x == "MSWordDoc":
            return "application/msword"
        fh.seek(2108, 0)
        x = fh.read(8)
        if x == "MSWordDoc":
            return "application/msword"
        fh.seek(546, 0)
        x = fh.read(4)
        if x == "bjbj" or x == "jbjb":
            return "application/msword"

    fh.seek(2, 0)
    x = fh.read(3)
    if x == '-lh':
        fh.seek(6)
        x = fh.read(1)
        if x == '-':
            return 'application/x-lha'

    # if s.startswith('\377O\377Q\0'):
    # return 'image/jp2'
    # fh.seek(3, 0)
    # x = fh.read(4)
    # if x == '\014jP ':
    # return 'image/jp2'
    # fh.seek(20, 0)
    # x = fh.read(3)
    # if x == 'jp2':
    # return 'image/jp2'

    if s.startswith('<?xml'):
        fh.seek(4, 0)
        x = fh.read(97)  # ou 97 + taille_de_la_chaine ?
        if "office:document" in x:
            fh.seek(100)
            x = fh.read(3901)
            for m in ('application/vnd.oasis.opendocument.graphics-flat-xml',
                      'application/vnd.oasis.opendocument.presentation-flat-xml',
                      'application/vnd.oasis.opendocument.text-flat-xml'):
                if 'office:mimetype="' + m + '"' in x:
                    return m

    if s.startswith('PK\003\004'):
        fh.seek(30, 0)
        x = fh.read(8)
        if x == "mimetype":
            fh.seek(38, 0)
            x = fh.read(64)
            for m in ("application/vnd.oasis.opendocument.text-web",
                      "application/vnd.oasis.opendocument.chart",
                      "application/vnd.oasis.opendocument.chart-template",
                      "application/vnd.oasis.opendocument.formula",
                      "application/vnd.oasis.opendocument.formula-template",
                      "application/vnd.oasis.opendocument.graphics",
                      "application/vnd.oasis.opendocument.graphics-template",
                      "application/vnd.oasis.opendocument.image",
                      "application/vnd.oasis.opendocument.presentation",
                      "application/vnd.oasis.opendocument.presentation-template",
                      "application/vnd.oasis.opendocument.spreadsheet",
                      "application/vnd.oasis.opendocument.spreadsheet-template",
                      "application/vnd.oasis.opendocument.text",
                      "application/vnd.oasis.opendocument.text-template",
                      "application/vnd.oasis.opendocument.text-master"):
                if x.startswith(m):
                    return m

    # On veut d'abord tester les chaines longues, puis les courtes qui sont
    # moins precises
    for k in reversed(sorted(STARTSTR.keys())):
        if s.startswith(k):
            return STARTSTR[k]

    return None


def hexbytes(xs, group_size=1, byte_separator=' ', group_separator=' '):
    # utility functions for printing data as hexdumps
    def ordc(c):
        return ord(c) if isinstance(c, str) else c

    if len(xs) <= group_size:
        s = byte_separator.join('%02X' % (ordc(x)) for x in xs)
    else:
        r = len(xs) % group_size
        s = group_separator.join(
            [byte_separator.join('%02X' % (ordc(x)) for x in group) for group in zip(*[iter(xs)] * group_size)]
        )
        if r > 0:
            s += group_separator + byte_separator.join(['%02X' % (ordc(x)) for x in xs[-r:]])
    return s.lower()


def hexprint(xs):
    def chrc(c):
        return c if isinstance(c, str) else chr(c)

    def ordc(c):
        return ord(c) if isinstance(c, str) else c

    def isprint(c):
        return ordc(c) in range(32, 127) if isinstance(c, str) else c > 31

    return ''.join([chrc(x) if isprint(x) else '.' for x in xs])


def hexdump(xs, group_size=4, byte_separator=' ', group_separator='-', printable_separator='  ', address=0,
            address_format='%04X', line_size=16):
    if address is None:
        s = hexbytes(xs, group_size, byte_separator, group_separator)
        if printable_separator:
            s += printable_separator + hexprint(xs)
    else:
        r = len(xs) % line_size
        s = ''
        bytes_len = 0
        for offset in range(0, len(xs) - r, line_size):
            chunk = xs[offset:offset + line_size]
            v_bytes = hexbytes(chunk, group_size, byte_separator, group_separator)
            s += (address_format + ': %s%s\n') % (
                address + offset, v_bytes, printable_separator + hexprint(chunk) if printable_separator else '')
            bytes_len = len(v_bytes)

        if r > 0:
            offset = len(xs) - r
            chunk = xs[offset:offset + r]
            v_bytes = hexbytes(chunk, group_size, byte_separator, group_separator)
            v_bytes += ' ' * (bytes_len - len(v_bytes))
            s += (address_format + ': %s%s\n') % (
                address + offset, v_bytes, printable_separator + hexprint(chunk) if printable_separator else '')

    return s


# decode ATRHeader from
# analyzeMFT.py routines
# Copyright (c) 2010 David Kovar.
def decodeATRHeader(s):
    d = dict()
    d['type'] = struct.unpack("<L", s[:4])[0]
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L", s[4:8])[0]
    d['res'] = struct.unpack("B", s[8])[0]
    d['nlen'] = struct.unpack("B", s[9])[0]  # This name is the name of the ADS, I think.
    d['name_off'] = struct.unpack("<H", s[10:12])[0]
    d['flags'] = struct.unpack("<H", s[12:14])[0]
    d['id'] = struct.unpack("<H", s[14:16])[0]
    if d['res'] == 0:
        d['ssize'] = struct.unpack("<L", s[16:20])[0]
        d['soff'] = struct.unpack("<H", s[20:22])[0]
        d['idxflag'] = struct.unpack("<H", s[22:24])[0]
    else:
        d['start_vcn'] = struct.unpack("<d", s[16:24])[0]
        d['last_vcn'] = struct.unpack("<d", s[24:32])[0]
        d['run_off'] = struct.unpack("<H", s[32:34])[0]
        d['compusize'] = struct.unpack("<H", s[34:36])[0]
        d['f1'] = struct.unpack("<I", s[36:40])[0]
        d['alen'] = struct.unpack("<d", s[40:48])[0]
        d['ssize'] = struct.unpack("<d", s[48:56])[0]
        d['initsize'] = struct.unpack("<d", s[56:64])[0]

    return d


def twos_comp(val, bits):
    """compute the 2's compliment of int value val"""
    if (val & (1 << (bits - 1))) != 0:
        val -= (1 << bits)
    return val


# decode NTFS data runs from a MFT type 0x80 record ala:
# http://inform.pucp.edu.pe/~inf232/Ntfs/ntfs_doc_v0.5/concepts/data_runs.html
def decode_data_runs(dataruns):
    decode_pos = 0
    header = dataruns[decode_pos]
    while header != '\x00':
        # print('HEADER\n' + hexdump(header))
        offset = int(binascii.hexlify(header)[0])
        runlength = int(binascii.hexlify(header)[1])
        # print('OFFSET %d LENGTH %d' %( offset,runlength))

        # move into the length data for the run
        decode_pos += 1

        # print(decodePos,runlength)
        length = dataruns[decode_pos:decode_pos + int(runlength)][::-1]
        # print('LENGTH\n'+hexdump(length))
        length = int(binascii.hexlify(length), 16)

        hexoffset = dataruns[decode_pos + runlength:decode_pos + offset + runlength][::-1]
        # print('HEXOFFSET\n' +hexdump(hexoffset))
        cluster = twos_comp(int(binascii.hexlify(hexoffset), 16), offset * 8)

        yield (length, cluster)
        decode_pos = decode_pos + offset + runlength
        header = dataruns[decode_pos]
        # break


def get_physical_drives():
    w = wmi.WMI()
    for physical_disk in w.Win32_DiskDrive():
        yield physical_disk.DeviceID, get_physical_drive_size(physical_disk.DeviceID)


def get_physical_drive_size(drive="\\\\.\\PhysicalDrive0"):
    """Uses IOCTL to get physical drives size"""
    handle = win32file.CreateFile(drive, 0, win32file.FILE_SHARE_READ, None, win32file.OPEN_EXISTING, 0, 0)
    if handle:
        IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000
        info = win32file.DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, '', 24)
        win32file.CloseHandle(handle)
        if info:
            (cyl_lo, cyl_hi, media_type, tps, spt, bps) = struct.unpack('6L', info)
            mediasize = ((cyl_hi << 32) + cyl_lo) * tps * spt * bps
            """print mediasize, 'bytes'
            print mediasize/10**3, 'kbytes'
            print mediasize/10**6, 'Mbytes'
            print mediasize/10**9, 'Gbytes'"""
            return mediasize
