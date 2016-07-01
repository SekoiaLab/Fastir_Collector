import win32file
import struct
import sys


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method


# IOCTLS for interacting with the driver.
CTRL_IOCTRL = CTL_CODE(0x22, 0x101, 0, 3)
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)
INFO_IOCTRL_DEPRECATED = CTL_CODE(0x22, 0x100, 0, 3)


class _Image(object):
    """This class abstracts the image."""
    buffer_size = 1024 * 1024

    def __init__(self, fd):
        self.fd = fd
        self.SetMode()
        self.ParseMemoryRuns()

        # Tell the driver what acquisition mode we want.
        self.GetInfo()
        # self.GetInfoDeprecated()

    def GetInfoDeprecated(self):
        result = win32file.DeviceIoControl(self.fd, INFO_IOCTRL_DEPRECATED, "",
                                           1024, None)
        fmt_string = "QQl"
        offset = struct.calcsize(fmt_string)

        cr3, kpcr, number_of_runs = struct.unpack_from(fmt_string, result)
        for x in range(number_of_runs):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            print "0x%X\t\t0x%X" % (start, length)

    FIELDS = (["CR3", "NtBuildNumber", "KernBase", "KDBG"] +
              ["KPCR%02d" % i for i in range(32)] +
              ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead"] +
              ["Padding%s" % i for i in range(0xff)] +
              ["NumberOfRuns"])

    def ParseMemoryRuns(self):
        self.runs = []

        result = win32file.DeviceIoControl(
            self.fd, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
            fmt_string, result)))

        self.dtb = self.memory_parameters["CR3"]
        self.kdbg = self.memory_parameters["KDBG"]

        offset = struct.calcsize(fmt_string)

        for x in range(self.memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.runs.append((start, length))

    def GetInfo(self):
        for k, v in sorted(self.memory_parameters.items()):
            if k.startswith("Pad"):
                continue

            if not v: continue

            print "%s: \t%#08x (%s)" % (k, v, v)

        print "Memory ranges:"
        print "Start\t\tEnd\t\tLength"

        for start, length in self.runs:
            print "0x%X\t\t0x%X\t\t0x%X" % (start, start + length, length)

    def SetMode(self):
        mode = 1
        win32file.DeviceIoControl(
            self.fd, CTRL_IOCTRL, struct.pack("I", mode), 0, None)

    def PadWithNulls(self, outfd, length):
        while length > 0:
            to_write = min(length, self.buffer_size)
            outfd.write("\x00" * to_write)
            length -= to_write

    def DumpWithRead(self, output_filename):
        """Read the image and write all the data to a raw file."""
        with open(output_filename, "wb") as outfd:
            offset = 0
            for start, length in self.runs:
                if start > offset:
                    print "\nPadding from 0x%X to 0x%X\n" % (offset, start)
                    self.PadWithNulls(outfd, start - offset)

                offset = start
                end = start + length
                while offset < end:
                    to_read = min(self.buffer_size, end - offset)
                    win32file.SetFilePointer(self.fd, offset, 0)

                    _, data = win32file.ReadFile(self.fd, to_read)
                    outfd.write(data)

                    offset += to_read

                    offset_in_mb = offset / 1024 / 1024
                    if not offset_in_mb % 50:
                        sys.stdout.write("\n%04dMB\t" % offset_in_mb)

                    sys.stdout.write(".")
                    sys.stdout.flush()
