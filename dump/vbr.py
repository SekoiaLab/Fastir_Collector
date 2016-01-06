
import hexdump
import os
from distorm3 import Decode, Decode16Bits

class Vbr(object):
    def __init__(self, image, offset, dest):
        self.offset = offset
        self.path_image = image
        self.dest = dest
        self.vbr = None

    def extract_vbr(self):
        with open(self.path_image, "rb") as f :
            f.seek(512 * self.offset)
            self.vbr = f.read(512)
        with open(os.path.join(self.dest, "vbr_raw"), "wb") as output_raw :
            output_raw.write(self.vbr)
        with open(os.path.join(self.dest, "vbr.txt"), "w") as output :
            output.write(hexdump.hexdump(self.vbr, "return"))

    def vbrDisassembly(self):
        l = Decode(0x000, self.vbr, Decode16Bits)
        assemblyCode = ""
        for (offset, size, instruction, hexdump) in l:
            assemblyCode = assemblyCode + "%.8x: %-32s %s" % (offset, hexdump, instruction) + "\n"
        with open(os.path.join(self.dest,"vbr_AssemblyCode.txt"), "w") as f:
            f.write(assemblyCode)
