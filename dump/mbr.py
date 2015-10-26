from construct import *
from distorm3 import Decode, Decode16Bits
import hexdump
import os


class Mbr:
    def __init__(self, path):
        self.mbrHexa = ""
        self.mbrStruct = ""
        self.bootloaderCode = ""
        self.offset = 0
        self.partition = {"name": []}
        self.signature = ""
        self.path = path
        self.mbr = Struct("mbr",
                          HexDumpAdapter(Bytes("bootloaderCode", 446)),
                          Array(4,
                                Struct("partitions",
                                       Enum(Byte("state"),
                                            INACTIVE=0x00,
                                            ACTIVE=0x80,
                                            ),
                                       BitStruct("beginning",
                                                 Octet("head"),
                                                 Bits("sect", 6),
                                                 Bits("cyl", 10),
                                                 ),
                                       Enum(UBInt8("type"),
                                            Nothing=0x00,
                                            FAT12_CHS=0x01,
                                            XENIX_ROOT=0x02,
                                            XENIX_USR=0x03,
                                            FAT16_16_32MB_CHS=0x04,
                                            Extended_DOS=0x05,
                                            FAT16_32MB_CHS=0x06,
                                            NTFS=0x07,
                                            FAT32_CHS=0x0b,
                                            FAT32_LBA=0x0c,
                                            FAT16_32MB_2GB_LBA=0x0e,
                                            Microsoft_Extended_LBA=0x0f,
                                            Hidden_FAT12_CHS=0x11,
                                            Hidden_FAT16_16_32MB_CHS=0x14,
                                            Hidden_FAT16_32MB_2GB_CHS=0x16,
                                            AST_SmartSleep_Partition=0x18,
                                            Hidden_FAT32_CHS=0x1b,
                                            Hidden_FAT32_LBA=0x1c,
                                            Hidden_FAT16_32MB_2GB_LBA=0x1e,
                                            PQservice=0x27,
                                            Plan_9_partition=0x39,
                                            PartitionMagic_recovery_partition=0x3c,
                                            Microsoft_MBR_Dynamic_Disk=0x42,
                                            GoBack_partition=0x44,
                                            Novell=0x51,
                                            CP_M=0x52,
                                            Unix_System_V=0x63,
                                            PC_ARMOUR_protected_partition=0x64,
                                            Solaris_x86_or_Linux_Swap=0x82,
                                            LINUX_NATIVE=0x83,
                                            Hibernation=0x84,
                                            Linux_Extended=0x85,
                                            NTFS_Volume_Set=0x86,
                                            BSD_OS=0x9f,
                                            FreeBSD=0xa5,
                                            OpenBSD=0xa6,
                                            Mac_OSX=0xa8,
                                            NetBSD=0xa9,
                                            Mac_OSX_Boot=0xab,
                                            MacOS_X_HFS=0xaf,
                                            BSDI=0xb7,
                                            BSDI_Swap=0xb8,
                                            Boot_Wizard_hidden=0xbb,
                                            Solaris_8_boot_partition=0xbe,
                                            CP_M_86=0xd8,
                                            Dell_PowerEdge_Server_utilities_FAT_FS=0xde,
                                            DG_UX_virtual_disk_manager_partition=0xdf,
                                            BeOS_BFS=0xeb,
                                            EFI_GPT_Disk=0xee,
                                            EFI_System_Partition=0xef,
                                            VMWare_File_System=0xfb,
                                            VMWare_Swap=0xfc,
                                            _default_=Pass,
                                            ),
                                       BitStruct("ending",
                                                 Octet("head"),
                                                 Bits("sect", 6),
                                                 Bits("cyl", 10),
                                                 ),

                                       ULInt32("sector_offset"),  # offset from MBR in sectors
                                       ULInt32("size"),  # in sectors
                                       )
                                ),
                          Const(Bytes("signature", 2), "\x55\xAA"),
                          )

    def save_mbr(self, image):
        file_image = open(image, "rb")
        file_mbr = open(self.path + os.path.sep + "mbr", "wb")
        try:
            file_mbr.write(file_image.read(512))
        except Exception as err:
            self.logger.error("Error to extract MBR")
        file_image.close()
        file_mbr.close()
        return file_mbr.name

    def extract_hexa(self, file_mbr):
        # file = open(fileMbr,"rb")
        hex_str = ""
        for line in file_mbr.split('\n'):
            hex_str += line[10:58]
        hex_str = hex_str.replace(' ', '')
        self.mbrHexa = hex_str

    def mbr_parsing(self, image):
        file_mbr = self.save_mbr(image)
        self.extract_hexa(hexdump.hexdump(open(file_mbr, 'rb').read(512), "return"))
        try:
            cap1 = self.mbrHexa.decode("hex")
            self.mbrStruct = self.mbr.parse(cap1)
            return self.mbrStruct
        except Exception as inst:
            self.logger.error("Error MBR Parsing")

    def boot_loader_disassembly(self):
        l = Decode(0x000, self.mbrStruct.bootloaderCode, Decode16Bits)
        assembly_code = ""
        for (offset, size, instruction, hexdump) in l:
            assembly_code = assembly_code + "%.8x: %-32s %s" % (offset, hexdump, instruction) + "\n"
        h_file = open(self.path + os.path.sep + "bootLoaderAssemblyCode.txt", "w")
        h_file.write(assembly_code)
        h_file.close()
