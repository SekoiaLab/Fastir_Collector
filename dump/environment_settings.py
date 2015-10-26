from construct import *
import hexdump
import os


class EnvironmentVariable(object):
    def __init__(self):
        self.name = ""
        self.value = ""

    def environment_variable(self, current_machine):
        list_env_var = []
        for ve in current_machine.Win32_environment():
            env_var = EnvironmentVariable()
            env_var.name = ve.name
            env_var.value = ve.VariableValue
            list_env_var.append(env_var)
        return list_env_var

    def __str__(self):
        output = ""
        output += "Name : " + self.name + "\nValue :" + self.value
        return output


class OperatingSystem(object):
    def __init__(self):
        self.version = ""
        self.directory = ""
        self.primary = ""

    def os_information(self, current_machine):
        for data in current_machine.Win32_OperatingSystem():
            self.version = data.Caption
            self.directory = data.SystemDirectory
            self.primary = data.Primary
        return self

    def __str__(self):
        output = ""
        output += "\nOperating System :" + str(self.version) + "\nSystem Directory : " + str(
            self.directory) + "\nPrimary Operating System : " + str(self.primary)
        return output


class Disks(object):
    def __init__(self):
        self.Partitions = ""
        self.physical = ""
        self.bytesPerSector = 0
        self.totalHeads = 0
        self.totalSectors = 0
        self.totalTracks = 0
        self.tracksPerCylinder = 0
        self.totalCylinders = 0
        self.deviceID = ""
        self.size = 0

    def get_disk_information(self, current_machine):
        disks = []
        for physicalDisk in current_machine.Win32_DiskDrive():
            disk = Disks()
            disk.physical = physicalDisk.Caption
            disk.deviceID = physicalDisk.DeviceID
            disk.Partitions = physicalDisk.Partitions
            disk.bytesPerSector = physicalDisk.BytesPerSector
            disk.totalSectors = physicalDisk.TotalSectors
            disk.totalCylinders = physicalDisk.TotalCylinders
            disk.totalHeads = physicalDisk.TotalHeads
            disk.totalSectors = physicalDisk.TotalSectors
            disk.totalTracks = physicalDisk.TotalTracks
            disk.tracksPerCylinder = physicalDisk.TracksPerCylinder
            disk.size = physicalDisk.Size
            disks.append(disk)
        return disks

    def __str__(self):
        output = ""
        output += "\nPhysical Disk : " + str(self.physical) + "\nPartitions : " + str(self.Partitions)
        output += "\nBytes per sector : " + str(self.bytesPerSector) + "\nTotal Heads :" + str(self.totalHeads)
        output += "\nTotal Sectors : " + str(self.totalSectors) + "\nTotal Tracks :" + str(
            self.totalTracks) + "\nTracks per Cylinder : " + str(self.tracksPerCylinder)
        output += "\nTotal Cylinders : " + str(self.totalCylinders) + "\nSize :" + str(self.size) + "\n"
        return output


class Partitions:
    def __init__(self, path, logger):
        self.logger = logger
        self.path = path
        self.type = ""
        self.partName = ""
        self.blockSize = 0
        self.size = 0
        self.bootSectorStruct = ""
        self.disk = ""
        self.bytesPerSector = 0
        self.sectorPerCluster = 0
        self.reservedSectors = ""
        self.sectorsPerTrack = 0
        self.numberOfHeads = 0
        self.hiddenSectors = 0
        self.totalSectors = 0
        self.mftLogicalClusterNumber = 0
        self.mftmirrLogicalClusterNumber = 0
        self.clusterPerFileRecordSegment = 0
        self.clustersPerIndexBuffer = 0
        self.volumeSerialNumber = 0
        self.numberCopiesFat = 0
        self.maximumRootEntryDirectories = 0
        self.numberOfSectorsSmaller32mb = 0
        self.sectorsNumberFat = 0
        self.fat32DriveVersion = ""
        self.sectorNumberFsInformation = 0
        self.sectorNumberPartition = 0
        self.sectorNumberBackupBoot = 0
        self.serialNumberPartition = ""
        self.fatName = ""
        self.possibleRootEntryNumber = 0
        self.numberOfSectorsSmaller32mb
        self.hexaBootSector = ""
        self.fat12BootSector = Struct("FAT12 boot sector",
                                      Bytes("jump", 3),
                                      ULInt64("OEM_name"),
                                      ULInt16("bytesPerSector"),
                                      ULInt8("sectors_per_cluster"),
                                      ULInt16("reservedSectors"),
                                      ULInt8("number_copies_fat"),
                                      ULInt16("possible_root_entry _number"),
                                      ULInt16("number_of_sectors_smaller_32mb"),
                                      ULInt8("media_descriptor"),
                                      ULInt16("sectors_per_fat"),
                                      ULInt16("sectorsPerTrack"),
                                      ULInt16("number_of_head"),
                                      ULInt32("number_hidden_sectors"),
                                      ULInt32("large_number_sector_greater_32mb"),
                                      ULInt8("drive_number"),
                                      ULInt8("reserved"),
                                      ULInt8("extended_boot_signature"),
                                      ULInt32("volumeSerialNumber"),
                                      Bytes("volume_label", 11),
                                      ULInt64("fs_type"),
                                      Bytes("bootstrap_code", 448),
                                      ULInt16("signature")
                                      )

        self.fat16BootSector = Struct("FAT16 boot sector",
                                      Bytes("jump", 3),
                                      ULInt64("OEM_name"),
                                      ULInt16("bytesPerSector"),
                                      ULInt8("sectors_per_cluster"),
                                      ULInt16("reservedSectors"),
                                      ULInt8("number_copies_fat"),
                                      ULInt16("maximum_root_entry _directories"),
                                      ULInt16("number_of_sectors_smaller_32mb"),
                                      ULInt8("media_descriptor"),
                                      ULInt16("sectors_per_fat"),
                                      ULInt16("sectorsPerTrack"),
                                      ULInt16("number_of_head"),
                                      ULInt32("number_hidden_sectors"),
                                      ULInt32("sectors_number_partition"),
                                      ULInt16("logical_drive_number"),
                                      ULInt8("extended_signature"),
                                      ULInt32("serial_number_partition"),
                                      Bytes("volume_name_partition", 11),
                                      ULInt64("fat_name"),
                                      Bytes("executable_code", 448),
                                      Bytes("signature", 2)
                                      )

        self.fat32BootSector = Struct("FAT32 boot sector",
                                      Bytes("jump", 3),
                                      ULInt64("OEM_name"),
                                      ULInt16("bytesPerSector"),
                                      ULInt8("sectors_per_cluster"),
                                      Bytes("reservedSectors", 2),
                                      ULInt8("number_copies_fat"),
                                      ULInt16("maximum_root_entry _directories"),
                                      ULInt16("number_of_sectors_smaller_32mb"),
                                      ULInt8("media_descriptor"),
                                      ULInt16("secors_per_fat_olderfatsystem"),
                                      ULInt16("sectorsPerTrack"),
                                      ULInt16("number_of_head"),
                                      ULInt32("number_hidden_sectors"),
                                      ULInt32("sectors_number_partition"),
                                      ULInt32("sectors_number_fat"),
                                      ULInt16("flags"),
                                      ULInt16("fat32Drive_version"),
                                      ULInt32("cluster_number_start_of_rootDirectory"),
                                      ULInt16("sector_number_fs_information"),
                                      ULInt16("sector_number_backupBoot"),
                                      Bytes("reserved", 12),
                                      ULInt8("logical_drive_number"),
                                      Bytes("unused", 1),
                                      ULInt8("extended_signature"),
                                      ULInt32("serial_number_partition"),
                                      Bytes("volume_name_partition", 11),
                                      ULInt64("fat_name"),
                                      Bytes("executable_code", 420),
                                      Bytes("signature", 2)
                                      )

        self.bootSectorNtfs = Struct("NTFS boot sector",
                                     Bytes("jump", 3),
                                     Bytes("oem_id", 8),
                                     ULInt16("bytesPerSector"),
                                     ULInt8("sectors_per_cluster"),
                                     Bytes("reservedSectors", 2),
                                     Bytes("always 0", 3),
                                     ULInt16("not used by NTFS"),
                                     ULInt8("Media descriptor"),
                                     Bytes("always0", 2),
                                     ULInt16("sectorsPerTrack"),
                                     ULInt16("numberOfHeads"),
                                     ULInt32("hiddenSectors"),
                                     Bytes("not_used_by_ntfs", 8),
                                     ULInt64("totalSectors"),
                                     ULInt64("mftLogicalClusterNumber"),
                                     ULInt64("mftmirrLogicalClusterNumber"),
                                     ULInt32("clusterPerFileRecordSegment"),
                                     ULInt8("clustersPerIndexBuffer"),
                                     Bytes("not_used_ntfs", 3),
                                     ULInt64("volumeSerialNumber"),
                                     ULInt32("checksum")
                                     )

    def partition_information(self, current_machine):
        list_partitions = []
        for physicalDisk in current_machine.Win32_DiskDrive():
            for partitions in physicalDisk.associators("Win32_DiskDriveToDiskPartition"):
                for logicalDisk in partitions.associators("Win32_LogicalDiskToPartition"):
                    partition = Partitions(self.path, self.logger)
                    partition.disk = physicalDisk.Caption
                    partition.partName = logicalDisk.Caption
                    partition.type = logicalDisk.FileSystem
                    partition.blockSize = logicalDisk.BlockSize
                    partition.size = logicalDisk.Size
                    localDrive = partition.partName + "\\"
                    ntfsdrive = '\\\\.\\' + localDrive.replace('\\', '')
                    partition = self.boot_sector_info(ntfsdrive, partition.type, partition)

                    list_partitions.append(partition)
        return list_partitions

    def boot_sector_info(self, part, type, partition):
        bootSector = self.save_boot_sector(part)
        self.extract_hexa(bootSector)
        try:
            cap1 = self.hexaBootSector.decode("hex")
            if type == "NTFS":
                self.bootSectorStruct = self.bootSectorNtfs.parse(cap1)
                partition.sectorPerCluster = self.bootSectorStruct.sectors_per_cluster
                partition.bytesPerSector = self.bootSectorStruct.bytesPerSector
                partition.clusterPerFileRecordSegment = self.bootSectorStruct.clusterPerFileRecordSegment
                partition.clustersPerIndexBuffer = self.bootSectorStruct.clustersPerIndexBuffer
                partition.hiddenSectors = self.bootSectorStruct.hiddenSectors
                partition.mftLogicalClusterNumber = self.bootSectorStruct.mftLogicalClusterNumber
                partition.mftmirrLogicalClusterNumber = self.bootSectorStruct.mftmirrLogicalClusterNumber
                partition.numberOfHeads = self.bootSectorStruct.numberOfHeads
                partition.reservedSectors = self.bootSectorStruct.reservedSectors
                partition.sectorsPerTrack = self.bootSectorStruct.sectorsPerTrack
                partition.totalSectors = self.bootSectorStruct.totalSectors
                partition.volumeSerialNumber = self.bootSectorStruct.volumeSerialNumber

            elif type == "Fat32":
                self.bootSectorStruct = self.fat32BootSector.parse(cap1)
                partition.sectorPerCluster = self.bootSectorStruct.sectors_per_cluster
                partition.bytesPerSector = self.bootSectorStruct.bytesPerSector
                partition.numberOfHeads = self.bootSectorStruct.number_of_head
                partition.sectorsPerTrack = self.bootSectorStruct.sectorsPerTrack
                partition.maximumRootEntryDirectories = self.bootSectorStruct.maximum_root_entry_directories
                partition.numberOfSectorsSmaller32mb = self.bootSectorStruct.number_of_sectors_smaller_32mb
                partition.sectorsNumberFat = self.bootSectorStruct.sectors_number_fat
                partition.fat32DriveVersion = self.bootSectorStruct.fat32_drive_version
                partition.sectorNumberFsInformation = self.bootSectorStruct.sector_number_fs_information
                partition.sectorsNumberPartition = self.bootSectorStruct.sectors_number_partition
                partition.sectorNumberBackupBoot = self.bootSectorStruct.sector_number_backup_boot
                partition.serialNumberPartition = self.bootSectorStruct.serial_number_partition
                partition.fatName = self.bootSectorStruct.fat_name

            elif type == "Fat16":
                self.bootSectorStruct = self.fat16BootSector.parse(cap1)
                partition.sectorPerCluster = self.bootSectorStruct.sectors_per_cluster
                partition.bytesPerSector = self.bootSectorStruct.bytesPerSector
                partition.numberOfHeads = self.bootSectorStruct.number_of_head
                partition.sectorsPerTrack = self.bootSectorStruct.sectorsPerTrack
                partition.maximumRootEntryDirectories = self.bootSectorStruct.maximum_root_entry_directories
                partition.numberOfSectorsSmaller32mb = self.bootSectorStruct.number_of_sectors_smaller_32mb
                partition.sectorsNumberFat = self.bootSectorStruct.sectors_per_fat
                partition.sectorNumberPartition = self.bootSectorStruct.sector_number_partition
                partition.serialNumberPartition = self.bootSectorStruct.serial_number_partition
                partition.fatName = self.bootSectorStruct.fat_name

            elif type == "Fat12":
                partition.sectorPerCluster = self.bootSectorStruct.sectors_per_cluster
                partition.bytesPerSector = self.bootSectorStruct.bytesPerSector
                partition.numberOfHeads = self.bootSectorStruct.number_of_head
                partition.sectorsPerTrack = self.bootSectorStruct.sectorsPerTrack
                partition.possibleRootEntryNumber = self.bootSectorStruct.possible_root_entry_number
                partition.numberOfSectorsSmaller32mb = self.bootSectorStruct.number_of_sectors_smaller_32mb
                partition.fatName = self.bootSectorStruct.fs_type
            return partition

        except Exception as inst:
            self.logger.error("Error : ", inst)

    def save_boot_sector(self, image):
        try:
            file_image = open(image, "rb")
            file_boot = open(self.path + os.path.sep + "boot sector", "w")
            file_boot.write(hexdump.hexdump(file_image.read(512), "return"))
            file_image.close()
            file_boot.close()
        except Exception as inst:
            self.logger.error("Extracting mbr failed")
        return file_boot.name

    def extract_hexa(self, boot_sector):
        try:
            h_file = open(boot_sector, "rb")
            hex_str = ""
            for line in h_file.readlines():
                hex_str += line[10:58]
            for i in hex_str.split(" "):
                self.hexaBootSector += i
            h_file.close()
        except Exception as inst:
            self.logger.error("Error Extract Hexadecimal of bootSector")

    def __str__(self):
        output = ""
        if self.type == "NTFS":
            output += "\nDisk :" + self.disk + "\nPartition name :" + self.partName + "\nType :" + self.type
            output += "\nBlock size :" + str(self.blockSize) + "\nSize :" + str(self.size) + "\nTotal sectors : " + str(
                self.totalSectors)
            output += "\nBytes per sector : " + str(self.bytesPerSector) + "\nSectors per cluster : " + str(
                self.sectorPerCluster)
            output += "\nSectors per track : " + str(
                self.sectorsPerTrack)  # + "\nReserved sectors : " + str(self.reservedSectors)
            output += "\nHidden sectors : " + str(self.hiddenSectors) + "\nNumber of heads : " + str(self.numberOfHeads)
            output += "\nLogical cluster number of MFT : " + str(
                self.mftLogicalClusterNumber) + "\nLogical cluster number of MFTMIRR : " + str(
                self.mftmirrLogicalClusterNumber)
            output += "\nClusters per file record segment : " + str(
                self.clusterPerFileRecordSegment) + "\nVolume serial number : " + str(self.volumeSerialNumber) + "\n"

        elif self.type == "Fat32":
            output += "\nDisk :" + self.disk + "\nPartition name :" + self.partName + "\nType :" + self.type
            output += "\nBlock size :" + str(self.blockSize) + "\nSize :" + str(
                self.size) + "\nBytes per sector : " + str(self.bytesPerSector)
            output += "\nSectors per cluster : " + str(self.sectorPerCluster) + "\nNumber of heads : " + str(
                self.numberOfHeads)
            output += "\nSectors per track : " + str(self.sectorsPerTrack) + "\nMaximum root entry directories :" + str(
                self.maximumRootEntryDirectories)
            output += "\nNumber of sectors in partition smaller than 32 mb : " + str(self.numberOfSectorsSmaller32mb)
            output += "\nNumber of sectors per FAT : " + str(
                self.sectorsNumberFat) + "\nVersion of FAT32 drive : " + str(self.fat32DriveVersion)
            output += "\nSector number of the FileSystem information sector : " + str(self.sectorNumberFsInformation)
            output += "\nSector number of the backupboot sector : " + str(
                self.sectorNumberBackupBoot) + "\nSerial number of partition : " + str(
                self.serialNumberPartition) + "\n"

        elif self.type == "Fat16":
            output += "\nDisk :" + self.disk + "\nPartition name :" + self.partName + "\nType :" + self.type
            output += "\nBlock size :" + str(self.blockSize) + "\nSize :" + str(
                self.size) + "\nBytes per sector : " + str(self.bytesPerSector)
            output += "\nSectors per cluster : " + str(self.sectorPerCluster) + "\nNumber of heads : " + str(
                self.numberOfHeads)
            output += "\nSectors per track : " + str(self.sectorsPerTrack) + "\nMaximum root entry directories :" + str(
                self.maximumRootEntryDirectories)
            output += "\nNumber of sectors in partition smaller than 32 mb : " + str(self.numberOfSectorsSmaller32mb)
            output += "\nNumber of sectors per FAT : " + str(
                self.sectorsNumberFat) + "\nNumber of sectors in partition : " + str(self.sectorNumberPartition)
            output += "\nSerial number of partition : " + str(self.serialNumberPartition) + "\nFat name : " + str(
                self.fatName) + "\n"

        elif self.type == "Fat12":
            output += "\nDisk :" + self.disk + "\nPartition name :" + self.partName + "\nType :" + self.type
            output += "\nBlock size :" + str(self.blockSize) + "\nSize :" + str(
                self.size) + "\nBytes per sector : " + str(self.bytesPerSector)
            output += "\nSectors per cluster : " + str(self.sectorPerCluster) + "\nNumber of heads : " + str(
                self.numberOfHeads)
            output += "\nSectors per track : " + str(self.sectorsPerTrack) + "\nPossible root entry number :" + str(
                self.possibleRootEntryNumber)
            output += "\nNumber of sectors in partition smaller than 32 mb : " + str(
                self.numberOfSectorsSmaller32mb) + "\nFat name : " + str(self.fatName) + "\n"

        return output
