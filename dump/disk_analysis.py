import os
import time
import wmi


class DiskAnalysis(object):
    def __init__(self, path):
        self.currentMachine = wmi.WMI()
        self.listDisks = []
        self.envVarList = {}
        self.listPartitions = []
        self.os = None
        self.mbrDisk = ""
        self.path = path + os.path.sep + 'results.txt'

    def save_informations(self):
        h_file = open(self.path, "w")

        h_file.write("\n\n-------------------------------" +
                     time.strftime("%d/%m/%y %H:%M", time.localtime()) + "-----------------------------------------\n")

        h_file.write("\n-------------------------------MBR----------------------------------------------------\n")
        h_file.write(str(self.mbrDisk))
        h_file.write("\n\n-------------------------------Disks--------------------------------------------------\n\n")
        for i in range(len(self.listDisks)):
            h_file.write(self.listDisks[i].__str__())
        h_file.write("\n-------------------------------Partitions---------------------------------------------\n")
        h_file.write("\nSystem Partition : " + self.envVarList["SYSTEMDRIVE"] + "\n")
        for i in range(len(self.listPartitions)):
            h_file.write(self.listPartitions[i].__str__())
        h_file.write("\n\n-------------------------------Operating System---------------------------------------\n\n")
        # file.write(self.os.__str__())
        h_file.write("\n\n-------------------------------Environment Variables-----------------------------------\n\n")
        for key, value in self.envVarList.items():
            h_file.write("\nName : " + str(key) + "\nValue :" + str(value))
        h_file.close()
