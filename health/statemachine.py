# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import subprocess
import traceback

import psutil
from settings import NETWORK_ADAPTATER
from utils.utils import write_to_output, get_csv_writer, write_to_csv, get_terminal_decoded_string, \
    record_sha256_logs
import win32process
import wmi


class _Statemachine(object):
    def __init__(self, params):
        self.params = params
        self.wmi = wmi.WMI()
        self.computer_name = params['computer_name']
        self.output_dir = params['output_dir'] + '\\' + self.computer_name
        self.systemroot = params['system_root']
        self.logger = params['logger']

    def _list_network_drives(self):
        for disk in self.wmi.Win32_LogicalDisk(DriveType=4):
            yield disk.Caption, disk.FileSystem, disk.ProviderName

    def _list_drives(self):
        for physical_disk in self.wmi.Win32_DiskDrive():
            for partition in physical_disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    yield physical_disk.Caption, partition.Caption, logical_disk.Caption, logical_disk.FileSystem

    def _list_share(self):
        for share in self.wmi.Win32_Share():
            yield share.Name, share.Path

    def _list_running(self):
        for process in self.wmi.Win32_Process():
            yield [process.ProcessId, process.Name, process.CommandLine, process.ExecutablePath]

    def _list_sessions(self):
        for session in self.wmi.Win32_Session():
            yield session.LogonId, session.AuthenticationPackage, session.StartTime, session.LogonType

    def _list_scheduled_jobs(self):
        path_task = self.system_root + '\\system32\\Tasks\\'
        for l in os.listdir(path_task):
            if os.path.isfile(path_task + l):
                yield path_task + l

    def _list_network_adapters(self):
        net = self.wmi.Win32_NetworkAdapter()
        for n in net:
            netcard = n.Caption
            IPv4 = ''
            IPv6 = ''
            DHCP_server = ''
            DNS_server = ''
            adapter_type = ''
            nbtstat_value = ''
            if n.AdapterTypeID:
                adapter_type = NETWORK_ADAPTATER[int(n.AdapterTypeID)]
            net_enabled = n.NetEnabled
            mac_address = n.MACAddress
            description = n.Description
            physical_adapter = unicode(n.PhysicalAdapter)
            product_name = n.ProductName
            speed = n.Speed
            database_path = ''
            if net_enabled:
                nic = self.wmi.Win32_NetworkAdapterConfiguration(MACAddress=mac_address)
                for nc in nic:
                    database_path = nc.DatabasePath
                    if nc.IPAddress:
                        try:
                            IPv4 = nc.IPAddress[0]
                            IPv6 = nc.IPAddress[1]
                        except IndexError as e:
                            self.logger.error('Error to catch IP Address %s ' % str(nc.IPAddress))
                    if IPv4:
                        nbtstat = 'nbtstat -A ' + IPv4
                        p = subprocess.Popen(nbtstat, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        output, errors = p.communicate()
                        # output=utils.decode_output_cmd(output)
                        output = get_terminal_decoded_string(output)
                        nbtstat_value = output.split('\r\n')
                        nbtstat_value = ' '.join([n.replace('\n', '') for n in nbtstat_value])
                    if nc.DNSServerSearchOrder:
                        DNS_server = nc.DNSServerSearchOrder[0]
                    if nc.DHCPEnabled:
                        if nc.DHCPServer:
                            DHCP_server = nc.DHCPServer
            yield netcard, adapter_type, description, mac_address, product_name, physical_adapter, product_name, speed, \
                  IPv4, IPv6, DHCP_server, DNS_server, database_path, nbtstat_value

    def _list_arp_table(self):
        cmd = "arp -a"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errors = p.communicate()
        output = get_terminal_decoded_string(output)
        item = output.split("\n")
        for i in item:
            yield i

    def _list_route_table(self):
        route_table = self.wmi.Win32_IP4RouteTable()
        for r in route_table:
            yield r.Name, r.Mask

    def _list_sockets_network(self):
        for pid in win32process.EnumProcesses():
            try:
                p = psutil.Process(pid)
                local_addr = ''
                local_port = ''
                remote_addr = ''
                remote_port = ''
                for connection in p.connections():
                    if len(connection.laddr) > 0:
                        local_addr = connection.laddr[0]
                        local_port = connection.laddr[1]
                    if len(connection.raddr) > 0:
                        remote_addr = connection.raddr[0]
                        remote_port = connection.raddr[1]
                    yield pid, p.name(), local_addr, local_port, remote_addr, remote_port, connection.status
            except psutil.AccessDenied:
                self.logger.warning(traceback.format_exc())

    def _list_services(self):
        services = self.wmi.Win32_Service()
        for s in services:
            yield s.Name, s.Caption, s.ProcessId, s.PathName, s.ServiceType, s.Status, s.State, s.StartMode

    def _list_kb(self):
        for kb in self.wmi.Win32_QuickFixEngineering():
            yield kb.Caption, kb.CSName, kb.FixComments, kb.HotFixID, kb.InstallDate, kb.InstalledOn, kb.Name, \
                  kb.ServicePackInEffect, kb.Status

    def _csv_list_running_process(self, list_running):
        self.logger.info("Health : Listing running processes")
        with open(self.output_dir + '_processes.csv', 'ab') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "PID", "PROCESS_NAME", "COMMAND", "EXEC_PATH"], csv_writer)
            for p in list_running:
                pid = p[0]
                name = p[1]
                cmd = p[2]
                exe_path = p[3]
                write_to_csv(
                    [self.computer_name, 'processes', unicode(pid), name, unicode(cmd), unicode(exe_path)],
                    csv_writer)
        record_sha256_logs(self.output_dir + '_processes.csv', self.output_dir + '_sha256.log')

    def _csv_list_share(self, share):
        self.logger.info("Health : Listing shares")
        with open(self.output_dir + '_shares.csv', 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "SHARE_NAME", "SHARE_PATH"], csv_writer)
            for name, path in share:
                write_to_csv([self.computer_name, 'shares', name, path], csv_writer)
        record_sha256_logs(self.output_dir + '_shares.csv', self.output_dir + '_sha256.log')

    def _csv_list_drives(self, drives):
        self.logger.info("Health : Listing drives")
        with open(self.output_dir + '_list_drives.csv', 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "FAB", "PARTITIONS", "DISK", "FILESYSTEM"], csv_writer)
            for phCapt, partCapt, logicalCapt, fs in drives:
                write_to_csv([self.computer_name, 'list_drives', phCapt, partCapt, logicalCapt, fs], csv_writer)
        record_sha256_logs(self.output_dir + '_list_drives.csv', self.output_dir + '_sha256.log')

    def _csv_list_network_drives(self, drives):
        self.logger.info("Health : Listing network drives")
        with open(self.output_dir + '_list_networks_drives.csv', 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "DISK", "FILESYSTEM", "PARTITION_NAME"], csv_writer)
            for diskCapt, diskFs, diskPName in drives:
                write_to_csv([self.computer_name, 'list_networks_drives', diskCapt, diskFs, diskPName], csv_writer)
        record_sha256_logs(self.output_dir + '_list_networks_drives.csv', self.output_dir + '_sha256.log')

    def _csv_list_sessions(self, sessions):
        self.logger.info('Health : Listing sessions')
        with open(self.output_dir + '_sessions.csv', 'ab') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "LOGON_ID", "AUTH_PACKAGE", "START_TIME", "LOGON_TYPE"], csv_writer)
            for logonID, authenticationPackage, startime, logontype in sessions:
                write_to_csv([self.computer_name, 'sessions', unicode(logonID),
                              authenticationPackage, unicode(startime.split('.')[0]), unicode(logontype)], csv_writer)
        record_sha256_logs(self.output_dir + '_sessions.csv', self.output_dir + '_sha256.log')

    def _csv_list_scheduled_jobs(self):
        self.logger.info('Health : Listing scheduled jobs')
        file_tasks = self.output_dir + '_tasks.csv'
        with open(file_tasks, 'wb') as tasks_logs:
            proc = subprocess.Popen(["schtasks.exe", '/query', '/fo', 'CSV'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            res = proc.communicate()
            res = get_terminal_decoded_string(res[0])
            # clean and write the command output
            write_to_output('"TASK_NAME","NEXT_SCHEDULE","STATUS"\r\n', tasks_logs, self.logger)
            column_names = None
            for line in res.split('\r\n'):
                if line == "":
                    continue
                if line[0] != '"':
                    continue
                if not column_names:
                    column_names = line
                    continue
                elif column_names == line:
                    continue
                write_to_output(line+"\r\n", tasks_logs, self.logger)

        self.logger.info('Health : Listing scheduled jobs')
        with open(file_tasks, "r") as fr, open(self.output_dir + "_scheduled_jobs.csv", 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "JOB_NAME", "TIME", "STATE"], csv_writer)
            for l in fr.readlines():
                l = l.decode('utf8')
                if l.find('\\') > 0:
                    l = l[:-1].replace('"', '')  # remove the end of line
                    arr_write = [self.computer_name, 'scheduled_jobs'] + l.split(',')
                    write_to_csv(arr_write, csv_writer)
        self.logger.info('Health : Listing scheduled jobs')
        record_sha256_logs(self.output_dir + '_scheduled_jobs.csv', self.output_dir + '_sha256.log')

    def _csv_list_network_adapters(self, ncs):
        self.logger.info('Health : Listing network adapters')
        with open(self.output_dir + "_networks_cards.csv", 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "NETWORK_CARD", "ADAPTER_TYPE", "DESCRIPTION", "MAC_ADDR",
                          "PRODUCT_NAME", "PHYSICAL_ADAPTER", "SPEED", "IPv4", "IPv6", "DHCP_SERVER", "DNS_SERVER",
                          "DATABASE_PATH", "NBTSTAT_VALUE"], csv_writer)
            for netcard, adapter_type, description, mac_address, product_name, physical_adapter, product_name, speed, \
                IPv4, IPv6, DHCP_server, DNS_server, database_path, nbtstat_value in ncs:
                if netcard is None:
                    netcard = ' '
                if adapter_type is None:
                    adapter_type = ''
                if description is None:
                    description = ' '
                if mac_address is None:
                    mac_address = ' '
                if physical_adapter is None:
                    physical_adapter = ' '
                if product_name is None:
                    product_name
                if speed is None:
                    speed = ' '
                if IPv4 is None:
                    IPv4 = ' '
                if IPv6 is None:
                    IPv6 = ''
                if DHCP_server is None:
                    DHCP_server = ' '
                if DNS_server is None:
                    DNS_server = ' '
                if database_path is None:
                    database_path = ' '
                if nbtstat_value is None:
                    nbtstat_value = ' '
                try:
                    write_to_csv([self.computer_name,
                                  'networks_cards', netcard, adapter_type,
                                  description, mac_address, product_name,
                                  physical_adapter, speed, IPv4,
                                  IPv6, DHCP_server, DNS_server,
                                  database_path, nbtstat_value], csv_writer)
                except IOError:
                    self.logger.error(traceback.format_exc())
        record_sha256_logs(self.output_dir + '_networks_cards.csv', self.output_dir + '_sha256.log')

    def _csv_list_arp_table(self, arp):
        self.logger.info('Health : Listing ARP tables')
        with open(self.output_dir + "_arp_table.csv", 'wb') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "IP", "MAC_ADDR", "STATUS"], csv_writer)
            for entry in arp:
                entry.replace('\xff', '')
                tokens = entry.split()
                entry_to_write = ''
                if len(tokens) == 3:
                    entry_to_write = '"' + self.computer_name + '"|"arp_table"|"' + '"|"'.join(tokens) + '"\n'
                if entry_to_write.find('\.') != 1 and len(entry_to_write) > 0:
                    arr_to_write = [self.computer_name, 'arp_table'] + tokens
                    write_to_csv(arr_to_write, csv_writer)
        record_sha256_logs(self.output_dir + '_arp_table.csv', self.output_dir + '_sha256.log')

    def _csv_list_route_table(self, routes):
        self.logger.info('Health : Listing routes tables')
        with open(self.output_dir + "_routes_tables.csv", 'ab') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "NAME", "MASK"], csv_writer)
            for ip, mask in routes:
                write_to_csv([self.computer_name, 'routes_tables', unicode(ip), unicode(mask)], csv_writer)
        record_sha256_logs(self.output_dir + '_routes_tables.csv', self.output_dir + '_sha256.log')

    def _csv_list_sockets_network(self, connections):
        self.logger.info('Health : Listing sockets networks')
        with open(self.output_dir + '_sockets.csv', 'ab') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "PID", "PROCESS_NAME", "LOCAL_ADDR", "SOURCE_PORT", "REMOTE_ADDR",
                          "REMOTE_PORT", "STATUS"], csv_writer)
            for pid, name, local_address, source_port, remote_addr, remote_port, status in connections:
                write_to_csv([self.computer_name, 'sockets', unicode(pid),
                              unicode(name), unicode(local_address), unicode(source_port),
                              unicode(remote_addr), unicode(remote_port), unicode(status)], csv_writer)
        record_sha256_logs(self.output_dir + '_sockets.csv', self.output_dir + '_sha256.log')

    def _csv_list_services(self, services):
        self.logger.info('Health : Listing services')
        with open(self.output_dir + '_services.csv', 'ab') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "CAPTION", "PID", "SERVICE_TYPE", "PATH_NAME", "STATUS", "STATE",
                          "START_MODE"], csv_writer)
            for name, caption, processId, pathName, serviceType, status, state, startMode in services:
                write_to_csv([self.computer_name, 'services', caption,
                              unicode(processId), serviceType, pathName,
                              unicode(status), state, startMode], csv_writer)
        record_sha256_logs(self.output_dir + '_services.csv', self.output_dir + '_sha256.log')

    def _csv_list_kb(self, kbs):
        self.logger.info('Health : Listing KB installed on computer')
        with open(self.output_dir + '_kb.csv', 'ab') as fw:
            csv_writer = get_csv_writer(fw)
            write_to_csv(["COMPUTER_NAME", "TYPE", "CAPTION", "CS_NAME", "FIX_COMMENTS", "HOTFIX_ID", "INSTALL_DATE",
                          "INSTALLED_ON", "NAME", "SERVICE_PACK", "STATUS"], csv_writer)
            for Caption, CSName, FixComments, HotFixID, InstallDate, InstalledOn, Name, ServicePackInEffect, Status in kbs:
                write_to_csv(
                    [self.computer_name, 'kb', Caption, CSName, FixComments, HotFixID, InstallDate, InstalledOn, Name,
                     ServicePackInEffect, Status], csv_writer)
