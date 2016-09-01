from __future__ import unicode_literals
from statemachine import _Statemachine
from settings import NETWORK_ADAPTATER
import utils
import subprocess


class WindowsXPStateMachine(_Statemachine):
    def __init__(self, params):
        _Statemachine.__init__(self, params)

    def _list_share(self):
        return super(WindowsXPStateMachine, self)._list_share()

    def _list_running(self):
        return super(WindowsXPStateMachine, self)._list_running()

    def _list_drives(self):
        return super(WindowsXPStateMachine, self)._list_drives()

    def _list_network_drives(self):
        return super(WindowsXPStateMachine, self)._list_network_drives()

    def _list_sessions(self):
        return super(WindowsXPStateMachine, self)._list_sessions()

    def _list_scheduled_jobs(self):
        return super(WindowsXPStateMachine, self)._list_scheduled_jobs()

    def _list_network_adapters(self):
        self.logger.info('Health : Listing scheduled jobs')
        net = self.wmi.Win32_NetworkAdapter()
        for n in net:
            netcard = utils.decode_output_cmd(n.Caption)
            IPv4 = ''
            IPv6 = ''
            DHCP_server = ''
            DNS_server = ''
            adapter_type = ''
            nbtstat_value = ''
            if n.AdapterTypeID:
                adapter_type = NETWORK_ADAPTATER[int(n.AdapterTypeID)]
            netconnectionstatus = n.NetConnectionStatus
            mac_address = n.MACAddress
            description = n.Description
            physical_adapter = ''
            product_name = ''
            database_path = ''
            speed = ''
            if n.Speed:
                speed = n.Speed
            if netconnectionstatus:
                nic = self.wmi.Win32_NetworkAdapterConfiguration(MACAddress=mac_address)
                for nc in nic:
                    if nc:
                        if nc.DatabasePath:
                            database_path = nc.DatabasePath
                            database_path = database_path.replace('\n', '')
                        if nc.IPAddress:
                            IPv4 = nc.IPAddress[0]
                            if len(nc.IPaddress) > 1:
                                IPv6 = nc.IPAddress[1]
                            nbtstat = 'nbtstat -A ' + IPv4
                            p = subprocess.Popen(nbtstat, shell=True, stdout=subprocess.PIPE)
                            output, errors = p.communicate()
                            output = utils.decode_output_cmd(output)
                            nbtstat_value = output.split('\r\n')
                            nbtstat_value = ''.join([n.replace('\n', '') for n in nbtstat_value])
                        if nc.DNSServerSearchOrder:
                            DNS_server = nc.DNSServerSearchOrder[0]
                            if nc.DHCPEnabled:
                                DHCP_server = nc.DHCPServer
            yield netcard, adapter_type, description, mac_address, product_name, physical_adapter, product_name, speed, IPv4, IPv6, DHCP_server, DNS_server, database_path, nbtstat_value


    def _list_kb(self):
        return super(WindowsXPStateMachine, self)._list_kb()

    def _list_arp_table(self):
        return super(WindowsXPStateMachine, self)._list_arp_table()

    def _list_route_table(self):
        return super(WindowsXPStateMachine, self)._list_route_table()

    def _list_sockets_network(self):
        return super(WindowsXPStateMachine, self)._list_sockets_network()

    def _list_sockets_services(self):
        return super(WindowsXPStateMachine, self)._list_services()

    def csv_list_drives(self):
        super(WindowsXPStateMachine, self)._csv_list_drives(self._list_drives())

    def csv_list_network_drives(self):
        super(WindowsXPStateMachine, self)._csv_list_network_drives(self._list_network_drives())

    def csv_list_share(self):
        super(WindowsXPStateMachine, self)._csv_list_share(self._list_share())

    def csv_list_running_proccess(self):
        super(WindowsXPStateMachine, self)._csv_list_running_process(self._list_running())

    def csv_hash_running_proccess(self):
        super(Windows10StateMachine, self)._csv_hash_running_process(self._list_running())

    def csv_list_sessions(self):
        super(WindowsXPStateMachine, self)._csv_list_sessions(self._list_sessions())


    def csv_list_arp_table(self):
        super(WindowsXPStateMachine, self)._csv_list_arp_table(self._list_arp_table())

    def csv_list_route_table(self):
        super(WindowsXPStateMachine, self)._csv_list_route_table(self._list_route_table())

    def csv_list_sockets_networks(self):
        super(WindowsXPStateMachine, self)._csv_list_sockets_network(self._list_sockets_network())

    def csv_list_services(self):
        super(WindowsXPStateMachine, self)._csv_list_services(self._list_services())

    def csv_list_kb(self):
        super(WindowsXPStateMachine, self)._csv_list_kb(self._list_kb())


    def _list_arp_table(self):
        return super(WindowsXPStateMachine, self)._list_arp_table()

    def _list_route_table(self):
        return super(WindowsXPStateMachine, self)._list_route_table()

    def _list_sockets_network(self):
        return super(WindowsXPStateMachine, self)._list_sockets_network()

    def _list_sockets_services(self):
        return super(WindowsXPStateMachine, self)._list_services()

    def json_list_drives(self):
        super(WindowsXPStateMachine, self)._json_list_drives(self._list_drives())

    def json_list_network_drives(self):
        super(WindowsXPStateMachine, self)._json_list_network_drives(self._list_network_drives())

    def json_list_share(self):
        super(WindowsXPStateMachine, self)._json_list_share(self._list_share())

    def json_list_running_proccess(self):
        super(WindowsXPStateMachine, self)._json_list_running_process(self._list_running())

    def json_hash_running_proccess(self):
        super(Windows10StateMachine, self)._json_hash_running_process(self._list_running())

    def json_list_sessions(self):
        super(WindowsXPStateMachine, self)._json_list_sessions(self._list_sessions())


    def json_list_arp_table(self):
        super(WindowsXPStateMachine, self)._json_list_arp_table(self._list_arp_table())

    def json_list_route_table(self):
        super(WindowsXPStateMachine, self)._json_list_route_table(self._list_route_table())

    def json_list_sockets_networks(self):
        super(WindowsXPStateMachine, self)._json_list_sockets_network(self._list_sockets_network())

    def json_list_services(self):
        super(WindowsXPStateMachine, self)._json_list_services(self._list_services())

    def json_list_kb(self):
        super(WindowsXPStateMachine, self)._json_list_kb(self._list_kb())