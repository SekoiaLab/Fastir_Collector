# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from statemachine import _Statemachine


class Windows8StateMachine(_Statemachine):
    def __init__(self, params):
        _Statemachine.__init__(self, params)

    def _list_share(self):
        return super(Windows8StateMachine, self)._list_share()

    def _list_running(self):
        return super(Windows8StateMachine, self)._list_running()

    def _list_drives(self):
        return super(Windows8StateMachine, self)._list_drives()

    def _list_network_drives(self):
        return super(Windows8StateMachine, self)._list_network_drives()

    def _list_sessions(self):
        return super(Windows8StateMachine, self)._list_sessions()

    def _list_scheduled_jobs(self):
        return super(Windows8StateMachine, self)._list_scheduled_jobs()

    def _list_network_adapters(self):
        return super(Windows8StateMachine, self)._list_network_adapters()

    def _list_arp_table(self):
        return super(Windows8StateMachine, self)._list_arp_table()

    def _list_route_table(self):
        return super(Windows8StateMachine, self)._list_route_table()

    def _list_sockets_network(self):
        return super(Windows8StateMachine, self)._list_sockets_network()

    def _list_sockets_services(self):
        return super(Windows8StateMachine, self)._list_services()

    def _list_kb(self):
        return super(Windows8StateMachine, self)._list_kb()

    def csv_list_drives(self):
        super(Windows8StateMachine, self)._csv_list_drives(self._list_drives())

    def csv_list_network_drives(self):
        super(Windows8StateMachine, self)._csv_list_network_drives(self._list_network_drives())

    def csv_list_share(self):
        super(Windows8StateMachine, self)._csv_list_share(self._list_share())

    def csv_list_running_proccess(self):
        super(Windows8StateMachine, self)._csv_list_running_process(self._list_running())

    def csv_list_sessions(self):
        super(Windows8StateMachine, self)._csv_list_sessions(self._list_sessions())

    def csv_list_arp_table(self):
        super(Windows8StateMachine, self)._csv_list_arp_table(self._list_arp_table())

    def csv_list_route_table(self):
        super(Windows8StateMachine, self)._csv_list_route_table(self._list_route_table())

    def csv_list_sockets_networks(self):
        super(Windows8StateMachine, self)._csv_list_sockets_network(self._list_sockets_network())

    def csv_list_services(self):
        super(Windows8StateMachine, self)._csv_list_services(self._list_services())

    def csv_list_kb(self):
        super(Windows8StateMachine, self)._csv_list_kb(self._list_kb())
