"""
    __init__.py

    Main import script for the SSH VPN protocol.

    This software is licensed under the MIT license. See LICENSE for more information.
"""

from client import Client
from server import Server

import time
import socket
import subprocess

import vpnadapter
import protocol

import client
import server

class SSH(protocol.Protocol):
    connected_clients = None
    """
        A list of connected client sockets.
    """

    routing_socket_mapping = None
    """
        A dictionary mapping client routing sockets to VPN IP addresses.
    """

    comm_forwarding = None
    """
        The communication forwarding.
    """

    routing_forwarding = None
    """
        The routing forwarding.
    """

    connected_sockets = None
    """
        Data buffers on a per socket basis.
    """

    socket_id_mapping = None

    routing_socket_buffers = None
    """
        Data buffers for routing sockets.
    """

    def server_init(self):
        """
            For the SSH server end, we initialize two ports: 11595 for the VPN communication and 1337 for VPN
            network traffic.
        """

        self.server = server.Server(config=self.config, application=self.application, protocol=self)

    def client_init(self):
        """
            Initializes the clientside programming.
        """

        self.client = client.Client(config=self.config, application=self.application, protocol=self)

        time.sleep(5)
        self.connect()

    def client_deinit(self):
        """
            Deinitializes the client programming.
        """

        del self.client

    def server_deinit(self):
        """
            Deinitialized the server programming.
        """

        del self.server

    def client_update(self):
        """
            Processes both the routing and comm sockets.
        """

        self.client.update()

    def server_update(self):
        """
            Processes both the routing and the comm sockets.
        """

        self.server.update()

        def get_connected_clients(self):
            result = []

            for info in self.connected_clients:
                vpn_address = "<Unassigned>"

                if info["socket"] in self.socket_mapping:
                    vpn_address = self.socket_mapping[info["socket"]]

                    result.append("%s - From %s:%u" % (vpn_address, info["address"], info["port"]))
                    return result
