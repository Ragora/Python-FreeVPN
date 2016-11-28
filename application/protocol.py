"""
	protocol.py

	Base protocol implementation class. All protocols to be made available for
	the VPN should derive from this protocol class.

	This software is licensed under the MIT license. See LICENSE for more information.
"""

import tundevice

class Protocol(object):
    """
        Base protocol class. We use this class to enumerate available protocols by
        using __subclasses__. All classes deriving from this must implement some
        method of establishing a connection to the VPN server and routing raw IP
        frames over the network as well as providing a means of communicating with the
        VPN server about VPN network information.
    """

    def __init__(self, config, application, addresses, server):
        """
            :parameters:
                config - The protocol specific configuration data.
        """

        self.config = config
        self.addresses = addresses
        self.server_address = server
        self.application = application

    def server_init(self):
        """
            Should be overwritten to provide server sided initialization.
        """

    def client_init(self):
        """
            Should be overwritten to provide client sided initialization.
        """

    def connect(self):
        """
            Attempt to establish a connection with the VPN server.
        """

    def get_connected_clients(self):
        """
            Returns a list of connected VPN clients.

            :return:
                A list of VPN clients described in any useful protocol specific manner.
        """

        return None

    def handle_frame(self, frame, information):
	    """
            Handles a frame from the TUN device.
        """

    def client_update(self):
        pass

    def server_update(self):
        pass
