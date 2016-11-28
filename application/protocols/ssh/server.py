"""
    server.py

    SSH VPN server implementation.

    This software is licensed under the MIT license. See LICENSE for more information.
"""

import json
import struct
import socket

import tundevice
import vpnadapter

class Server(object):
    """
        Class representing an SSH protocol VPN server.
    """

    config = None
    """
        SSH VPN server configuration data.
    """

    comm_socket = None
    """
        The comm socket.
    """

    comm_socket_buffers = None
    """
        A mapping of comm sockets to their current buffers.
    """

    routing_socket = None
    """
        The routing socket.
    """

    action_mapping = None
    """
        A mapping of action names to their implementations.
    """

    application = None
    """
        The main application object.
    """

    routing_socket_mapping = None
    """
        A mapping of virtual IP addresses to their routing sockets.
    """

    def __init__(self, protocol, application, config):
        self.config = config
        self.protocol = protocol
        self.application = application

        self.connected_clients = []
        self.comm_socket_buffers = {}
        self.routing_socket_mapping = {self.protocol.server_address: None}
        self.action_mapping = {"requestIP": self.action_requestIP}

        self.comm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.comm_socket.bind(("127.0.0.1", self.config["remoteCommPort"]))
        self.comm_socket.setblocking(0)
        self.comm_socket.listen(1)

        self.routing_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.routing_socket.bind(("127.0.0.1", self.config["remoteRoutingPort"]))
        self.routing_socket.setblocking(0)
        self.routing_socket.listen(1)

        self.device = vpnadapter.VPNAdapter(protocol=self, address=self.protocol.server_address, name="vpnServer")
        print("** Initialized VPN server.")

    def __del__(self):
        if self.comm_socket is not None:
            self.comm_socket.close()

        if self.routing_socket is not None:
            self.routing_socket.close()

    def handle_frame(self, frame, information):
        """
            Process a frame from the server TUN device.
        """
        print(information)
        self.route_frame(frame, information)

    def action_requestIP(self, client_id, payload):
        client_data = self.connected_clients[client_id]

        if payload is None or "address" not in payload or payload["address"] is None:
            if len(self.protocol.addresses) == 0:
                return {"success": False, "reason": "No addresses left."}

            address = self.protocol.addresses.pop()
            print("** Auto Assigning IP address %s to client %u." % (address, client_id))
            self.routing_socket_mapping[address] = client_data["routing"]["socket"]
            return {"success": True, "address": address}
        else:
            address = payload["address"]
            if address in self.routing_socket_mapping:
                return {"success": False, "reason": "Address in use."}
            elif address not in self.protocol.addresses:
                return {"success": False, "reason": "Address not available."}

            print("** Assigning requested IP address %s to client %u." % (address, client_id))
            self.routing_socket_mapping[address] = client_data["routing"]["socket"]
            self.addresses.protocol.remove(address)

            return {"success": True, "address": address}

    def handle_messages(self, client_id, messages):
        client_data = self.connected_clients[client_id]

        for message in messages:
            action = message["action"]

            if action in self.action_mapping:
                payload = None
                if "payload" in message:
                    payload = message["payload"]

                # Build the server response
                result = self.action_mapping[action](client_id, payload)

                dispatched = {"action": "response", "payload": result}
                if "token" in message:
                    dispatched["token"] = message["token"]

                client_data["comm"]["socket"].send(json.dumps(dispatched) + "\n")
            else:
                print("!! Unknown action '%s' from client %!" % (action, client_id))

    def send(self, action, payload, socket):
        """
            Sends a comm payload to the connected socket.
        """
        dispatched = {"action": action, "payload": payload}
        socket.send(json.dumps(dispatched) + "\n")

    def route_frame(self, frame, information):
        # Route to the recipient
        destination = information["destination"]

        if destination in self.routing_socket_mapping:
            routing_socket = self.routing_socket_mapping[destination]

            if routing_socket is None:
                self.device.write_data(frame)
                print("!!! Routing Local Socket")
            else:
                print("!!! Routing to remote %s" % destination)
                routing_socket.send(frame)
        else:
            print("!!! Unknown recipient: %s" % destination)

    def update(self):
        self.device.update()

        # Process the comm socket first
        try:
            connection, address = self.comm_socket.accept()
            connection.setblocking(0)

            address, port = address
            next_id = len(self.connected_clients)
            print("** Accepted connection on comm socket from %s:%u. ID %u." % (address, port, next_id))

            socket_data = {
                "comm": {"socket": connection, "buffer": ""},
                "routing": {"socket": None, "buffer": ""}
            }

            self.connected_clients.append(socket_data)
            self.comm_socket_buffers[connection] = None

            # Send the socket their ID
            connection.send(json.dumps({"action": "setID", "payload": {"value": next_id}}) + "\n")
        except socket.error as e:
            pass

        # Then the routing socket
        try:
            connection, address = self.routing_socket.accept()
            address, port = address

            # FIXME: Instead of blocking, we will want to queue up this connection
            ident_bytes = connection.recv(4)
            client_id = struct.unpack("<I", ident_bytes)[0]

            print("** Accepted connection on routing socket from %s:%u. ID %u." % (address, port, client_id))

            if client_id < 0 or client_id >= len(self.connected_clients):
                print("!! Received invalid identifier (%u) on routing socket, dropping." % client_id)
                connection.close()
            else:
                connection.setblocking(0)

                connection_data = self.connected_clients[client_id]
                if connection_data["routing"]["socket"] is not None:
                    print("!! Received an identifier that was already in use (%u), dropping." % client_id)
                    connection.close()
                else:
                    connection_data["routing"]["socket"] = connection
        except socket.error as e:
            pass

        # Process any ongoing sockets
        for client_id, info in enumerate(self.connected_clients):
            comm_sock = info["comm"]["socket"]
            routing_sock = info["routing"]["socket"]

            if routing_sock is not None:
                try:
                    # First we read the frame header
                    header_data = routing_sock.recv(24)
                    header_info = tundevice.get_frame_info(header_data)

                    # Read the frame data
                    remaining_bytes = header_info["length"] - 24
                    frame_data = routing_sock.recv(remaining_bytes)

                    if len(frame_data) != remaining_bytes:
                        print("!!! Didn't read enough bytes")

                    self.route_frame(header_data + frame_data, header_info)
                except socket.error as e:
                    pass

            if comm_sock is not None:
                try:
                    data = comm_sock.recv(1500)

                    if data != "":
                        messages = data.split("\n")

                        if len(messages) == 1:
                            self.comm_socket_buffers[comm_sock] += messages[0]
                        else:
                            last_segment = messages.pop()

                            if self.comm_socket_buffers[comm_sock] is not None:
                                messages[0] += self.comm_socket_buffers[comm_sock]

                            if last_segment != "":
                                self.comm_socket_buffers[comm_sock] = last_segment
                            else:
                                self.comm_socket_buffers[comm_sock] = None

                            messages = [json.loads(message) for message in messages]
                            self.handle_messages(client_id, messages)
                except socket.error as e:
                    pass
