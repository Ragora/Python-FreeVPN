"""
    client.py

    SSH VPN client implementation.

    This software is licensed under the MIT license. See LICENSE for more information.
"""

import json
import time
import struct
import socket
import subprocess

import vpnadapter

class Client(object):
    comm_connection = None
    """
        The communications connection to the VPN server.
    """

    comm_buffer = None
    """
        Buffer for the communication socket.
    """

    routing_connection = None

    config = None
    """
        The configuration for this SSH protocol.
    """

    actions = None
    """
        Action mapping.
    """

    client_id = None
    """
        The server assigned client ID.
    """

    token_callbacks = None
    """
        Callbacks for API calls.
    """

    def __init__(self, config, application, protocol):
        self.config = config
        self.protocol = protocol
        self.application = application
        self.token_callbacks = {}

        self.action_mapping = {
            "setID": self.action_setID,
            "ping": self.action_ping
        }

        print("Attempting authentication with server ...")

        # Attempt to establish a connection to the routing & API processes
        command = "sudo -u {localUser} --set-home ssh {remoteUser}@{host} -f -N -L{localCommPort}:localhost:{remoteCommPort} -o PasswordAuthentication=no -o StrictHostKeyChecking=no -p {port} 2> /dev/null"
        command = command.format(**self.config)
        self.comm_forwarding = subprocess.Popen(command, shell=True)

        command = "sudo -u {localUser} --set-home ssh {remoteUser}@{host} -f -N -L{localRoutingPort}:localhost:{remoteRoutingPort} -o PasswordAuthentication=no -o StrictHostKeyChecking=no -p {port} 2> /dev/null"
        command = command.format(**self.config)
        self.routing_forwarding = subprocess.Popen(command, shell=True)

        time.sleep(5)
        print("Establishing connection with VPN server communication process ...")

        self.comm_buffer = ""
        self.comm_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.comm_connection.connect(("127.0.0.1", self.config["localCommPort"]))
        self.comm_connection.setblocking(0)

        print("** Established comm connection to VPN.")
        print("** Waiting for ID.")

        if self.receive(max_seconds=5, wait_period=1) is False:
            print("!! Failed to get ID!")
        else:
            self.routing_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.routing_connection.connect(("127.0.0.1", self.config["localRoutingPort"]))
            self.routing_connection.send(struct.pack("<I", self.client_id))
            self.routing_connection.setblocking(0)

            print("** Established routing connection to VPN.")

            # Once we've established a routing connection, we will want to obtain an IP address
            print("** Obtaining IP address.")
            self.send("requestIP", {"address": None}, self.handle_ip_assignment)

            if self.receive(max_seconds=5, wait_period=1) is False:
                print("!! Failed to get address!")

    def __del__(self):
        self.comm_forwarding.kill()
        self.routing_forwarding.kill()

    def handle_ip_assignment(self, payload):
        address = payload["address"]
        print("** Received IP Address from VPN server: %s" % address)

        self.address = address
        self.device = vpnadapter.VPNAdapter(protocol=self, name="vpnClient", address=address)

    def handle_messages(self, messages):
        for message in messages:
            action = message["action"]

            # If this is a call response, lookup the token
            if action == "response":
                token = message["token"]

                if token in self.token_callbacks:
                    self.token_callbacks[token](message["payload"])
                    del self.token_callbacks[token]
                continue

            if action in self.action_mapping:
                payload = None
                if "payload" in message:
                    payload = message["payload"]

                self.action_mapping[action](payload)
            else:
                print("!! Received unknown action '%s'!" % action)

    def action_setID(self, payload):
        """
            Implementation for the setID action.
        """

        self.client_id = payload["value"]
        print("** Server assigned ID %u" % payload["value"])

    def action_ping(self, payload):
        self.send("pong", payload["value"])

    def send(self, action, payload, callback=None):
        with open("/dev/urandom", "r") as handle:
            token = handle.read(8).encode("base64")

        dispatched = {"action": action, "token": token, "payload": payload}
        self.comm_connection.send(json.dumps(dispatched) + "\n")

        if callback is not None:
            self.token_callbacks[token] = callback

    def handle_frame(self, frame, information):
        self.routing_connection.send(frame)

    def receive(self, max_seconds=None, wait_period=1):
        """
            Blocks until at least one server message is received. Returns all messages
            into a list.
        """

        results = []
        waited_seconds = 0
        while max_seconds is None or (wait_period != 0 and waited_seconds < max_seconds):
            try:
                data = self.comm_connection.recv(1500)

                if data != "":
                    messages = data.split("\n")

                    if len(messages) == 1:
                        self.comm_buffer += messages[0]
                    else:
                        last_segment = messages.pop()

                        if self.comm_buffer is not None:
                            messages[0] += self.comm_buffer

                        if last_segment != "":
                            self.comm_buffer = last_segment
                        else:
                            self.comm_buffer = None

                        results = [json.loads(message) for message in messages]
                        break
            except socket.error as e:
                pass

            if wait_period != 0:
                time.sleep(wait_period)
                waited_seconds += wait_period

        self.handle_messages(results)
        return len(results) != 0

    def update(self):
        self.device.update()

        try:
            data = self.routing_connection.recv(150)
            if data != "":
                self.device.write_data(data)
        except socket.error as e:
            pass
