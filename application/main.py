#!/usr/bin/python
"""
    main.py

    Main application script.

    This software is licensed under the MIT license. See LICENSE for more information.
"""

import json
import argparse

import iptools

import protocol
import protocols

class Application(object):
    """
        Main application object.
    """

    def main(self):
        """
            Main entry point.
        """

        parser = argparse.ArgumentParser(description="Initialize a VPN server.")

        # Build the available protocol list
        protocol_list = protocol.Protocol.__subclasses__()
        protocols = {}
        for proto in protocol_list:
            protocols[proto.__name__] = proto

        choices = [proto for proto in protocols.keys()]
        parser.add_argument("protocol", help="The protocol to use.", choices=choices)
        parser.add_argument("endpoint", help="Whether or not to run as a client or server.", choices=["server", "client"])
        values = vars(parser.parse_args())

        protocol_name = values["protocol"]
        selected_protocol = protocols[protocol_name]

        # Load the selected protocol configuration
        with open("config.json") as handle:
            configuration = json.loads(handle.read())
            protocol_configuration = configuration[protocol_name]

        # Build the available IP list
        available_addresses = list(iptools.IpRange(configuration["general"]["network"]))
        available_addresses = available_addresses[0:len(available_addresses) - 1]
        server_address = configuration["general"]["server"]

        if server_address not in available_addresses:
            print("!!! Server address %s not in network %s!" % (server_address, configuration["general"]["network"]))
            return
        else:
            available_addresses.remove(server_address)

        # Initialize the protocol
        conn = selected_protocol(config=protocol_configuration, application=self,
                                addresses=available_addresses, server=server_address)

        if values["endpoint"] == "server":
            conn.server_init()
            update_function = conn.server_update
        else:
            conn.client_init()
            update_function = conn.client_update

        while True:
            try:
                update_function()
            except (KeyboardInterrupt, EOFError):
                if values["endpoint"] == "server":
                    conn.server_deinit()
                else:
                    conn.client_deinit()
                break

        print("")
        print("Stopped VPN.")

if __name__ == "__main__":
	Application().main()
