"""
	vpnadapter.py

	VPN virtual interface specialization of the TUNDevice.

	This software is licensed under the MIT license. See LICENSE for more information.
"""

from tundevice import TUNDevice

class VPNAdapter(TUNDevice):
    """
        The actual TUN device we use for our VPN network handling.
    """

    protocol = None
    """
        The internal protocol using this TUN adapter.
    """

    def __init__(self, protocol, **kwargs):
        super(VPNAdapter, self).__init__(**kwargs)
        self.protocol = protocol

    def handle_frame(self, frame, information):
        """
            Processes frames that were dispatched to the TUN device.
        """

        self.protocol.handle_frame(frame, information)
        return None
