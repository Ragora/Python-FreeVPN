"""
	tundevice.py

	TUN device implementation.

	This software is licensed under the MIT license. See LICENSE for more information.
"""

import os
import fcntl
import struct
import select
import subprocess

TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def int2ip(number):
    """
        Converts an integer to the string IP address.
    """
    number = int(number)
    octet_one = (number / 16777216) % 256
    octet_two = (number / 65536) % 256
    octet_three = (number / 256) % 256
    octet_four = (number) % 256

    return "%u.%u.%u.%u" % (octet_one, octet_two, octet_three, octet_four)

def ip2int(ip):
    """
        Converts an IP address to its integer representation.
    """

    octets = ip.split(".")

    octet_one = int(octets[0]) << 24
    octet_two = int(octets[1]) << 16
    octet_three = int(octets[2]) << 8
    octet_four = int(octets[3])

    return octet_one | octet_two | octet_three | octet_four

def get_frame_info(header):
    """
        Returns frame information from the given header data.
    """
    frame_length = struct.unpack("!H", header[2:4])[0]
    source = int2ip(struct.unpack("!I", header[12:16])[0])
    destination = int2ip(struct.unpack("!I", header[16:20])[0])

    return {"length": frame_length, "source": source, "destination": destination}

def set_frame_info(frame, information):
    """
        Modifies frame header information.
    """

    frame = list(frame)

    if "source" in information:
        frame[16:20] = struct.pack("!I", ip2int(information["source"]))

    if "destination" in information:
        frame[20:24] = struct.pack("!I", ip2int(information["destination"]))

    # FIXME: There might be something faster to join by here
    return "".join(frame)

class TUNDevice(object):
    """
        A TUN device. This is used to present userspace handling of IP frames on your local machine.

        FIXME: Handle under size frames
    """

    name = None
    """
        The name of the TUN device. This will be what appears in ifconfig.
    """

    address = None
    """
        The IP address of the TUN device.
    """

    mtu = None
    """
        The MTU of this TUN device.
    """

    _device = None
    """
        The actual device handler.
    """

    _current_frame_buffer = None
    """
        The current frame buffer for over MTU requests.
    """

    _current_frame_length = None
    """
        The length of the current frame for over MTU requests.
    """

    _sockets = None
    """
        The list of sockets to test for writability and readability using the select call.
    """

    _before_data = None
    _after_data = None

    def __init__(self, name, address, cidr=24):
        # FIXME: Determine the device MTU
        # self.mtu = mtu
        self.name = name
        self.address = address

        self._device = open("/dev/net/tun", "r+b")
        self._sockets = [self._device]

        self._before_data = ""
        self._after_data = ""

        # Tall it we want a TUN device.
        ifr = struct.pack("16sH", self.name, IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._device, TUNSETIFF, ifr)

        # Optionally, we want it be accessed by the normal user.
        # fcntl.ioctl(tun, TUNSETOWNER, 1000)

        # Bring it up and assign addresses.
        subprocess.check_call("ip addr add %s/%u dev %s > /dev/null" % (self.address, cidr, self.name), shell=True)
        subprocess.check_call("ip link set dev %s up > /dev/null" % self.name, shell=True)
        subprocess.check_call("ip route get %s > /dev/null" % self.address, shell=True)

    def update(self):
        """
            Processes the TUN device for any incoming network data, handling MTU as necessary.
        """

        readable, writable, exceptional = select.select(self._sockets, self._sockets, self._sockets)
        readable = len(readable) != 0
        writable = len(writable) != 0

        # If there is any data available to read, we read everything until the socket is no longer readable
        while readable is True:
            # We read a frame header worth of bytes first
            frame_header = os.read(self._device.fileno(), 24)
            if len(frame_header) != 24:
                print("!!! Invalid Frame Header Length. Read %u != 24 bytes." % len(frame_header))

            information = get_frame_info(frame_header)
            data_length = information["length"]
            if data_length <= 0 or data_length > 65536:
                print("!!! Invalid Frame Length: %u" % data_length)
            else:
                remaining_bytes = data_length - 24
                frame_data = os.read(self._device.fileno(), remaining_bytes)
                if len(frame_data) != remaining_bytes:
                    print("!!! Bad Frame Data Length: %u != %u" % (len(frame_data), remaining_bytes))
                else:
                    result = self.handle_frame(frame_header + frame_data, information)
                    if result is not None:
                        self.write_data(result)

            readable = False

    def handle_frame(self, frame, info):
        """
            Callback for handling an unhandled IP frame on our virtual network.

            :parameters:
                frame - The entire frame data. MTU is handled internally by this class.
                info - Information read out of the frame headers.

            :return:
                The frame data to write to the network. Return None to drop the frame.
        """

        return frame

    def write_data(self, data):
        os.write(self._device.fileno(), data)

    def write_data_callback(self, data, before=False):
        """
            Used for writing more frame data aside from what was initially returned in our handle_frame callback.

            :parameters:
                frame - The frame data to write.
                before - Whether or not this new frame should be written before the returned frame data.
        """

        if before is True:
            self._after_data += data
            return
        self._before_data += data
