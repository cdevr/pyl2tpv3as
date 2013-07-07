# Adapted from twisted matrix code.
# -*- test-case-name: twisted.pair.test.test_ip -*-
# Copyright (c) 2001-2004 Twisted Matrix Laboratories.
# See LICENSE for details.

"""Support for working directly with IP packets"""

import struct
import socket

from twisted.internet import protocol
import raw
from zope.interface import implements


def intToIp(intip):
    """Configure a 32 bit integer to a string ip representation"""
    octet = ''
    for exp in [3, 2, 1, 0]:
        octet = octet + str(intip / (256 ** exp)) + "."
        intip = intip % (256 ** exp)
        return(octet.rstrip('.'))


class IPHeader:
    def __init__(self, data):
        (ihlversion, self.tos, self.tot_len, self.fragment_id, frag_off,
         self.ttl, self.protocol, self.check, saddr, daddr) \
         = struct.unpack("!BBHHHBBH4s4s", data[:20])
        self.saddr = socket.inet_ntoa(saddr)
        self.daddr = socket.inet_ntoa(daddr)
        self.version = ihlversion & 0x0F
        self.ihl = ((ihlversion & 0xF0) >> 4) << 2
        self.fragment_offset = frag_off & 0x1FFF
        self.dont_fragment = (frag_off & 0x4000 != 0)
        self.more_fragments = (frag_off & 0x2000 != 0)


def ipPacket(ihlversion, tos, tot_len, frag_id, frag_off,
             ttl, protocol, check, saddr, daddr, payload):
    saddr = socket.inet_aton(saddr)
    daddr = socket.inet_aton(daddr)

    return struct.pack("!BBHHHBBH4s4s", ihlversion, tos, tot_len, frag_id,
                       frag_off, ttl, protocol, check, saddr, daddr) + payload

MAX_SIZE = 2L ** 32


class IPProtocol(protocol.AbstractDatagramProtocol):
    implements(raw.IRawPacketProtocol)

    def __init__(self):
        self.ipProtos = {}

    def addProto(self, num, proto):
        proto = raw.IRawDatagramProtocol(proto)
        if num < 0:
            raise TypeError('Added protocol must be positive or zero')
        if num >= MAX_SIZE:
            raise TypeError('Added protocol must fit in 32 bits')
        if num not in self.ipProtos:
            self.ipProtos[num] = []
        self.ipProtos[num].append(proto)

    def datagramReceived(self,
                         data,
                         partial=None,
                         dest=None,
                         source=None,
                         protocol=None):
        header = IPHeader(data)
        for proto in self.ipProtos.get(header.protocol, ()):
            proto.datagramReceived(data=data[20:],
                                   partial=partial,
                                   source=header.saddr,
                                   dest=header.daddr,
                                   protocol=header.protocol,
                                   version=header.version,
                                   ihl=header.ihl,
                                   tos=header.tos,
                                   tot_len=header.tot_len,
                                   fragment_id=header.fragment_id,
                                   fragment_offset=header.fragment_offset,
                                   dont_fragment=header.dont_fragment,
                                   more_fragments=header.more_fragments,
                                   ttl=header.ttl,
                                   )
