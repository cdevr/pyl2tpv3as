#!/usr/bin/python
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import log, reflect, components
from twisted.internet import base, fdesc, error
import errno
import os
import ip
from zope.interface import implements
import raw
import sys
from socket import *
import random
import struct
import binascii
import string

routerid = sys.argv[1]

# L2tpv3 control connections, one per remote router.
# Indexed with a tuple, (source ip, dest ip, connection id)
controlConnections = {}

# L2TPV3Connection, L2tpv3 data connections.
# Indexed by (source, dest, session id)
connections = {}

# The instances of the switch class, indexed by connection cookie.
switches = {}

avpVendors = {
    0: "Reserved",
    9: "CiscoSystems"
}

avpTypes = {
    0: {
        0: "Control Message",
        2: "Protocol Version",
        3: "Framing Capabilities",
        5: "Tie Breaker",
        6: "Firmware Revision",
        7: "Host name",
        8: "Vendor name",
        15: "Call serial number",
        10: "Receive window size",
        56: "Unknown AVP",
        57: "Unknown AVP",
        60: "Router ID",
        61: "Assigned Control Connection ID",
        62: "Pseudowire capability list"},
    9: {
      1: "Assigned Connection ID",
      2: "Pseudowire Capabilities list",
      3: "Local session ID",
      4: "Remote session ID",
      6: "Remote end ID",
      7: "Pseudowire type",
      9: "Unknown AVP",
      10: "Draft AVP Version",
      110: "Unknown AVP",
      111: "Unknown AVP"}}

ControlMessageTypes = {
    "SCCRQ": 1,
    "SCCRP": 2,
    "SCCCN": 3,
    "StopCCN": 4,
    "reserved": 5,
    "Hello": 6,
    "ACK": 20,

    "OCRQ": 7,
    "OCRP": 8,
    "OCCN": 9,
    "ICRQ": 10,
    "ICRP": 11,
    "ICCN": 12,
    "CDN": 14,

    "WEN": 15,

    "SLI": 16}


# Create the inverse lookup table for quick lookup on packet reception.
ControlMessages = dict([(y, x) for (x, y)
                        in ControlMessageTypes.iteritems()])

rsock = None


def is_broadcast(mac):
    """Returns true fi this MAC address denotes a broadcast address."""
    return mac == "\xff" * 6


def is_multicast(mac):
    """Returns true if this MAC address denotes a multicast address."""
    return ord(mac[0]) & 1


def getSwitch(cookie):
    """The switch ID is only sent upon L2tpv3 connection setup. Actual packets
    are marked with a 'cookie', so we need to lookup the switch based on the
    cookie."""
    if cookie not in switches:
        switches[cookie] = Switch(cookie)
    return switches[cookie]


class Switch:
    """A basic layer2 switch implementation."""
    def __init__(self, cookie):
        self.cookie = cookie
        self.ports = []
        self.macs = {}
        self.multicast_macs = {}

        print "created switch %s" % cookie

    def addPort(self, conn):
        if not conn in self.ports:
            self.ports += [conn]

    def addMulticast(self, mac, port):
        if mac in self.multicast_macs:
            if not port in self.multicast_macs[mac]:
                self.multicast_macs[mac] += [port]
        else:
            self.multicast_macs[mac] = [port]

    def replicate(self, incoming, packet):
        for p in self.ports:
            if p != incoming:
                p.sendDataPacket(packet)

    def switchPacket(self, incoming, packet):
        dst_mac = packet[0:6]
        src_mac = packet[6:12]
        prot = packet[12:14]

        if prot != '\x08\x00' and prot != '\x08\x06' and prot != '\x86\xdd':
            # don't switch anything except IP, IPv6 and ARP.
            return

        # is src multicast ?
        if is_broadcast(src_mac):
            # Do not associate broadcast sources with ports.
            pass
        elif is_multicast(src_mac):
            # Multicasts get added to a port, can be on multiple ports.
            # TODO this should timeout after a while.
            self.addMulticast(src_mac, incoming)
        else:
            # Otherwise register this MAC to this port. If it was registered
            # on another port, it moves.
            # TODO these should timeout.
            self.macs[src_mac] = incoming

        # Analyse destination MAC addresses.
        if is_broadcast(dst_mac):
            # broadcast, replicate on every interface except the incoming
            # interface.
            self.replicate(incoming, packet)
        elif is_multicast(dst_mac):
            print "multicast destination"
            if dst_mac in self.multicast_macs:
                for p in self.multicast_macs[dst_mac]:
                    if p != incoming:
                        p.sendDataPacket(packet)
            else:
                # Ignore packet to unknown multicast address.
                print "packet to unknown multicast address - ignoring"
                pass
        else:
            if dst_mac in self.macs:
                print "sending to connection : %s" % self.macs[dst_mac]
                if self.macs[dst_mac] != incoming:
                    self.macs[dst_mac].sendDataPacket(packet)
            else:
                # If you see too many of these messages, you probably have
                # assymetric L2 paths.
                print ("destination unknown, replicate on all interfaces"
                       " except incoming one")
                self.replicate(incoming, packet)


class RawSocket(base.BasePort):
    def __init__(self, ip, protnum, proto, reactor=None):
        base.BasePort.__init__(self, reactor)
        self.ip = ip
        self.protnum = protnum
        self.proto = proto

    def __repr__(self):
        return "Raw socket on ip %s listening for proto %s" % (self.ip,
                                                               self.proto)

    def startListening(self):
        log.msg("Listening on raw socket for protocol %s" % (self.protnum))

        self.fd = socket(AF_INET, SOCK_RAW, self.protnum)
        self.fd.bind((self.ip, self.protnum))

        self.startReading()

    def fileno(self):
        return self.fd.fileno()

    def doRead(self):
        packet = self.fd.recv(16384)
        self.proto.datagramReceived(packet)

    def doWrite(self, packet, dest):
        packet = self.fd.sendto(packet, (dest, 0))


class L2TPV3AVP:
    format = "!HHH"
    hlen = struct.calcsize(format)

    def __init__(self, M=False, H=False, vendor_id=0,
                 attribute_type=0, data=""):
        self.M = M
        self.H = H
        self.vendor_id = vendor_id
        self.attribute_type = attribute_type
        self.data = data
        self.len = struct.calcsize(self.format) + len(data)

    def toBinary(self):
        return struct.pack(
            self.format, [0, 0x8000][self.M] + [0, 0x4000][self.H] + self.len,
            self.vendor_id, self.attribute_type) + self.data

    def __repr__(self):
        vendor = avpVendors.get(self.vendor_id)
        if vendor != None:
            avpType = avpTypes[self.vendor_id].get(self.attribute_type)
        else:
            avpType = None

        return "AVP { %s%s, %s(%s):%s(%s) len(%d) '%s' }" % (
            ['m', 'M'][self.M], ['h', 'H'][self.H], self.vendor_id, vendor,
            self.attribute_type, avpType, self.len,
            binascii.b2a_hex(self.data))

    def decode(self, fmt):
        return struct.unpack(fmt, self.data)


def L2TPV3AVPFromBinary(data):
    avp = L2TPV3AVP()
    (flaglen, avp.vendor_id, avp.attribute_type) = struct.unpack(avp.format,
                                                                 data[:6])

    avp.M = (flaglen & 0x8000 != 0)
    avp.H = (flaglen & 0x4000 != 0)
    avp.len = flaglen & 0x03FF

    avp.data = data[6:avp.len]

    return avp


def L2TPV3AVPFromParams(M, H, len, vendor_id, attribute_type, data):
    avp = L2TPV3AVP()
    avp.M = M
    avp.H = H
    avp.len = len & 0x03FF
    avp.vendor_id = vendor_id
    avp.attribute_type = attribute_type
    avp.data = data

    return avp


class L2TPV3Packet:
    format = "!H"
    hlen = struct.calcsize(format)

    def __init__(self, session, data):
        self.data = data
        self.session = session

    def toBinary(self):
        return stuct.pack(format, self.session) + data


class L2TPV3ControlHeader:
    format = "!IHHIHH"
    hlen = struct.calcsize(format)

    def __init__(self, data=None):
        if data == None:
            self.T = True
            self.L = True
            self.S = True
            self.ver = 3
            self.avps = []
            self.Nr = 0
            self.Ns = 0
            # self.avpmap = {}
        else:
            (zeros, flagsver, self.length, self.control_id, self.Ns,
             self.Nr) = struct.unpack(self.format, data[:self.hlen])
            self.ver = flagsver & 0x000F
            self.T = (flagsver & 0x8000 != 0)
            self.L = (flagsver & 0x4000 != 0)
            self.S = (flagsver & 0x0800 != 0)

            assert(len(data) - 4 == self.length)

            # get the AVPs
            self.avps = []
            c = self.hlen
            while c < self.length:
                avp = L2TPV3AVPFromBinary(data[c:])
                assert(len(avp.toBinary()) != 0)  # prevent infinite loop
                c += len(avp.toBinary())
                self.avps += [avp]
                # self.avpmap(avp.vendor_id, avp.attribute_type)] = avp;
            # assert(c == self.len) TODO

    def __repr__(self):
        s = "ZLB"
        if self.get(0, 0) != None:
            s = ControlMessages[self.get(0, 0).decode("!H")[0]]

        return ("L2tpv3control %s { T %s L %s S %s Ver %s Len %s"
                " Control_id %s Ns %s Nr %s AVPS [ %s ] }") % (
            s, self.T, self.L, self.S, self.ver, self.length, self.control_id,
            self.Ns, self.Nr, ",".join(map(str, self.avps)))

    def get(self, vendor, avpType, altVendor=None, altType=None):
        for avp in self.avps:
            if (avp.vendor_id == vendor and avp.attribute_type == avpType):
                return avp
        if altVendor != None:
            for avp in self.avps:
                if (avp.vendor_id == altVendor and
                    avp.attribute_type == altType):
                    return avp
        return None

    def toBinary(self):
        flagsver = self.ver
        if self.T:
            flagsver += 0x8000
        if self.L:
            flagsver += 0x4000
        if self.S:
            flagsver += 0x0800

        avpstring = "".join(map(lambda x: x.toBinary(), self.avps))
        # session ID (4 bytes integer) doesn't count
        avplen = len(avpstring) - 4
        return struct.pack(self.format,
            0,
            flagsver,
            struct.calcsize(self.format) + avplen,
            self.control_id,
            self.Ns,
            self.Nr) + avpstring


class L2TPV3Connection():
    serial = 0
    localSessId = 0
    remoteSessId = 0
    pseudowireType = 0
    remoteEndId = 0
    status = 0
    switch = None
    source = None
    dest = None

    def __init__(self, source, dest, icrq):
        self.source = source
        self.dest = dest
        self.serial = icrq.get(0, 15).decode("!I")[0]
        # switch local and remote ID's
        self.localSessId = icrq.get(0, 64, 9, 4).decode("!I")[0]
        self.remoteSessId = icrq.get(0, 63, 9, 3).decode("!I")[0]
        self.pseudowireType = icrq.get(0, 68, 9, 7).decode("!H")[0]
        self.remoteEndId = icrq.get(0, 66, 9, 6).data
        if icrq.get(0, 71) != None:
            self.status = icrq.get(0, 71).decode("!H")[0]

        if self.localSessId == 0:
            # assign a unique session ID
            self.localSessId = struct.unpack(
                "!I", string.join(
                    [chr(random.randint(0, 255)) for x in range(4)], ''))[0]
            print "generated local session id : %s (%s)" % (
                self.localSessId, type(self.localSessId))

        # join switch
        self.switch = getSwitch(self.remoteEndId)
        self.switch.addPort(self)

    def genICRP(self):
        icrp = L2TPV3ControlHeader()
        icrp.avps = [
            # control message type AVP
            L2TPV3AVP(True, False, 0, 0,
                      struct.pack("!H", ControlMessageTypes["ICRP"])),
            # local session id.
            L2TPV3AVP(False, False, 0, 63,
                      struct.pack("!I", self.localSessId)),
            # remote session id.
            L2TPV3AVP(False, False, 0, 64,
                      struct.pack("!I", self.remoteSessId)),
            # pseudowire type.
            L2TPV3AVP(False, False, 0, 68,
                      struct.pack("!H", self.pseudowireType)),
            # No l2 specific sublayer supported.
            L2TPV3AVP(False, False, 0, 69,
                      struct.pack("!H", 0)),
            # Sequencing : not supported.
            L2TPV3AVP(False, False, 0, 70,
                      struct.pack("!H", 0)),
            # Circuit status. We always say Active. Works fine.
            L2TPV3AVP(False, False, 0, 71,
                      struct.pack("!H", 1)),
            # Local session id.
            L2TPV3AVP(False, False, 9, 3,
                      struct.pack("!I", self.localSessId)),
            # Remote session id.
            L2TPV3AVP(False, False, 9, 4,
                      struct.pack("!I", self.remoteSessId)),
            # Pseudowire type.
            L2TPV3AVP(False, False, 9, 7,
                      struct.pack("!H", self.pseudowireType)),
            # Interface MTU.
            L2TPV3AVP(False, False, 9, 14,
                      struct.pack("!H", 2040))]
        return icrp

    def genSLI(self):
        sli = L2TPV3ControlHeader()
        sli.avps = [
            # control message type AVP.
            L2TPV3AVP(True, False, 0, 0,
                      struct.pack("!H", ControlMessageTypes["SLI"])),
            # local session id.
            L2TPV3AVP(False, False, 0, 63,
                      struct.pack("!I", self.localSessId)),
            # remote session id.
            L2TPV3AVP(False, False, 0, 64,
                      struct.pack("!I", self.remoteSessId)),
            # Pseudowire type.
            L2TPV3AVP(False, False, 0, 68,
                      struct.pack("!H", self.pseudowireType)),
            # circuit status, let's just say it's active, and new
            L2TPV3AVP(False, False, 0, 71,
                      struct.pack("!H", 1)),
            # local session id
            L2TPV3AVP(False, False, 9, 3,
                      struct.pack("!I", self.localSessId)),
            # remote session id
            L2TPV3AVP(False, False, 9, 4,
                      struct.pack("!I", self.remoteSessId))]
        return sli

    def sendDataPacket(self, packet):
        print "sendDataPacket called on %s %s packet : %s" % (
            self.source, self.remoteEndId, binascii.b2a_hex(packet))

        l2tpv3packet = struct.pack("!I", self.remoteSessId) + packet
        rsock.doWrite(l2tpv3packet, self.source)
        pass

    def genDataPacket(self, packet):
        return L2TPV3Packet(self.remoteSessId, packet)

    def datagramReceived(self, source, dest, packet):
        self.switch.switchPacket(self, packet)

    def __repr__(self):
        return "L2TPv3Connection %s %s (session IDs l/r : %s/%s)" % (
            self.source, self.remoteEndId, self.localSessId, self.remoteSessId)


class L2TPV3ControlConnection():
    Ns = 0
    Nr = 0

    def __init__(self, source, dest, control_id):
        self.source = source
        self.dest = dest
        self.control_id = control_id
        self.state = "idle"

    def sendDatagram(self, packet):
        print "sending packet %d (received %d)" % (self.Ns, self.Nr)
        packet.control_id = self.control_id
        packet.Ns = self.Ns
        self.Ns += 1  # sending a packet
        packet.Nr = self.Nr

        rsock.doWrite(packet.toBinary(), self.source)

    def sendZLB(self):
        print "sending ZLB"
        packet = L2TPV3ControlHeader()
        packet.control_id = self.control_id
        packet.Ns = self.Ns
        # self.Ns += 1 # ZLB doesn't count as a packet sent.
        packet.Nr = self.Nr
        # no AVPs

        rsock.doWrite(packet.toBinary(), self.source)

    def sendHello(self):
        packet = L2TPV3ControlHeader()
        packet.control_id = self.control_id
        packet.Ns = self.Ns
        packet.avps = [
            # control message type AVP
            L2TPV3AVP(True, False, 0, 0,
                      struct.pack("!H", ControlMessageTypes["Hello"]))]
        self.Ns += 1  # sending a packet, increase counter.
        packet.Nr = self.Nr

        rsock.doWrite(packet.toBinary(), self.source)

    def addToSwitch(switchid, conn):
        if switchid in switches:
            switches[switchid] += [conn]
        else:
            switches[switchid] = [conn]

    def datagramReceived(self, proto, source, dest, data):
        p = L2TPV3ControlHeader(data)
        print "received packet (nr = %d) %s" % (self.Nr, p)

        if p.length == 12:
            # received ZLB doesn't count as a received packet
            print "ZLB received, ignoring"
            return

        # temp bugfix TODO fix this with proper buffering
        self.Nr = p.Ns + 1
        self.Ns = p.Nr
        # self.Nr += 1

        if self.state == "idle":
            if p.get(0, 0).decode("!H") == (ControlMessageTypes["SCCRQ"],):
                log.msg(p)

                log.msg("Hostname : ", p.get(0, 7).data)
                if p.get(0, 60) != None:
                    log.msg("Router ID : ",
                            ".".join(map(str, p.get(0, 60).decode("BBBB"))))
                else:
                    log.msg("No router ID")
                log.msg("Assigned Control Connection ID : %d" % (
                    self.control_id))

                # reply with a SCCRP to establish control connection
                reply = L2TPV3ControlHeader()

                s = struct.pack("!I", self.control_id)
                reply.avps = [
                    # control message type AVP
                    L2TPV3AVP(True, False, 0, 0,
                              struct.pack("!H", ControlMessageTypes["SCCRP"])),
                    # protocol version AVP version 1 revision 0
                    L2TPV3AVP(True, False, 0, 2,
                              struct.pack("!BB", 1, 0)),
                    # hostname AVP
                    L2TPV3AVP(True, False, 0, 7, "boem.babies"),
                    # router ID AVP
                    L2TPV3AVP(False, False, 0, 60, inet_aton(routerid)),
                    # Assigned control connection ID AVP
                    L2TPV3AVP(False, False, 0, 61,
                              struct.pack("!I", self.control_id)),
                    # Pseudowire Capabilities list AVP (only support ethernet)
                    L2TPV3AVP(False, False, 0, 62,
                              struct.pack("!HH", 4, 5)),
                    # Cisco Assigned control connection ID AVP
                    L2TPV3AVP(True, False, 9, 1,
                              struct.pack("!I", self.control_id)),
                    # Cisco core AVP draft
                    L2TPV3AVP(True, False, 9, 2,
                              struct.pack("!HH", 4, 5)),
                    # Cisco core AVP draft
                    L2TPV3AVP(True, False, 9, 10,
                              struct.pack("!H", 1))]

                self.sendDatagram(reply)
                log.msg("Sent SCCRP")
            elif p.get(0, 0).decode("!H") == (ControlMessageTypes["SCCCN"],):
                self.state = "online"
                self.sendZLB()  # acknowledge receipt of SCCCN
                log.msg("SCCCN received, control conn online. ZLB ack sent")
            else:
                reply = L2TPV3ControlHeader()
                reply.avps = [
                  # control message type AVP
                  L2TPV3AVP(True, False, 0, 0,
                            struct.pack("!H", ControlMessageTypes["StopCCN"])),
                  L2TPV3AVP(True, False, 0, 1,
                            struct.pack("!HH", 2, 6) +
                                        "invalid control connection"),
                  # Assigned control connection ID AVP
                  L2TPV3AVP(False, False, 0, 61,
                            struct.pack("!I", self.control_id)),
                  # Cisco Assigned control connection ID AVP
                  L2TPV3AVP(True, False, 9, 1,
                            struct.pack("!I", self.control_id)),
                ]
                self.sendDatagram(reply)
                log.msg("Unknown packet, sent STOPCCN: %s" % p)
        if self.state == "online":
            if p.get(0, 0).decode("!H") == (ControlMessageTypes["ICRQ"],):
                log.msg("Request to bring pseudowire online !")
                log.msg("Call serial number : %s" % (
                    p.get(0, 15).decode("!I")[0]))
                log.msg("Local Session ID : %s" % (
                    p.get(0, 63, 9, 3).decode("!I")[0]))
                log.msg("Remote Session ID : %s" % (
                    p.get(0, 64, 9, 4).decode("!I")[0]))
                log.msg("Pseudowire Type : (4 = 'eth vlan', 5 = 'eth') %s" % (
                    p.get(0, 68, 9, 7).decode("!H")[0]))
                log.msg("Remote end ID : %s" % p.get(0, 66, 9, 6).data)
                if p.get(0, 71) != None:
                    log.msg("Circuit status : New(%s) Active(%s)" % (
                        p.get(0, 71).decode("!H")[0] & 0x0001,
                        p.get(0, 71).decode("!H")[0] & 0x0002))
                c = L2TPV3Connection(source, dest, p)
                connections[(source, dest, c.localSessId)] = c

                # send the ICRP
                self.sendDatagram(c.genICRP())
            elif p.get(0, 0).decode("!H") == (ControlMessageTypes["SLI"],):
                # acknowledge receipt
                self.sendZLB()
            elif p.get(0, 0).decode("!H") == (ControlMessageTypes["Hello"],):
                # acknowledge receipt
                self.sendZLB()
            elif p.get(0, 0).decode("!H") == (ControlMessageTypes["ICCN"],):
                log.msg("Pseudowire online !")
                # lookup remote session ID to find local session
                localSessId = p.get(0, 64, 9, 4).decode("!I")[0]

                self.sendDatagram(
                    connections[(source, dest, localSessId)].genSLI())
                # TODO send stopCCN
            else:
                log.msg("Unknown packet : %s" % p)


class L2TPV3(protocol.DatagramProtocol):
    implements(raw.IRawDatagramProtocol)

    def __init__(self):
        pass

    def datagramReceived(self, data, partial, source, dest, protocol, version,
                         ihl, tos, tot_len, fragment_id, fragment_offset,
                         dont_fragment, more_fragments, ttl):
        # determine if it's a control connection packet (session_id == 0)
        sess_id, = struct.unpack("!I", data[:4])

        if sess_id == 0:  # Root session.
            l = L2TPV3ControlHeader(data)
            print "packet received from %s, len %s %s" % (source, len(data), l)

            if l.control_id == 0:
                # find the assigned connection id AVP
                l.control_id = struct.unpack("!I", l.get(0, 61, 9, 1).data)[0]
                print "proposed connection id : %d" % l.control_id
            # get the control connection
            if not (source, dest, l.control_id) in controlConnections:
                controlConnections[(source, dest, l.control_id)] = \
                    L2TPV3ControlConnection(source, dest, l.control_id)
            controlConnections[(source, dest, l.control_id)].datagramReceived(
                self, source, dest, data)
        elif (source, dest, sess_id) in connections:
            connections[(source, dest, sess_id)].datagramReceived(
                source, dest, data[4:])
        else:
            print "data packet with invalid session received"
            # TODO should probably send a disconnect message at this point.

if __name__ == "__main__":
    log.startLogging(sys.stdout)
    p_l2tpv3 = L2TPV3()

    p_ip = ip.IPProtocol()
    p_ip.addProto(115, p_l2tpv3)

    rsock = reactor.listenWith(RawSocket, ip=routerid, protnum=115,
                               proto=p_ip, reactor=reactor)
    reactor.run()
