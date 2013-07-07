#!/usr/bin/python
# TODO more tests
from main import *
import binascii


def testDecodeSCCRQ():
    data = ("00000000c80300d90000000000000000"
        "80080000000000018008000000020100800a0000000300000000000e000000053c"
        "1a508b77f271de0008000000061130800e000000076172312e6272753100190000"
        "0008436973636f2053797374656d732c20496e632e80080000000a040000060000"
        "0038000600000039000a0000003c5e8ca002000a0000003da6ef07760018000000"
        "3e000500040006000700010003000a0009000b800a00090001a6ef077680180009"
        "0002000500040006000700010003000a0009000b80080009000a00010006000900"
        "6e00060009006f")
    packet = binascii.a2b_hex(data)

    header = L2TPV3ControlHeader(packet)
    print header


def testEncodeSCCRP():
    packet = L2TPV3ControlHeader()
    packet.control_id = 0
    packet.ns = 0
    packet.nr = 0

    print binascii.b2a_hex(packet.toBinary())


def testEncodeAVP():
    avp = L2TPV3AVP(True, False, 0, 0,
                    struct.pack("!H", ControlMessageTypes["SCCRQ"]))
    s = avp.toBinary()

    print str(avp)
    print binascii.b2a_hex(s)


if __name__ == "__main__":
    testDecodeSCCRQ()
    testEncodeSCCRP()
    testEncodeAVP()
