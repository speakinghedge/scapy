#! /usr/bin/env python
#
# scapy.contrib.description = EtherCat
# scapy.contrib.status = loads

"""
    EtherCat automation protocol
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :author:    Thomas Tannhaeuser, hecke@naberius.de
    :license:   GPLv2

        This module is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This module is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

    :description:

        This module provides Scapy layers for the EtherCat protocol.

        normative references:
            - IEC 61158-3-12 - data link service and topology description
            - IEC 61158-4-12 - protocol specification

        Currently only read/write services as defined in IEC 61158-4-12,
        sec. 5.4 are supported.

    :TODO:

        - Mailbox service (sec. 5.5)
        - Network variable service (sec. 5.6)

    :NOTES:

        - EtherCat frame type defaults to TYPE-12-PDU (0x01) using xxx bytes
          of padding
        - padding for minimum frame size is added automatically

"""

from scapy.layers.dot11 import Packet, ByteField, LEShortField, \
    LEBitFieldLenField, LEBitField, LEBitEnumField, FieldListField, \
    LEIntField
from scapy.layers.l2 import Ether, Dot1Q, Padding, bind_layers, \
    log_runtime, struct

################################################
# DLPDU structure definitions (read/write PDUs)
################################################

ETHERCAT_TYPE_12_CIRCULATING_FRAME = {
    0x00: 'FRAME-NOT-CIRCULATING',
    0x01: 'FRAME-CIRCULATED-ONCE'
}

ETHERCAT_TYPE_12_NEXT_FRAME = {
    0x00: 'LAST-TYPE12-PDU',
    0x01: 'TYPE12-PDU-FOLLOWS'
}


class EtherCatType12DLPDU(Packet):
    """
    Type12 message base class
    """
    def post_build(self, pkt, pay):
        """

        set next attr automatically if not set explicitly by user

        :param pkt: raw string containing the current layer
        :param pay: raw string containing the payload
        :return: <new current layer> + payload
        """

        data_len = len(self.data)
        if data_len > 2047:
            raise ValueError('payload size {} exceeds maximum length {} '
                             'of data size.'.format(data_len, 2047))

        if self.next is not None:
            has_next = True if self.next else False
        else:
            if pay:
                has_next = True
            else:
                has_next = False

        oct_7 = struct.unpack('B', pkt[7])[0]
        if has_next:
            oct_7 |= 0b10000000
        else:
            oct_7 &= 0b01111111

        pkt = pkt[:7] + struct.pack('B', oct_7)[0] + pkt[8:]
        return pkt + pay

    def guess_payload_class(self, payload):

        try:
            dlpdu_type = struct.unpack("b", payload[0])[0]
            return EtherCat.ETHERCAT_TYPE12_DLPDU_TYPES[dlpdu_type]

        except KeyError:
            log_runtime.error(
                '{}.guess_payload_class() - unknown or invalid '
                'DLPDU type'.format(self.__class__.__name__))
            return Packet.guess_payload_class(self, payload)

        return Packet.guess_payload_class(self, payload)

    # structure templates lacking leading cmd-attribute
    PHYSICAL_ADDRESSING_DESC = [
        ByteField('idx', 0),
        LEShortField('adp', 0),
        LEShortField('ado', 0),
        LEBitFieldLenField('len', None, 11, count_of='data'),
        LEBitField('_reserved', 0, 3),
        LEBitEnumField('c', 0, 1, ETHERCAT_TYPE_12_CIRCULATING_FRAME),
        LEBitEnumField('next', None, 1, ETHERCAT_TYPE_12_NEXT_FRAME),
        LEShortField('irq', 0),
        FieldListField('data', [], ByteField('', 0x00),
                       count_from=lambda pkt: pkt.len),
        LEShortField('wkc', 0)
    ]

    BROADCAST_ADDRESSING_DESC = PHYSICAL_ADDRESSING_DESC

    LOGICAL_ADDRESSING_DESC = [
        ByteField('idx', 0),
        LEIntField('adr', 0),
        LEBitFieldLenField('len', None, 11, count_of='data'),
        LEBitField('_reserved', 0, 3),
        LEBitEnumField('c', 0, 1, ETHERCAT_TYPE_12_CIRCULATING_FRAME),
        LEBitEnumField('next', None, 1, ETHERCAT_TYPE_12_NEXT_FRAME),
        LEShortField('irq', 0),
        FieldListField('data', [], ByteField('', 0x00),
                       count_from=lambda pkt: pkt.len),
        LEShortField('wkc', 0)
    ]


################
# read messages
################

class EtherCatAPRD(EtherCatType12DLPDU):
    """
    APRD - Auto Increment Physical Read
    (IEC 61158-5-12, sec. 5.4.1.2 tab. 14 / p. 32)
    """

    fields_desc = [ByteField('_cmd', 0x01)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFPRD(EtherCatType12DLPDU):
    """
    FPRD - Configured address physical read
    (IEC 61158-5-12, sec. 5.4.1.3 tab. 15 / p. 33)
    """

    fields_desc = [ByteField('_cmd', 0x04)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatBRD(EtherCatType12DLPDU):
    """
    BRD - Broadcast read
    (IEC 61158-5-12, sec. 5.4.1.4 tab. 16 / p. 34)
    """

    fields_desc = [ByteField('_cmd', 0x07)] + \
                  EtherCatType12DLPDU.BROADCAST_ADDRESSING_DESC


class EtherCatLRD(EtherCatType12DLPDU):
    """
    LRD - Logical read
    (IEC 61158-5-12, sec. 5.4.1.5 tab. 17 / p. 36)
    """

    fields_desc = [ByteField('_cmd', 0x0a)] + \
                  EtherCatType12DLPDU.LOGICAL_ADDRESSING_DESC


#################
# write messages
#################


class EtherCatAPWR(EtherCatType12DLPDU):
    """
    APWR - Auto Increment Physical Write
    (IEC 61158-5-12, sec. 5.4.2.2 tab. 18 / p. 37)
    """

    fields_desc = [ByteField('_cmd', 0x02)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFPWR(EtherCatType12DLPDU):
    """
    FPWR - Configured address physical write
    (IEC 61158-5-12, sec. 5.4.2.3 tab. 19 / p. 38)
    """

    fields_desc = [ByteField('_cmd', 0x05)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatBWR(EtherCatType12DLPDU):
    """
    BWR - Broadcast read (IEC 61158-5-12, sec. 5.4.2.4 tab. 20 / p. 39)
    """

    fields_desc = [ByteField('_cmd', 0x08)] + \
                  EtherCatType12DLPDU.BROADCAST_ADDRESSING_DESC


class EtherCatLWR(EtherCatType12DLPDU):
    """
    LWR - Logical write
    (IEC 61158-5-12, sec. 5.4.2.5 tab. 21 / p. 40)
    """

    fields_desc = [ByteField('_cmd', 0x0b)] + \
                  EtherCatType12DLPDU.LOGICAL_ADDRESSING_DESC


######################
# read/write messages
######################


class EtherCatAPRW(EtherCatType12DLPDU):
    """
    APRW - Auto Increment Physical Read Write
    (IEC 61158-5-12, sec. 5.4.3.1 tab. 22 / p. 41)
    """

    fields_desc = [ByteField('_cmd', 0x03)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFPRW(EtherCatType12DLPDU):
    """
    FPRW - Configured address physical read write
    (IEC 61158-5-12, sec. 5.4.3.2 tab. 23 / p. 43)
    """

    fields_desc = [ByteField('_cmd', 0x06)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatBRW(EtherCatType12DLPDU):
    """
    BRW - Broadcast read write
    (IEC 61158-5-12, sec. 5.4.3.3 tab. 24 / p. 39)
    """

    fields_desc = [ByteField('_cmd', 0x09)] + \
                  EtherCatType12DLPDU.BROADCAST_ADDRESSING_DESC


class EtherCatLRW(EtherCatType12DLPDU):
    """
    LRW - Logical read write
    (IEC 61158-5-12, sec. 5.4.3.4 tab. 25 / p. 45)
    """

    fields_desc = [ByteField('_cmd', 0x0c)] + \
                  EtherCatType12DLPDU.LOGICAL_ADDRESSING_DESC


class EtherCatARMW(EtherCatType12DLPDU):
    """
    ARMW - Auto increment physical read multiple write
    (IEC 61158-5-12, sec. 5.4.3.5 tab. 26 / p. 46)
    """

    fields_desc = [ByteField('_cmd', 0x0d)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCatFRMW(EtherCatType12DLPDU):
    """
    FRMW - Configured address physical read multiple write
    (IEC 61158-5-12, sec. 5.4.3.6 tab. 27 / p. 47)
    """

    fields_desc = [ByteField('_cmd', 0x0e)] + \
                  EtherCatType12DLPDU.PHYSICAL_ADDRESSING_DESC


class EtherCat(Packet):
    """
    Common EtherCat header layer
    """
    ETHER_HEADER_LEN = 14
    ETHER_FSC_LEN = 4
    ETHER_FRAME_MIN_LEN = 64
    ETHERCAT_HEADER_LEN = 2

    FRAME_TYPES = {
        0x01: 'TYPE-12-PDU',
        0x04: 'NETWORK-VARIABLES',
        0x05: 'MAILBOX'
    }

    fields_desc = [
        LEBitField('length', 0, 11),
        LEBitField('_reserved', 0, 1),
        LEBitField('type', 0, 4),
    ]

    ETHERCAT_TYPE12_DLPDU_TYPES = {
        0x01: EtherCatAPRD,
        0x04: EtherCatFPRD,
        0x07: EtherCatBRD,
        0x0a: EtherCatLRD,
        0x02: EtherCatAPWR,
        0x05: EtherCatFPWR,
        0x08: EtherCatBWR,
        0x0b: EtherCatLWR,
        0x03: EtherCatAPRW,
        0x06: EtherCatFPRW,
        0x09: EtherCatBRW,
        0x0c: EtherCatLRW,
        0x0d: EtherCatARMW,
        0x0e: EtherCatFRMW
    }

    def post_build(self, pkt, pay):
        """
        need to set the length of the whole PDU manually
        to avoid any bit fiddling use a dummy class to build the layer content

        also add padding if frame is < 64 bytes

        Note: padding only handles Ether/n*Dot1Q/EtherCat
              (no special mumbo jumbo)

        :param pkt: raw string containing the current layer
        :param pay: raw string containing the payload
        :return: <new current layer> + payload
        """

        class _EtherCatLengthCalc(Packet):
            """
            dummy class used to generate str representation easily
            """
            fields_desc = [
                LEBitField('length', None, 11),
                LEBitField('_reserved', 0, 1),
                LEBitField('type', 0, 4),
            ]

        payload_len = len(pay)

        # length field is 11 bit
        if payload_len > 2047:
            raise ValueError('payload size {} exceeds maximum length {} '
                             'of EtherCat message.'.format(payload_len, 2047))

        self.length = payload_len

        vlan_headers_total_size = 0
        upper_layer = self.underlayer

        # add size occupied by VLAN tags
        while upper_layer and isinstance(upper_layer, Dot1Q):
            vlan_headers_total_size += 4
            upper_layer = upper_layer.underlayer

        if not isinstance(upper_layer, Ether):
            raise Exception('missing Ether layer')

        pad_len = EtherCat.ETHER_FRAME_MIN_LEN - (EtherCat.ETHER_HEADER_LEN +
                                                  vlan_headers_total_size +
                                                  EtherCat.ETHERCAT_HEADER_LEN +
                                                  payload_len +
                                                  EtherCat.ETHER_FSC_LEN)

        if pad_len > 0:

            pad = Padding()
            pad.load = b'\x00' * pad_len

            return str(_EtherCatLengthCalc(length=self.length,
                                           type=self.type)) + pay + str(pad)
        else:
            return str(_EtherCatLengthCalc(length=self.length,
                                           type=self.type)) + pay

    def guess_payload_class(self, payload):

        try:
            dlpdu_type = struct.unpack("b", payload[0])[0]
            return EtherCat.ETHERCAT_TYPE12_DLPDU_TYPES[dlpdu_type]
        except KeyError:
            log_runtime.error(
                '{}.guess_payload_class() - unknown or invalid '
                'DLPDU type'.format(self.__class__.__name__))
            return Packet.guess_payload_class(self, payload)


bind_layers(Ether, EtherCat, type=0x88a4)
bind_layers(Dot1Q, EtherCat, type=0x88a4)

# bindings for DLPDUs

bind_layers(EtherCat, EtherCatAPRD, type=0x01)
bind_layers(EtherCat, EtherCatFPRD, type=0x01)
bind_layers(EtherCat, EtherCatBRD, type=0x01)
bind_layers(EtherCat, EtherCatLRD, type=0x01)
bind_layers(EtherCat, EtherCatAPWR, type=0x01)
bind_layers(EtherCat, EtherCatFPWR, type=0x01)
bind_layers(EtherCat, EtherCatBWR, type=0x01)
bind_layers(EtherCat, EtherCatLWR, type=0x01)
bind_layers(EtherCat, EtherCatAPRW, type=0x01)
bind_layers(EtherCat, EtherCatFPRW, type=0x01)
bind_layers(EtherCat, EtherCatBRW, type=0x01)
bind_layers(EtherCat, EtherCatLRW, type=0x01)
bind_layers(EtherCat, EtherCatARMW, type=0x01)
bind_layers(EtherCat, EtherCatFRMW, type=0x01)
