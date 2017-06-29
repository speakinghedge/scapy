import os
import sys

scapy_path = os.path.realpath('{}/../../../../'.format(os.path.dirname(os.path.realpath(__file__))))
sys.path.insert(0, scapy_path + '/')

'''
This is a simple example on how to sniff LLDP PDUs and dump relevant information.
'''

from scapy.layers.l2 import sniff
from scapy.contrib.lldp import *

INTERFACE = 'eth2'


def lldp_msg(pkt):
    print '#######  lldp frame received: {}  ############################'.format(pkt.time)

    print '{} -> {}'.format(pkt[Ether].src, pkt[Ether].dst)

    chassis_id_tlv = pkt[LLDPDUChassisID]
    if chassis_id_tlv.subtype == LLDPDUChassisID.SUBTYPE_MAC_ADDRESS:
        print '\tChassisID: {}'.format(':'.join('%02x' % ord(b) for b in chassis_id_tlv.id))

    port_id_tlv = pkt[LLDPDUPortID]
    if port_id_tlv.subtype == LLDPDUPortID.SUBTYPE_INTERFACE_NAME:
        print '\tPortID: {}'.format(port_id_tlv.id)

    try:
        management_address_tlv = pkt[LLDPDUManagementAddress]
        if management_address_tlv.management_address_subtype == LLDPDUManagementAddress.SUBTYPE_MANAGEMENT_ADDRESS_IPV4:
            print '\tManagementIP: {}'.format(
                '.'.join('%d' % ord(b) for b in management_address_tlv.management_address))

    except KeyError as err:
        pass


if __name__ == '__main__':

    conf.contribs['LLDP'].strict_mode_disable()
    try:
        sniff(iface=INTERFACE, prn=lldp_msg, filter='ether proto {}'.format(LLDP_ETHER_TYPE))
    except KeyboardInterrupt as err:
        pass
