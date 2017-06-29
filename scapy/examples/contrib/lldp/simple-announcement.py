import os
import sys
import time

scapy_path = os.path.realpath('{}/../../../../'.format(os.path.dirname(os.path.realpath(__file__))))
sys.path.insert(0, scapy_path + '/')

'''
This is a simple example on how to use the LLDP layer.
'''

from scapy.contrib.lldp import *

LLDP_TTL = 10
INTERFACE = 'eth5'

if __name__ == '__main__':

    socket = conf.L2socket(iface=INTERFACE)
    try:
        count = 1
        while True:
            frm = Ether(src='00:ba:d0:0b:ee:f0', dst=LLDP_NEAREST_BRIDGE_MAC) / \
                  LLDPDUChassisID(subtype=LLDPDUChassisID.SUBTYPE_MAC_ADDRESS, id=b'\x06\x05\x04\x03\x02\x01') / \
                  LLDPDUPortID(subtype=LLDPDUPortID.SUBTYPE_INTERFACE_NAME, id='sw-00-port-0000') / \
                  LLDPDUTimeToLive(ttl=LLDP_TTL) / \
                  LLDPDUSystemCapabilities(mac_bridge_available=True, mac_bridge_enabled=True) / \
                  LLDPDUSystemName(name='tor-sw-00') / \
                  LLDPDUManagementAddress(
                      management_address_subtype=LLDPDUManagementAddress.SUBTYPE_MANAGEMENT_ADDRESS_IPV4,
                      management_address=b'\x01\x02\x03\x04') / \
                  LLDPDUEndOfLLDPDU()

            print '{} send LLDP announcement (ttl = {}) via {}...'.format(count, LLDP_TTL, INTERFACE)
            count += 1
            socket.send(frm)

            time.sleep(LLDP_TTL)

    except KeyboardInterrupt as err:
        pass
