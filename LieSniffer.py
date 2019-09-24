import socket
import struct

# Tobby Lie
# CSCI 4742 Lab 3
# Last modified: 9/24/19 @ 2:33PM

def main():
    # make a connection and use htons to maintain the endianness of the machine architecture with network byte order
    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    # infinite loop in order to continuously capture raw packets
    while True:
        # receive packets on socket with max buffer size of 65536 -> largest buffer that can be defined
        # raw data captured will be in byte format and need to still locate where information we need from each packet
        # is such as what type of packet it is
        ethernet_data, address = packets.recvfrom(65536)
        # get the destination mac address, source mac address, protocol and ip data from ethernet
        dest_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)
        # means it is an ipv4 packet
        if protocol == 8:
            ip_protocol, src_ip, dest_ip, transport_data = ipv4_dissect(ip_data)
            # tcp is protocol 6
            if ip_protocol == 6:
                src_port, dest_port = tcp_dissect(transport_data)
                print('source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3},'
                      'protocol:{4}, source port:{5}, dest port:{6}'.format(src_mac,
                                                                            dest_mac,
                                                                            src_ip,
                                                                            dest_ip,
                                                                            ip_protocol,
                                                                            src_port,
                                                                            dest_port))
            # udp is protocol 17
            elif ip_protocol == 17:
                src_port, dest_port = udp_dissect(transport_data)
                print('source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3},'
                      'protocol:{4}, source port:{5}, dest port:{6}'.format(src_mac,
                                                                            dest_mac,
                                                                            src_ip,
                                                                            dest_ip,
                                                                            ip_protocol,
                                                                            src_port,
                                                                            dest_port))
            # icmp is protocol 1
            elif ip_protocol == 1:
                type, code = icmp_dissect(transport_data)
                print('source mac:{0}, dest mac:{1}, source ip:{2}, dest ip:{3},'
                      'protocol:{4}, type:{5}, code:{6}'.format(src_mac,
                                                                dest_mac,
                                                                src_ip,
                                                                dest_ip,
                                                                ip_protocol,
                                                                type,
                                                                code))

def ethernet_dissect(ethernet_data):
    ''' from raw data in byte form convert it to an understandable form '''
    # 6s - a string of 6 characters -> MAC addresses are 48 bits or 6 bytes
    # H - unsigned short integer of 2 bytes
    # protocol is usable but source mac address and destination mac address are not
    dest_mac, src_mac, protocol = struct.unpack('!6s6sH', ethernet_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]

def tcp_dissect(transport_data):
    ''' extract source and destination port from transport data '''
    # it is the first four bytes, first 2 are source and second 2 are destination
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port

def udp_dissect(transport_data):
    ''' extract source and destination port from transport data '''
    # it is the first four bytes, first 2 are source and second 2 are destination
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port

def icmp_dissect(transport_data):
    ''' extract type and code port from transport data '''
    # it is the first four bytes, first 2 are type and second 2 are code
    type, code = struct.unpack('!HH', transport_data[:4])
    return type, code


def mac_format(mac):
    ''' formats MAC addresses from byte string to proper formatting '''
    # takes first destination mac address and then source mac address and correct their format
    # utilizing map function on each mac string
    # map essentially applies the same function on all elements and returns that result
    # input is mac string and function is '{:02x}'.format
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

def ipv4_format(address):
    ''' convert each element to string by applying map '''
    return '.'.join(map(str, address))

def ipv4_dissect(ip_data):
    ''' extracts data needed from ip_data '''
    # skip first 9 bytes, take in 1 byte for protocol
    # skip next 2 bytes, 4 bytes for source address
    # 4 bytes for destination address
    # the rest is ip data
    ip_protocol, source_ip, target_ip = struct.unpack('!9xB2x4s4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]

main()
