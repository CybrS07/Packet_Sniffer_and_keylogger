import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = eth_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Source: {}, Destination: {}'.format(src, target))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, ack, flags, data = tcp_packet(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flags['URG'], flags['ACK'], flags['PSH']))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN: {}'.format(flags['RST'], flags['SYN'], flags['FIN']))

                # HTTP
                if src_port == 80 or dest_port == 80:
                    print(TAB_2 + 'HTTP Data:')
                    try:
                        http = data.decode('utf-8', errors='replace')
                        http_info = http.split('\r\n')
                        for line in http_info:
                            if line:
                                print(DATA_TAB_3 + line)
                    except Exception:
                        print(format_multi_line(DATA_TAB_3, data))

                # HTTPS
                elif src_port == 443 or dest_port == 443:
                    print(TAB_2 + 'HTTPS (Encrypted):')
                    if len(data) >= 3:
                        tls_types = {0x16: 'Handshake', 0x17: 'Application Data',
                                     0x14: 'ChangeCipherSpec', 0x15: 'Alert'}
                        content_type = tls_types.get(data[0], hex(data[0]))
                        print(DATA_TAB_3 + 'TLS Content Type: {}'.format(content_type))
                    print(format_multi_line(DATA_TAB_3, data))

                else:
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_packet(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

                # DNS
                if src_port == 53 or dest_port == 53:
                    print(TAB_2 + 'DNS Data:')
                    print(format_multi_line(DATA_TAB_3, data))

                else:
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))

            # Other
            else:
                print(TAB_1 + 'Other IPv4 Protocol: {}'.format(proto))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

        else:
            print(TAB_1 + 'Non-IPv4 Packet (EtherType: {})'.format(eth_proto))
            print(format_multi_line(DATA_TAB_2, data))


""" Unpack ethernet frame """
def eth_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


""" Format MAC address """
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


""" Unpack IPv4 packet """
def ipv4_packet(data):
    version_header_loader = data[0]
    version = version_header_loader >> 4
    header_length = (version_header_loader & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


""" Format IPv4 address """
def ipv4(addr):
    return '.'.join(map(str, addr))


""" Unpack ICMP packet """
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


""" Unpack TCP segment """
def tcp_packet(data):
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, ack, flags, data[offset:]


""" Unpack UDP segment """
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, size, data[8:]


""" Format multi-line data """
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == '__main__':
    main()