"""
Juliette Laburthe, jkl6et
Used the dpkt documentation to understand helper methods (inet_to_str)
https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ip.html
https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html
https://dpkt.readthedocs.io/en/latest/_modules/dpkt/tcp.html?highlight=.flags
"""

import sys
import dpkt
import socket
import numpy as np

# helper method to return readable ip addresses : https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html

# Number of blocks
N = 5
# Alpha Value
alpha = 0.8


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


packets = []
with open(sys.argv[1], 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for timestamp, buf in pcap:

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                packets.append(ip)

        except Exception:
            pass

print(packets[0])


def processPackets(ip_list):
  # grabbing source and destination ips to update dictionaries
    blockSize = len(ip_list) // N
    f, s = [], [0]
    for i in range(0, len(ip_list), blockSize):
        currentIP = ip_list[i:i + blockSize]
        # creating dictionaries to store IP and counts of when they are sending SYN
        # or being returned a SYNACK.
        rst_dict = {}
        synack_dict = {}
        dst_dict = {}
        # Used to store IPs that, according to our specs, are suspect of port scanning.
        scanners = []

        syn_dict = {}
        f_dict = {}
        r_dict = {}
        for ip in currentIP:
            src = inet_to_str(ip.src)
            dst = inet_to_str(ip.dst)
            tcp = ip.data
            # print(tcp.seq)
            #  is hex for SYN flag
            if tcp.flags == 2:
                if src not in syn_dict:
                    syn_dict[tcp.seq] = (src, dst, False)

            # 18 is hex for SYNACK flag (2+16)
            if tcp.flags == 18:
                if tcp.seq-1 in list(syn_dict.keys()):
                    f_dict[tcp.seq] = (src, dst, 1)
                    syn_dict[tcp.seq] = True
                else:
                    r_dict[tcp.seq] = (src, dst, 1)

        # implement this every n packets
        synack_f = len(f_dict)

        estimate_f = alpha * (0 if not f else f[-1]) + (1-alpha)*synack_f
        delta1n = abs(len(f_dict)-len(syn_dict))
        delta2n = abs(len(f_dict)-len(r_dict))
        d1n = delta1n/estimate_f
        d2n = delta2n/estimate_f
        xn = np.sqrt(d1n ** 2 + d2n ** 2)
        s.append(estimate_f)
        yn = estimate_f - min(s)
        f.append(synack_f)


def dn(yn):
    if yn <= 1:
        return 0
    else:
        return 1


if dn(yn) == 1:
    print("syn flood occuring")
else:
    print("no syn flood detected.")
