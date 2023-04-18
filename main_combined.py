import sys
import socket
import dpkt
import datetime
import time
import numpy as np


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def isTCP(buf):
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except:
        return 0

    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data

        if isinstance(ip.data, dpkt.tcp.TCP):
            return ip
    return 0


def convert_time(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).time()


def ewma(prev, current, beta):
    return beta*prev + (1-beta)*current


# adaptive threshold algorithm
def ata(pcap_file):
    pcap = dpkt.pcap.Reader(open(pcap_file, 'rb'))
    num_syn = 0
    prev_time = 0
    prev_ewma = 1
    start_time = 0
    start_timestamp = False
    start_average = False

    BETA = 0.75
    ALPHA = 3
    INTERVAL = 5

    for timestamp, buf in pcap:
        if not start_timestamp:
            prev_time = timestamp
            start_time = timestamp
            start_timestamp = True
        ip = isTCP(buf)
        if ip != 0:
            tcp = ip.data
            syn = (tcp.flags & dpkt.tcp.TH_SYN != 0)

            if syn:
                num_syn += 1

            if(timestamp - prev_time > INTERVAL):
                if not start_average:
                    prev_ewma = num_syn
                    start_average = True
                    # print("Nothing detected between " +
                    #         str(convert_time(prev_time)) + " - " + str(convert_time(timestamp)))
                    # print("Number of packets: " + str(num_syn))
                    prev_time = timestamp
                    num_syn = 0
                else:
                    if(num_syn > (ALPHA + 1) * prev_ewma):
                        print("Nothing detected between " +
                              str(convert_time(start_time)) + " - " + str(convert_time(timestamp)))
                        print("****** SYN FLOOD DETECTED *******")
                        print("Flood detected at time: " +
                              str(convert_time(timestamp)))
                        print("Expected average number of packets: " +
                              str(prev_ewma))
                        print("Number of packets detected between " +
                              str(convert_time(prev_time)) + " - " + str(convert_time(timestamp)) + " : " + str(num_syn))
                        break
                    else:
                        # print("Nothing detected between " +
                        #     str(convert_time(prev_time)) + " - " + str(convert_time(timestamp)))
                        # print("Number of packets: " + str(num_syn))
                        # print("*")
                        prev_time = timestamp
                        num_syn = 0
                        prev_ewma = ewma(prev_ewma, num_syn, BETA)

            # print(convert_time(timestamp))


def default_method(pcap_file):
    pcap = dpkt.pcap.Reader(open(pcap_file, 'rb'))
    output = dict()
    for timestamp, buf in pcap:
        ip = isTCP(buf)
        if ip != 0:
            tcp = ip.data

            src_ip = inet_to_str(ip.src)
            dest_ip = inet_to_str(ip.dst)
            syn = (tcp.flags & dpkt.tcp.TH_SYN != 0)
            ack = (tcp.flags & dpkt.tcp.TH_ACK != 0)

            if syn and ack:
                if dest_ip not in output:
                    output[dest_ip] = {
                        'SYN': 0,
                        'SYN+ACK': 1
                    }
                else:
                    output[dest_ip]['SYN+ACK'] += 1
            elif syn:
                if src_ip not in output:
                    output[src_ip] = {
                        'SYN': 1,
                        'SYN+ACK': 0
                    }
                else:
                    output[src_ip]['SYN'] += 1

    keys = tuple(output.keys())
    for k in keys:
        if output[k]['SYN'] < (output[k]['SYN+ACK'] * 3):
            del output[k]

    return sorted(output.keys())

# CUSUM


def dn(yn):
    if yn <= 1:
        return 0
    else:
        return 1


def getLists(f):
    pcap = dpkt.pcap.Reader(open(f, 'rb'))
    packets = []
    timestamps = []
    for timestamp, buf in pcap:

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                packets.append(ip)
                timestamps.append(timestamp)

        except Exception:
            pass
    return (packets, timestamps)


def processPackets(ip_list, timestamps):
    # Alpha Value
    alpha = 0.8
    # Beta Value, sus
    beta = 0.5
    print("Alpha:", alpha, "Beta:", beta)
  # grabbing source and destination ips to update dictionaries
    blockSize = min(len(ip_list), 100000)
    f, s = [], []
    x = []
    # detection_count = 0
    for i in range(0, len(ip_list), blockSize):
        # print("N:",i,"-",i+blockSize)
        currentIP = ip_list[i:i + blockSize]

        syn_dict = {}
        f_dict = {}
        r_dict = {}
        for ip in currentIP:
            src = inet_to_str(ip.src)
            dst = inet_to_str(ip.dst)
            tcp = ip.data
            # 2 is hex for SYN flag
            if tcp.flags == 2:
                if src not in syn_dict:
                    syn_dict[tcp.seq] = (src, dst, False)

            # 18 is hex for SYNACK flag (2+16)
            if tcp.flags == 18:
                if tcp.ack-1 in list(syn_dict.keys()):
                    f_dict[tcp.seq] = (src, dst)
                    syn_dict[tcp.seq] = True
                else:
                    r_dict[tcp.seq] = (src, dst)

        # implement this every n packets
        synack_f = len(f_dict)
        estimate_f = alpha * (0 if not f else f[-1]) + (1-alpha)*synack_f
        delta1n = abs(len(f_dict)-len(syn_dict))
        delta2n = abs(len(f_dict)-len(r_dict))
        d1n = 0
        d2n = 0
        if estimate_f == 0:
            d1n = 0
            d2n = 0
        else:
            d1n = delta1n/estimate_f
            d2n = delta2n/estimate_f
        xn = np.sqrt(d1n ** 2 + d2n ** 2)
        # print("Xn", xn)
        f.append(synack_f)

        x1 = xn - beta
        x.append(x1)
        S = sum(x)
        s.append(S)
        yn = S - min(s)
        if dn(yn) == 1:
            print("****** SYN FLOOD DETECTED *******")
            print("a SYN flood has been detected at time:", str(
                datetime.datetime.utcfromtimestamp(timestamps[i])))
            # detection_count +=1
            # victims = np.unique(list(map(operator.itemgetter(0), list(r_dict.values()))))
            # attackers = np.unique(list(map(operator.itemgetter(1), list(r_dict.values()))))
            # print("Victim IPs:", [x for x in victims])
            # print("Attacker IPs:", [x for x in attackers])
            return
        # consider the case where all pcaps in the current n are all SYN flooding victim IPs
        # elif len(syn_dict) == len(currentIP):
        #     print("a SYN flood has been detected.")
        #     detection_count +=1
        #     victims = np.unique(list(map(operator.itemgetter(1), list(syn_dict.values()))))
        #     attackers = np.unique(list(map(operator.itemgetter(0), list(syn_dict.values()))))
        #     print("Victim IPs:", [x for x in victims])
        #     print("Attacker IPs:", [x for x in attackers])
    print("No Floods Detected")
    # print("A Syn flood was detected",detection_count,"times in the pcap.")


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Please include a PCAP filename.")
        sys.exit(-1)
    pcap_file = sys.argv[1]
    # pcap = dpkt.pcap.Reader(open(pcap_file, 'rb'))
    t0 = time.time()
    print("Default Method from HW 1: ")
    ips = default_method(pcap_file)
    if len(ips) > 0:
        print("****** SYN FLOOD DETECTED *******")
        print("Attackers:")
        for ip in ips:
            print(ip)
    tdefault = time.time()
    print("Adaptive Threshold Method")
    ata(pcap_file)
    tata = time.time()
    print("CUSUM Method")
    ip_list, timestamps = getLists(pcap_file)
    processPackets(ip_list, timestamps)
    tcusum = time.time()
    print("Runtime for Default Method: " +
          str(convert_time(tdefault - t0).second) + " seconds")
    print("Runtime for Adaptive Threshold Method: " +
          str(convert_time(tata - tdefault).second) + " seconds")
    print("Runtime for CUSUM:", str(convert_time(tcusum - tata).second)+ " seconds")


# used the reference site in the hw:
# https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html
