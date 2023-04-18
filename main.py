import sys
import socket
import dpkt
import datetime


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
def ata(pcap):
    num_syn = 0
    prev_time = 0
    prev_ewma = 1
    start_time = 0
    startTimestamp = False
    startAverage = False

    BETA = 0.75
    ALPHA = 3
    INTERVAL = 5

    for timestamp, buf in pcap:
        if not startTimestamp:
            prev_time = timestamp
            start_time = timestamp
            startTimestamp = True
        ip = isTCP(buf)
        if ip != 0:
            tcp = ip.data
            syn = (tcp.flags & dpkt.tcp.TH_SYN != 0)

            if syn:
                num_syn += 1
                
            if(timestamp - prev_time > INTERVAL):
                if not startAverage:
                    prev_ewma = num_syn
                    startAverage = True
                    # print("Nothing detected between " +
                    #         str(convert_time(prev_time)) + " - " + str(convert_time(timestamp)))
                    # print("Number of packets: " + str(num_syn))
                    print("*")
                    prev_time = timestamp
                    num_syn = 0
                else:
                    if(num_syn > (ALPHA + 1) * prev_ewma):
                        print("Nothing detected between " +
                            str(convert_time(start_time)) + " - " + str(convert_time(timestamp)))
                        print("****** SYN FLOOD DETECTED *******")
                        print("Flood detected at time: " + str(convert_time(timestamp)))
                        print("Expected average number of packets: " + str(prev_ewma))
                        print("Number of packets detected between " +
                            str(convert_time(prev_time)) + " - " + str(convert_time(timestamp)) + " : " + str(num_syn))
                        break
                    else:
                        # print("Nothing detected between " +
                        #     str(convert_time(prev_time)) + " - " + str(convert_time(timestamp)))
                        # print("Number of packets: " + str(num_syn))
                        print("*")
                        prev_time = timestamp
                        num_syn = 0
                        prev_ewma = ewma(prev_ewma, num_syn, BETA)
            
            # print(convert_time(timestamp))


def default_method(pcap):
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


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Please include a PCAP filename.")
        sys.exit(-1)
    pcap_file = sys.argv[1]
    pcap = dpkt.pcap.Reader(open(pcap_file, 'rb'))
    # beta = 1
    # ips = default_method(pcap)
    # if len(ips) == 0:
    #     print("none")
    # for ip in ips:
    #     print(ip)
    ata(pcap)


# used the reference site in the hw:
# https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html
