
# # R1: Write code to analyze the trace of IP datagrams in traceroute 
# # Use: traceroute-frag.pcap 

# # R2: Compare 5 traces in each group 

import sys
import struct
import math
from IP_parser import IPPacket
from TracerouteState import TracerouteState
import math



def print_rtt_results(state):
    print("=" * 62)

    # per-router RTTs
    for router_ip, rtts in state.rtts_by_router.items():
        if len(rtts) == 0:
            
            continue

        avg = sum(rtts) / len(rtts)
        if len(rtts) > 1:
            variance = sum((x - avg)**2 for x in rtts) / (len(rtts)-1)
            sd = math.sqrt(variance)
        else:
            sd = 0.0

        print(f"The avg RTT between {state.src_ip} and {router_ip} is: {avg:.6f} ms, "
              f"the s.d. is: {sd:.6f} ms")

    # final destination RTT
    if state.rtts_to_dest:
        avg = sum(state.rtts_to_dest) / len(state.rtts_to_dest)
        if len(state.rtts_to_dest) > 1:
            variance = sum((x - avg)**2 for x in state.rtts_to_dest) / (len(state.rtts_to_dest)-1)
            sd = math.sqrt(variance)
        else:
            sd = 0.0

        print(f"The avg RTT between {state.src_ip} and {state.dst_ip} is: {avg:.6f} ms, "
              f"the s.d. is: {sd:.6f} ms")

    print("=" * 62)



def print_fragment_results(state):
    # identify fragments datagrams 
    fragmented_ids = [
        ip_id for ip_id, frags in state.fragments.items()
        if len(frags) > 1
    ]

    # no fragmentation 
    if not fragmented_ids:
        print("The number of fragments created from the original datagram is: 0")
        print("The offset of the last fragment is: 0")
        return

    # fragmented 
    ip_id = fragmented_ids[0]
    frags = state.fragments[ip_id]

    num_frags = len(frags)

    # get offset of last fragment (MF == 0)
    last_offsets = [offset for mf, offset in frags if mf == 0]

    if last_offsets:
        last_offset = max(last_offsets)
    else:
        last_offset = 0

    print(f"The number of fragments created from the original datagram is: {num_frags}")
    print(f"The offset of the last fragment is: {last_offset}")




def print_intermediate_nodes(state):
    print("The IP addresses of the intermediate destination nodes:")

    hop_number = 1

    for hop in sorted(state.routers_by_hop.keys()):
        routers = state.routers_by_hop[hop]   # DO NOT SORT

        for router_ip in routers:
            print(f"\trouter {hop_number}: {router_ip} (TTL={hop})")
            hop_number += 1



def compute_rtts(state):

    state.rtts_by_router = {}
    state.rtts_to_dest = []

    for port, send_list in state.sent_times_by_port.items():
        if port not in state.icmp_times:
            continue

        recv_time = state.icmp_times[port]
        router_ip = state.icmp_router.get(port)

        if router_ip is None:
            continue

        for sent_time, ttl in send_list:
            rtt_ms = (recv_time - sent_time)

            if router_ip == state.dst_ip:      # final hop
                state.rtts_to_dest.append(rtt_ms)
            else:
                state.rtts_by_router.setdefault(router_ip, []).append(rtt_ms)

# def compute_rtts(state):

#     state.rtts_by_router = {}
#     state.rtts_to_dest = []

#     # udp_sent: port -> [send1, send2, ...]
#     # icmp_times: port -> [recv1, recv2, ...]   (may be a list or single float)
#     for port, send_times in state.udp_sent.items():

#         # No reply → skip
#         if port not in state.icmp_times:
#             continue

#         recv_times = state.icmp_times[port]
#         router_ip = state.icmp_router.get(port)

#         if router_ip is None:
#             continue

#         # Normalize recv_times to ALWAYS be a list
#         if isinstance(recv_times, float):
#             recv_times = [recv_times]

#         # Compute RTT for every send_time and recv_time pair
#         for send_time in send_times:
#             for recv_time in recv_times:

#                 rtt_ms = (recv_time - send_time)

#                 if router_ip == state.dst_ip:
#                     state.rtts_to_dest.append(rtt_ms)
#                 else:
#                     state.rtts_by_router.setdefault(router_ip, []).append(rtt_ms)







def finalize_udp_timestamps(state):
    """after parsing pcap, organize timestamps by port"""
    state.sent_times_by_port = {}

    for port, sent_time in state.udp_sent.items():
        ttl = state.udp_probes.get(port)
        state.sent_times_by_port.setdefault(port, []).append((sent_time, ttl))




def parse_fragment_info(ip_bytes):
    """ takes IP header and returns ip id, MF flag, and fragment offset in bytes
    """

    ip_id = int.from_bytes(ip_bytes[4:6], "big")
    flags_and_offset = int.from_bytes(ip_bytes[6:8], "big")

    # MF flag = bit 13 of the 16-bit field
    mf_flag = 1 if (flags_and_offset & 0x2000) != 0 else 0

    # Fragment offset = low 13 bits × 8 bytes
    frag_units = flags_and_offset & 0x1FFF
    frag_offset_bytes = frag_units * 8

    return ip_id, mf_flag, frag_offset_bytes




def is_traceroute_udp(p_packet, udp_payload): 

    src_port = int.from_bytes(udp_payload[0:2], 'big')
    dst_port = int.from_bytes(udp_payload[2:4], 'big')

    # Skip DNS
    if src_port == 53 or dst_port == 53:
        return False

    # skip private IP's and broadcasts 
    if is_private_ip(p_packet.dst_ip) or is_multicast_or_broadcast(p_packet.dst_ip):
        return False

    # Must have some payload (traceroute uses UDP payload)
    if len(udp_payload) <= 8:
        return False

    return True

def is_private_ip(ip):
    """trace route only targets public IP's """
    parts = list(map(int, ip.split(".")))
    
    # 10.0.0.0/8
    if parts[0] == 10:
        return True

    # 172.16.0.0/12
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True

    # 192.168.0.0/16
    if parts[0] == 192 and parts[1] == 168:
        return True

    return False


def is_multicast_or_broadcast(ip):
    """check if IP is a broadcast"""
    # Multicast range: 224.0.0.0 – 239.255.255.255
    first = int(ip.split(".")[0])
    if 224 <= first <= 239:
        return True
    
    # Broadcast
    if ip == "255.255.255.255":
        return True

    return False



def parse_icmp_type(payload: bytes):
    """Return ICMP type from ICMP header"""
    if len(payload) < 1:
        return None
    return payload[0]


def parse_icmp(): 
    pass

# complete first 
def parse_udp(packet):

    # get IP of sources node (computer that executes the source node)
    # source node is the IP of the first UDP packet 

    
    # get IP of destination of ul
    pass


def parse_pcap(pcap_file, state):
    """parse the PCAP file and populate TCP connection information"""
    

    with open(pcap_file, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print("Incomplete global header")
            exit(1)
        
        magic_big = struct.unpack('>I', global_header[:4])[0]
        magic_little = struct.unpack('<I', global_header[:4])[0]

        if magic_big == 0xa1b2c3d4 or magic_big == 0xa1b23c4d:
            endian = '>'
        elif magic_little == 0xa1b2c3d4 or magic_little == 0xa1b23c4d:
            endian = '<'
        else:
            print("Unknown magic number, cannot determine endianness")
            exit(1)
        
        state.first_ts = None
        packet_index = 0
        all_packets = [] # new code 


        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)
            ts = ts_sec + ts_usec / 1e6
            packet_index += 1

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                print("Incomplete packet data")
                break
            
            all_packets.append((ts, packet_data))

        all_packets.sort(key=lambda x: x[0])

        for ts, packet_data in all_packets:

            
            if state.first_ts is None:
                state.first_ts = ts
            relative_ts = ts - state.first_ts

            ether_type = int.from_bytes(packet_data[12:14], "big")
            if ether_type != 0x0800:
                continue

            p_packet = IPPacket.from_bytes(packet_data[14:])
            state.protocols.add(p_packet.protocol)


            ip_header = packet_data[14:14 + p_packet.header_length * 4]
            ip_id, mf_flag, frag_offset_bytes = parse_fragment_info(ip_header)

            if ip_id not in state.fragments:
                state.fragments[ip_id] = []
            state.fragments[ip_id].append((mf_flag, frag_offset_bytes))

            if p_packet.protocol == 1:      # ICMP 
                icmp_type = parse_icmp_type(p_packet.payload)
                
                icmp = p_packet.payload
                icmp_time = relative_ts # save relative ts 

                inner_ip_bytes = icmp[8:8+20]
                inner_ip = IPPacket.from_bytes(inner_ip_bytes)

                inner_udp_bytes = icmp[8+20 : 8+20+8]
                inner_src_port = int.from_bytes(inner_udp_bytes[0:2], "big")


       


                # print(f"[ICMP RECV] inner_port={inner_src_port}, time={icmp_time:.6f}, type={icmp_type}")
                # print(f"   matches UDP send? {inner_src_port in state.udp_sent}")

                if icmp_type == 11:  # Time Exceeded
                    router_ip = p_packet.src_ip

                    # Linux UDP traceroute
                    if inner_ip.protocol == 17:


                        # print("\n=== ICMP TIME EXCEEDED RECEIVED ===")
                        # print(f"  Router (outer ICMP src IP): {router_ip}")
                        # print(f"  Embedded original UDP src_port: {inner_src_port}")
                        # print(f"  Embedded original dst IP: {inner_ip.dst_ip}")
                        # print(f"  Embedded original src IP: {inner_ip.src_ip}")
                        # print(f"  Embedded original TTL (after decrement): {inner_ip.ttl}")
                        # print(f"  Matching UDP ports seen so far: {list(state.udp_sent.keys())[:15]}")


                        if inner_src_port in state.udp_sent:
        
                        
                            # Store ICMP return time indexed by source port
                            state.icmp_times[inner_src_port] = icmp_time
                            state.icmp_router[inner_src_port] = router_ip


                            hop = state.udp_probes.get(inner_src_port)

                            if hop is None:
                                continue  # skip if we can't match hop number

                            if hop not in state.routers_by_hop:
                                state.routers_by_hop[hop] = []

                            if router_ip not in state.routers_by_hop[hop]:
                                state.routers_by_hop[hop].append(router_ip)

                        else: 
                            print(f"[DROP] ICMP for port {inner_src_port} "
          f"from router {router_ip} at time {icmp_time:.6f} "
          f"-> no matching UDP send")




                # Destination unreachable, final hop 
                if icmp_type == 3: 
                    if inner_ip.protocol == 17:
                        
                        if inner_src_port in state.udp_sent:
                        
                            # store ICMP return time indexed by source port
                            state.icmp_times[inner_src_port] = icmp_time
                            # state.final_replies.add(inner_src_port)
                            state.icmp_router[inner_src_port] = state.dst_ip 

                            state.final_replies.add(inner_src_port)


            elif p_packet.protocol == 17:   # UDP 
                udp = p_packet.payload
                ttl = p_packet.ttl
                udp_hdr = p_packet.payload[:8]
                src_port = int.from_bytes(udp_hdr[0:2], "big")
                

                if is_traceroute_udp(p_packet, udp):
                    if state.src_ip == None and state.dst_ip == None: 
                        state.src_ip = p_packet.src_ip
                        state.dst_ip = p_packet.dst_ip
                    if src_port == 60094:
                        print("FOUND UDP 60094 at timestamp", relative_ts)
                    state.udp_sent[src_port] = relative_ts
                    state.udp_probes[src_port] = ttl






    

def main(): 

    # open pcap file
    if len(sys.argv) != 2:
            print('Usage: python3 a3.py <pcap file>')
            sys.exit(1)

    state = TracerouteState()

    # parse the traceroute file
    traceroute_file = sys.argv[1]
    parse_pcap(traceroute_file, state)

    # output 
    print(f"The IP address of the source node: {state.src_ip}")
    print(f"The IP address of ultimate destination node: {state.dst_ip}")
    print_intermediate_nodes(state)

    print("The values in the protocol field of IP headers:")
    for proto in sorted(state.protocols):
        print(f"{proto}: {state.protocol_name(proto)}")
    print_fragment_results(state)

    # computer relative times 
    finalize_udp_timestamps(state)
    compute_rtts(state)
    # ouput RTT results 
    print_rtt_results(state)



if __name__ == "__main__": 
    main()