# TracerouteState.py

import struct
import math
from dataclasses import dataclass, field
from collections import defaultdict

@dataclass
class TracerouteState:
    PROTO_NAMES = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }
    
    src_ip = None
    dst_ip = None
    udp_probes = {}           # port -> ttl
    routers_by_hop = defaultdict(list)
    protocols = set()
    fragments = {}


    first_ts = None 

    # raw_udp_times: list[tuple[float, int, int]] = field(default_factory=list)  # (ts, src_port, ttl)
    # sent_times_by_port: dict[int, list[tuple[float, int]]] = field(default_factory=dict)  # src_port -> [(rel_time, ttl)]
    udp_sent: dict = field(default_factory=dict)
    icmp_times: dict = field(default_factory=dict)  # src_port -> icmp_time
    icmp_router: dict= field(default_factory=dict)
    
    sent_times_by_port: dict = field(default_factory=dict)
    rtts_by_router: dict = field(default_factory=dict)
    rtts_to_dest: list = field(default_factory=list)
    final_replies: set= field(default_factory=set)  # src_ports that got type 3
    
    def protocol_name(self, proto_num):
        return self.PROTO_NAMES.get(proto_num, "Unknown")


    # def compute_rtts(state):
    #     for src_port, send_list in state.sent_times_by_port.items():
    #         if src_port not in state.icmp_times_by_port:
    #             continue
                
    #         icmp_time = state.icmp_times_by_port[src_port]
            
    #         # Final destination
    #         if src_port in state.final_replies:
    #             for send_time, ttl in send_list:
    #                 state.rtts_to_dest.append(icmp_time - send_time)
    #             continue
            
    #         # Intermediate hops - match to specific router that responded
    #         if src_port in state.icmp_router_by_port:
    #             router_ip = state.icmp_router_by_port[src_port]
    #             for send_time, ttl in send_list:
    #                 rtt_ms = (icmp_time - send_time)
    #                 state.rtts_by_router.setdefault(router_ip, []).append(rtt_ms)


    # def compute_rtts(state):
    #     for src_port, send_list in state.sent_times_by_port.items():
    #         if src_port not in state.icmp_times_by_port:
    #             continue
                
    #         icmp_time = state.icmp_times_by_port[src_port]
            
    #         # Final destination hop (ICMP type 3)
    #         if src_port in state.final_replies:
    #             for send_time, ttl in send_list:
    #                 state.rtts_to_dest.append(icmp_time - send_time)
    #             continue
            
    #         # Intermediate hops (ICMP type 11)
    #         for send_time, ttl in send_list:
    #             if ttl in state.routers_by_hop:
    #                 for router_ip in state.routers_by_hop[ttl]:
    #                     state.rtts_by_router.setdefault(router_ip, []).append(
    #                         (icmp_time - send_time) 
    #                     )



