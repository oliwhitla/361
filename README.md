# 361

Resubmission of 361: 

Run code: 
python3 a3.py insert capture file 

example: python3 a3.py group1-trace1.pcap

The code crashed because I used the wrong type hints. Ex. var: dict[int, int] is not allowed -> changed to var: dict

For reference the affect line were changed to: 

udp_sent: dict = field(default_factory=dict)

icmp_times: dict = field(default_factory=dict) # src_port -> icmp_time

icmp_router: dict= field(default_factory=dict)

sent_times_by_port: dict = field(default_factory=dict)

rtts_by_router: dict = field(default_factory=dict)

rtts_to_dest: list = field(default_factory=list)

final_replies: set= field(default_factory=set) # src_ports that got type 3

