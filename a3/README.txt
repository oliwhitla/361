A3.py 

run code: 

python3 a3.py <insert capture file> 

example: python3 a3.py group1-trace1.pcap


File Structure: 
a3.py                    
IP_parser.py             
TracerouteState.py       
README.txt        

Error I can't seem fix: 

PCAP file actually contains multiple traceroute cycles, and traceroute reuses the same set of 
UDP ports in later cycles. 
Because my code initially recorded packets from a later cycle, 
the earlier ICMP replies (from ~7 seconds into the capture) were being matched against 
UDP probes sent ~900 seconds later, causing valid probes to not match 



