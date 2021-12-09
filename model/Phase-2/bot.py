import pyshark
import numpy as np
import re
import sys

'''
F1 : mean_inter_time
F2 : fwd_pkt
F3 : bkd_pkt
F4 : frwd_bytes
F5 : bkd_bytes
F6 : total_data
F7 : small_pkt
F8 : large_pkt
F9 : max_inter_time
F10 : min_inter_time
F11 : total_duration
F12 : pkt_frequency
F13 : mean_fwd_inter_time
F14 : mean_bkd_inter_time
F15 : max_fwd_inter_time
F16 : min_fwd_inter_time
F17 : max_bkd_inter_time
F18 : min_bkd_inter_time
label = 1 : malicious :: 0 : benign 
'''

mal_ips = ['192.168.2.112',	'131.202.243.84', '192.168.5.122','198.164.30.2', '192.168.2.110', '192.168.4.118','192.168.2.113', '192.168.1.103', '192.168.4.120', '192.168.2.112',
'192.168.2.109', '192.168.2.105','147.32.84.180', '147.32.84.170', '147.32.84.150', '147.32.84.140','147.32.84.130', '147.32.84.160',
'10.0.2.15', '192.168.106.141',	'192.168.106.131', '172.16.253.130', '172.16.253.131', '172.16.253.129', 
'172.16.253.240', '74.78.117.238', '158.65.110.24', '192.168.3.35',	'192.168.3.25',	'192.168.3.65',
'172.29.0.116',	'172.29.0.109',	'172.16.253.132','192.168.248.165',	'10.37.130.4']	

def Update_fwd(ip, index, pkt, prot_str, last_time):
    global start_time
    F1[index] += float(pkt.sniff_timestamp) - last_time
    F2[index] += 1
    if "TCP" in prot_str:
        F4[index] += int(pkt.layers[prot_str.index("TCP")].len)
    elif "UDP" in prot_str:
        F4[index] += int(pkt.layers[prot_str.index("UDP")].length)
    F6[index] += int(pkt.length)
    F7[index] = min(int(pkt.length), F7[index])
    F8[index] = max(int(pkt.length), F8[index])
    F9[index] =  max(float(pkt.sniff_timestamp) - last_time, F9[index])
    F10[index] = min(float(pkt.sniff_timestamp) - last_time, F10[index])
    F11[index] = float(pkt.sniff_timestamp)- start_time
    F13[index] += float(pkt.sniff_timestamp) - last_time
    F15[index] = max(float(pkt.sniff_timestamp) - last_time, F15[index])
    F16[index] = min(float(pkt.sniff_timestamp) - last_time, F16[index])
    if ip in mal_ips:
        labels[index] = 1



def Update_bwd(index, pkt, prot_str, last_time):
    global start_time
    F1[index] += float(pkt.sniff_timestamp) - last_time
    F3[index] += 1
    if "TCP" in prot_str:
        F5[index] += int(pkt.layers[prot_str.index("TCP")].len)
    elif "UDP" in prot_str:
        F5[index] += int(pkt.layers[prot_str.index("UDP")].length)
    F6[index] += int(pkt.length)
    F7[index] = min(int(pkt.length), F7[index])
    F8[index] = max(int(pkt.length), F8[index])
    F9[index] =  max(float(pkt.sniff_timestamp) - last_time, F9[index])
    F10[index] = min(float(pkt.sniff_timestamp) - last_time, F10[index])
    F11[index] = float(pkt.sniff_timestamp)- start_time
    F13[index] += float(pkt.sniff_timestamp) - last_time
    F14[index] += float(pkt.sniff_timestamp) - last_time
    F17[index] = max(float(pkt.sniff_timestamp) - last_time, F17[index])
    F18[index] = min(float(pkt.sniff_timestamp) - last_time, F18[index])
 
MX_SIZE = 53687091
IP = []
Feature = []
F14 = F13 = F12 = F11 = F6 = F5 = F4 = F3 = F2 = F1 = [0]*MX_SIZE
F18 = F16 = F10 = F7 = [sys.maxsize]*MX_SIZE
F17 = F15 = F9 = F8 = [-sys.maxsize-1]*MX_SIZE
labels = [0]*MX_SIZE

# Function to extract all ip addresses 
ips = set()
def extract(text):
    pat = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    matches = re.findall(pat, text) 
    for ip in matches: ips.add(ip)
    return matches

capture = pyshark.FileCapture('Training.pcap', display_filter='ip.version==4')

for pkt in capture:
    extract(str(pkt))

# packet feature extraction
global start_time
start_time = float(capture[0].sniff_timestamp)
long_lst = []
cnt = 0
for pkt in capture:
    
    last_time = float(pkt.sniff_timestamp)
    # A network flow is uniquely identified by <source IP, source port, destination IP, destination port, protocol>

    prot_str = re.findall(r"([a-zA-Z0-9]*)\sLayer", str(pkt.layers))
    if "TCP" in prot_str:
        curr_list = [pkt.ip.src, pkt.ip.dst, pkt.tcp.srcport, pkt.tcp.dstport]
    if "UDP" in prot_str:
        curr_list = [pkt.ip.src, pkt.ip.dst, pkt.udp.srcport, pkt.udp.dstport]

    if curr_list not in long_lst:
        cnt += 1
        long_lst.append(curr_list)
    
    Update_fwd(pkt.ip.src, long_lst.index(curr_list), pkt, prot_str, last_time)
    Update_bwd(long_lst.index(curr_list), pkt, prot_str, last_time)

file = open("Phase_b(t).csv","a+")
for i in range(cnt):
    if F2[i] + F3[i] != 0:
        F1[i] = F1[i]/(F2[i] + F3[i])
    if F2[i] != 0:
        F13[i] = F13[i]/F2[i]
    if F3[i] != 0:
        F14[i] = F14[i]/F3[i]
    line = str(long_lst[i][0]) + "," + str(F1[i]) + "," + str(F2[i]) + "," + str(F3[i]) + "," + str(F4[i]) + "," + str(F5[i]) + "," + str(F6[i]) + "," + str(F7[i]) + "," + str(F8[i]) + "," + str(F9[i])+ "," + str(F10[i]) + "," + str(F11[i]) + "," + str(F12[i])+ "," + str(F13[i]) + "," + str(F14[i]) + "," + str(F15[i])+ "," + str(F16[i]) + "," + str(F17[i])+ "," + str(F18[i])	
    line = line[:-1]
    line += "\n"
    file.write(line)	
file.close()  