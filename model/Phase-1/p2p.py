import subprocess

meta = {}
connections = set()

class Features:
    def __init__(self, ip):
        self.ret = 0
        self.div = 0
        self.div_r = 0
        self.num_connection = 0
        self.dis_IP = 0
        self.res_pkt = 0
        self.out_of_order = 0
        self.icmp = 0
        self.pkts = 0
        self.fwd_bytes = 0
        self.bkd_bytes = 0
        self.avg_ret = 0
        self.dup_ack = 0
        self.cntrl = 0

def utils(ip):
    sp = ip.split('.')
    res = str(sp[0]) + str(sp[1])
    return res

def Update_fet():
    global par
    f = False
    ret=[]
    n=len(par)
    for i in range(len(par)):
        if par[i] == '\xe2\x86\x92' and not f:
            f = True
        elif par[i] == '\xe2\x86\x92' and i+2 < n:
            ret.append(par[i-1])
            ret.append(par[i+1])
            break
    if ret:
        sport = ret[0]
        dport = ret[1]
        todat = [par[4], sport, dport, par[5]]
        connections.add(todat)
    return


def Update():
    file = open("Phase_a.csv","a+")
    for i in meta:
        curr = meta[i]
        for j in curr:
            ref = curr[j]
            ref.div = len(dis_ip_r)
            ref.div_r = len(dis_ip)/len(dis_ip_r)
            if var1 != 0:
                ref.bkd_bytes = var2/var1
            if var3 != 0:
                ref.fwd_bytes = var4/var3
            ref.num_connection = len(connections)
            line = str(ref.ret) + "," + str(ref.div) + "," + str(ref.div_r) + "," + str(ref.num_connection) + "," + str(ref.dis_IP) + "," + str(ref.res_pkt) + "," + str(ref.out_of_order) + "," + str(ref.icmp) + "," + str(ref.pkts) + "," + str(ref.fwd_bytes) + "," + str(ref.bkd_bytes) + "," + str(ref.avg_ret) + "," + str(ref.dup_ack) + "," + str(ref.cntrl)		
            line = line[:-1]
            line += "\n"
            file.write(line)	
    file.close()

var1 = var2 = var3 = var4 = 0
dis_ip = set()
dis_ip_r = set()
ips = set()

cmd1 = "tshark -r Training.pcap -Y 'ip.version==4'"
process1 = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)	
for line in iter(process1.stdout.readline, ''):
    line = line.decode('utf-8')
    if len(line) == 0:
        break
    par = line.split()	
    ip = par[2]
    features = meta[(int)(float(par[1]))/6000] = {}
    features[ip] = Features(ip)
    ref = features[ip]
    var1 += 1
    dis_ip.add(par[4])
    dis_ip_r.add(utils(par[4]))
    if len(par)>7:
        var2 += int(par[6])
    if par[4] in features:
        ref = features[par[4]]
        var3 += 1
        if len(par)>7:
            var4 += int(par[6])
    Update_fet()

cmd2 = "tshark -r Training.pcap -Y 'ip.version==4&&((tcp.analysis.retransmission&&tcp.flags.syn==1)||tcp.analysis.duplicate_ack||tcp.analysis.out_of_order||tcp.flags.reset==1||icmp.type==3)'"
process2 = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)	
for line in iter(process2.stdout.readline, ''):
    line = line.decode('utf-8')
    par = line.split()	
    if len(line) == 0:
        break
    ip = par[2]
    features = meta[(int)(float(par[1]))/6000]
    if ip in features:
        ref = features[ip]
        for tok in par:
            if "Retransmission" in tok:
                ref.ret += 1
                ref.avg_ret += 1
            if tok == "Dup":
                ref.dup_ack+=1
            if "RST" in tok:
                ref.res_pkt += 1
            if "Out-Of-Order" in tok:
                ref.out_of_order += 1
            if tok == "ICMP":
                ref.icmp += 1
        if par[4] in features:
            data = features[ip]
            if "ICMP" in par:
                ref.icmp += 1


cmd3 = "tshark -r Training.pcap -Y 'ip.version==4&&(!data.data)'"
process3 = subprocess.Popen(cmd3, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)	
for line in iter(process2.stdout.readline, ''):
    line = line.decode('utf-8')
    if len(line) == 0:
        break
    par = line.split()	
    ip = par[2]
    features = meta[(int)(float(par[1]))/6000]
    if ip in features:
        ref = features[ip]
        ref.cntrl += 1

Update()