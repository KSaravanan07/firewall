import socket 
import sys
import socket 
import sys
import os
import ctypes
import fcntl
import threading
import struct  
import json 
import colorama
import codecs
import copy
import binascii
import time
from colorama import Fore
import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt

dos_threshold = 0 # sets the threshold limit for DOS attack
dos_attack = {} # holds the count of each IP address

rule_list = [] # stores the list of rules added to restrict the different fields
accepted_list = [] # holds the list of accepted packets
discarded_list = [] # holds the list of discarded packets
time_list = [] # holds the time passed in seconds

accepted_count = 0 # holds the count of accepted packets
discarded_count = 0 # holds the count of discarded packets
to_print = True # boolean to manage the prininting of packet information


class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16), ("ifr_flags", ctypes.c_short)]



# extracts destination mac, source mac, type and payload from packets received.
def ethernet_header(raw_data):   
    dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = dest_mac.hex(':')
    src_mac = src_mac.hex(':')
    data = raw_data[14:]
    return dest_mac, src_mac, type_mac, data

# changes the destination mac address for firewall's to desired VM and returns the new data packet along with some other fileds.
def ipv4_header(raw_data, old_data):
    global dos_attack
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15 )*4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) 
    # storing the payload of IP header
    data = raw_data[header_length:]
    src = '.'.join(map(str, src))   
    flag = 1
    # if any IP is not present in the DOS attack dictionary then add it and set count to 1 otherwise increase the count
    for p in dos_attack:
        if(p == src):
            dos_attack[src]=dos_attack[src]+1
            flag=0
    if(flag!=0):
        dos_attack[src] = 1
    target = '.'.join(map(str, target))    
    # if the packet is directed to VM1 change the MAC address field in the ethernet header to that of VM1
    if src == '192.168.102.215' or target == '192.168.101.144':         # to vm1
        #print("SENT TO VM111111111111111111111")
        dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', old_data[:14])
        dest_mac = binascii.unhexlify("52:54:00:cd:29:41".replace(':', ''))
        new_data = struct.pack('! 6s 6s H', dest_mac, src_mac, type_mac)
        # appending the new ethernet header with its payload
        new_data = new_data + old_data[14:]
        
    # if the packet is directed to VM1 change the MAC address field in the ethernet header to that of VM1
    elif src == '192.168.101.144' or target == '192.168.102.215':       # to vm2
    	#print("SENT TO VM222222222222222222222")
    	dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', old_data[:14])
    	dest_mac = binascii.unhexlify("52:54:00:5d:5a:74".replace(':', ''))
    	new_data = struct.pack('! 6s 6s H', dest_mac, src_mac, type_mac)
        # appending the new ethernet header with its payload
    	new_data = new_data + old_data[14:]

    else:
    	#print("SENT TO INTERNEEEEEEEEEEEETTTTT")
    	dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', old_data[:14])
    	#dest_mac = binascii.unhexlify("52:54:00:5d:5a:74".replace(':', ''))
    	#src_mac = binascii.unhexlify("52:54:00:cd:29:41".replace(':', ''))
    	new_data = struct.pack('! 6s 6s H', dest_mac, src_mac, type_mac)
        # appending the new ethernet header with its payload
    	new_data = new_data + old_data[14:]

    return version, header_length, ttl, proto, src, target, data, new_data

# extracting the IPV6 header from the packet
def ipv6_header(raw_data):
     
    ipv6_traffic_class = raw_data[0]
    # first four bits represents version
    ipv6_ver = ipv6_traffic_class >> 4

    # extract traffic class , that indicates class or priority of IPv6 packet
    traffic_class1 = (ipv6_traffic_class & 15) << 4
    traffic_class_flow_label = raw_data[1]
    traffic_class2 = (traffic_class_flow_label & 240) >> 4
    traffic_class = traffic_class1 + traffic_class2

    # data length
    data_length = (raw_data[4] << 8) + raw_data[5]

    #extract flow label that indicates that this packet belongs to a specific sequence of packets between a source and destination, requiring special handling by intermediate IPv6 routers.(20 bits)
    flow_label1 = (traffic_class_flow_label & 15) << 16
    flow_label2 = raw_data[2] << 8
    flow_label = flow_label1 + flow_label2 + raw_data[3]
   
    # Indicates either the first extension header (if present) or the protocol in the upper layer PDU (such as TCP, UDP, or ICMPv6).(8 bits)
    next_header = raw_data[6]

    # Indicates the maximum number of links over which the IPv6 packet can travel before being discarded.(8 bits)
    hop_limit = raw_data[7]

    #Pv6 address of the originating host. (128 bits)
    source = raw_data[8:24]

    #IPv6 address of the current destination host (128 bits)
    dst = raw_data[24:40]
    
    data = raw_data[40:0]

    return ipv6_ver, traffic_class, flow_label, data_length, next_header, hop_limit, source, dst, data

# extracting the TCP header fields from the packet
def tcp_header(raw_data):
    (src_port, dest_port, sequence, acknowledgment, hlen_reserved_flags) =struct.unpack('! H H L L H', raw_data[:14])
    hlen = (hlen_reserved_flags >> 12) * 4
    flag_urg = (hlen_reserved_flags & 32) >> 5
    flag_ack = (hlen_reserved_flags & 16) >> 4
    flag_psh = (hlen_reserved_flags & 8) >> 3
    flag_rst = (hlen_reserved_flags & 4) >> 2
    flag_syn = (hlen_reserved_flags & 2) >> 1
    flag_fin = hlen_reserved_flags & 1
    data = raw_data[hlen:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

#extracts type, code, checksum 
def icmp_header(raw_data):
    type1, code, check_sum, other = struct.unpack('! s s 2s 4s', raw_data[:8])
    type1 = ''.join(map(str, type1)) 
    code = ''.join(map(str, code)) 
    return type1, code, check_sum, other

#extracts source, destination port , length and checksum from UDP header
def udp_header(raw_data):
    st = struct.unpack('! H H H H',raw_data[:8])
    sport = st[0]
    dport = st[1]
    length = st[2]
    checksum = st[3]
    return sport, dport, length, checksum

#checks whether the packet is of type TCP/UDP/ICMP and stores the corresponding field values and returns the same. It also returns the new packet,i.e, the packet with MAC of VM2.
def packet_parse(raw_data):
    #print("\n ----------------------------------------------inside parse")
    new_pkg = raw_data
    pkg = {}
    # extracting the ethernet header from the packet captured
    eth = ethernet_header(raw_data)

    # storing important header fields of different headers
    e_pkg = {} # stores ethernet header fields
    i_pkg = {} # stores IP header fields
    t_pkg = {} # stores TCP, UDP or ICMP header
    e_pkg["Destination MAC"] = eth[0]
    e_pkg["Source MAC"] = eth[1]
    pkg["ETHERNET"] = e_pkg
    p_type = 0
    if int(eth[2]) == 2048:
        ipv4 = ipv4_header(eth[3], raw_data)
        new_pkg = ipv4[7] # packet with modified header fields (needs to be sent to the second host)
        i_pkg["Source IPV4"] = ipv4[4]
        i_pkg["Destination IPV4"] = ipv4[5]  
        pkg["IP"] = i_pkg
        p_type = ipv4[3]
        if ipv4[3] == 6:        #tcp        
            tcp = tcp_header(ipv4[6])
            t_pkg["Source Port"] = tcp[0]
            t_pkg["Destination Port"] = tcp[1]
            pkg["TCP"] = t_pkg
        elif ipv4[3] == 1:      #icmp
            icmp = icmp_header(ipv4[6])
            t_pkg["Code"] = icmp[1]
            t_pkg["Type"] = icmp[0]
            pkg["ICMP"] = t_pkg
        elif ipv4[3] == 17:     #udp 
            udp = udp_header(ipv4[6])
            t_pkg["Source Port"] = udp[0]
            t_pkg["Destination Port"] = udp[1]
            pkg["UDP"] = t_pkg

    return pkg, new_pkg, p_type


#sends the packets to destination(VM) if it is allowed, i.e, rule is set to true.
def vm_1_inf(inf1, inf2):
    global accepted_count
    global discarded_count
    global to_print
    while True:
        dropped = False
        # receiving packets from interface 1
        raw_data = inf1.recvfrom(65535)
        # pkg stores the needful fields extracted from different headers and new_raw is the new packet generated
        pkg, new_raw, p_type = packet_parse(raw_data[0])  
        
        
        if check_rule(pkfg, p_type): 
            if(to_print):
                print("\nPacket Discarded")   
                print("\033[1;32m")
            dropped = True
            discarded_count = discarded_count + 1
        else:
            if(to_print):
                print("\033[1;32m")
        if(to_print):
            print("\033[1;32m ==================================================================================")
        if(not dropped):
            if(to_print):
                print("\033[1;32m")
            accepted_count = accepted_count + 1
            if len(new_raw) < 1500 :
                inf2.sendall(new_raw)
'''
# sends the packets to destination(VM) if it is allowed, i.e, rule is set to true.
def vm_1_inf(inf1, inf2):
    global accepted_count
    global discarded_count
    global to_print
    curr_dos_attack = {}
    prev_dos_attack = {}
    dos_timer = time.time()
    threshold = 6
    while True:
        dropped = False
        # receiving packets from interface 1
        raw_data = inf1.recvfrom(65535)
        # pkg stores the needful fields extracted from different headers and new_raw is the new packet generated
        pkg, new_raw, p_type = packet_parse(raw_data[0])  
        if "IPV4" in pkg.keys():
            #print(prev_dos_attack)
            #print(curr_dos_attack)
            if pkg['IPV4']['Source IPV4'] in prev_dos_attack.keys():
                if(time.time() - dos_timer >= 2):
                    if((curr_dos_attack[pkg['IPV4']['Source IPV4']] - prev_dos_attack[pkg['IPV4']['Source IPV4']]) > threshold):
                        dos_timer = time.time()
                        if(to_print):
                            print("DOS Detected")
                    
                    prev_dos_attack[pkg['IPV4']['Source IPV4']] = copy.deepcopy(curr_dos_attack[pkg['IPV4']['Source IPV4']])
                curr_dos_attack[pkg['IPV4']['Source IPV4']] = curr_dos_attack[pkg['IPV4']['Source IPV4']] + 1
                
            else:
                prev_dos_attack[pkg['IPV4']['Source IPV4']] = 1
                curr_dos_attack[pkg['IPV4']['Source IPV4']] = 1
                    
        if check_rule(pkg, p_type): 
            if(to_print):
                print("Packet Discarded")   
                print("\033[1;32m")
            dropped = True
            discarded_count = discarded_count + 1
        
        else:
            if(to_print):
                print("\n inside no drop vm1")
            # print("\033[1;32m" + j + ": " + str(pkg[i][j]), end = '\t')
        if(to_print):
            print("\033[1;32m =================================================================")
        if(not dropped):
            accepted_count = accepted_count + 1
            inf2.sendall(new_raw)
 '''           
# sends the packets to destination(VM) if it is allowed, i.e, rule is set to true.          
def vm_2_inf(inf1, inf2):
    global accepted_count
    global discarded_count
    global to_print
    while True:
        dropped = False
        raw_data = inf1.recvfrom(65535)
        pkg, new_raw, p_type = packet_parse(raw_data[0])
        if check_rule(pkg, p_type):        
            if(to_print): 
                print("\033[1;32m")
            dropped = True
            discarded_count = discarded_count + 1
        else:
            if(to_print):
                print("\033[1;32m")
        if(to_print):
            print("\033[1;32m ==================================================================================")
        if(not dropped):
            if(to_print):
                print("\033[1;32m")
            accepted_count = accepted_count + 1
            if len(new_raw) < 1500 :
                inf2.sendall(new_raw)
'''
# sends the packets to destination(VM) if it is allowed, i.e, rule is set to true.   
def vm_2_inf(inf1, inf2):
    global accepted_count
    global discarded_count
    global to_print

    curr_dos_attack = {}
    prev_dos_attack = {}
    dos_timer = time.time()
    threshold = 6
    while True:
        dropped = False
        raw_data = inf1.recvfrom(65535)
        pkg, new_raw, p_type = packet_parse(raw_data[0])
        
        if "IPV4" in pkg.keys():
            if pkg['IPV4']['Source IPV4'] in prev_dos_attack.keys():
                if(time.time() - dos_timer >= 2):
                    if((curr_dos_attack[pkg['IPV4']['Source IPV4']] - prev_dos_attack[pkg['IPV4']['Source IPV4']]) > threshold):
                        dos_timer = time.time()
                        if(to_print):
                            print("DOS Detected")
                    
                    prev_dos_attack[pkg['IPV4']['Source IPV4']] = copy.deepcopy(curr_dos_attack[pkg['IPV4']['Source IPV4']])
                curr_dos_attack[pkg['IPV4']['Source IPV4']] = curr_dos_attack[pkg['IPV4']['Source IPV4']] + 1
                
            else:
                prev_dos_attack[pkg['IPV4']['Source IPV4']] = 1
                curr_dos_attack[pkg['IPV4']['Source IPV4']] = 1
        if check_rule(pkg, p_type):  
            if(to_print): 
                print("\033[1;32m")
            dropped = True
            discarded_count = discarded_count + 1
        else:
            if(to_print):
                print("\033[1;32m")
        if(to_print):
            print("\033[1;32m =================================================================")
        if(not dropped):
            if(to_print):
                print("\033[1;32m")
            accepted_count = accepted_count + 1
            inf2.sendall(new_raw)
'''

# makes two socket object and binds them to interface 1 and interface 2. Then start two thread that will call vm_1_inf and vm_2_inf functions so that both VM's can send packets to each other.
def start_firewall(interface_1, interface_2):
    
    global to_print
    ETH_P_ALL = 3
    action = 0          # action = 0 drop and
                # action = 1 pass through 
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914

    ifr1 = ifreq()
    ifr1.ifr_ifrn = bytes(interface_1, 'UTF-8')

    ifr2 = ifreq()
    ifr2.ifr_ifrn = bytes(interface_2, 'UTF-8')

    s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s1.bind((interface_1, 0))

    s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s2.bind((interface_2, 0))

    fcntl.ioctl(s1.fileno(), SIOCGIFFLAGS, ifr1) # G for Get
    fcntl.ioctl(s2.fileno(), SIOCGIFFLAGS, ifr2)

    ifr1.ifr_flags |= IFF_PROMISC
    ifr2.ifr_flags |= IFF_PROMISC

    fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr1) # S for Set
    fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr2)

    print("Firewall is Running ")
    prev_accepted_count = 0
    prev_discarded_count = 0
    try:
        timer = time.time()
        #print('timer',timer)
        t1 = threading.Thread(target = vm_1_inf, args = (s1,s2,) )
        t1.start()
        t2 = threading.Thread(target = vm_2_inf, args = (s2,s1,) )
        t2.start()
        
        while True:
            try:
                curr_time = time.time()
                if curr_time - timer >= 1:
                    prev_accepted_count = accepted_count - prev_accepted_count
                    prev_discarded_count = discarded_count - prev_discarded_count
                    time_list.append(curr_time)
                    accepted_list.append(prev_accepted_count)
                    discarded_list.append(prev_discarded_count)
                    prev_accepted_count = accepted_count
                    prev_discarded_count = discarded_count
                    #print(accepted_list)
                    timer = time.time()
            except:
                #print("EXITEDDF")
                to_print = False
                time.sleep(1)
                t3 = threading.Thread(target = menu )
                t3.start()
            
    except:
        show_stat()

    finally:
        ifr1.ifr_flags &= ~IFF_PROMISC
        fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr1)
        s1.close()
        ifr2.ifr_flags &= ~IFF_PROMISC
        fcntl.ioctl(s2.fileno(), SIOCSIFFLAGS, ifr2)
        s2.close()


#Adds rule in rule_file.json. User can add rule to block a client based on IPV4, IPV6 address, or Port numbers or MAC address.
def add_rule(choice):

    rule = {}

    if choice == 1:

        idx = int(input('\nEnter a uniqe ID : '))
        rule["Rule ID"] = idx
        cal = input('\nChange Source MAC (0/1): ')
        if (int(cal) == 0):
            src_mac = " "
        else:
            src_mac = input('\nEnter the source MAC address you want to restrict :  ')
        rule['Source MAC'] = src_mac

        cal = input('\nChange Destination MAC (0/1): ')
        if (int(cal) == 0):
            des_mac = " "
        else:
            des_mac = input('\nEnter the destination MAC address you want to restrict :  ')
        rule["Destination MAC"] = des_mac
        rule["Source IPV4"] = " "
        rule["Destination IPV4"] = " "
        rule["Source IPV6"] = " "
        rule["Destination IPV6"] = " "
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Source Port"] = temp1
    
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Destination Port"] = temp1

        rule["ICMP Type"] = ""
        rule["ICMP Code"] = ""

    elif choice == 2:

        idx = int(input('\nEnter a uniqe ID : '))
        rule["Rule ID"] = idx
        rule["Source MAC"] = " "
        rule["Destination MAC"] = " "
        cal = input('\nChange Source IP (0/1)')
        if (int(cal) == 0):
            src_ip4 = " "
        else:
            src_ip4 = input('\nEnter the source IPV4 address you want to restrict :  ')
        rule["Source IPV4"] = src_ip4
        cal = input('\nChange Destination IP (0/1)')
        if (int(cal) == 0):
            des_ip4 = " "
        else:
            des_ip4 = input('\nEnter the destination IPV4 address you want to restrict :  ')
        rule["Destination IPV4"] = des_ip4
        rule["Source IPV6"] = " "
        rule["Destination IPV6"] = " "
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Source Port"] = temp1
    
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Destination Port"] = temp1
        rule["ICMP Type"] = ""
        rule["ICMP Code"] = ""

    elif choice == 3:

        idx = int(input('\nEnter a uniqe ID : '))
        rule["Rule ID"] = idx
        rule["Source MAC"] = " "
        rule["Destination MAC"] = " "
        rule["Source IPV4"] = " "
        rule["Destination IPV4"] = " "
        cal = input('\nChange Source IP (0/1)')
        if (int(cal) == 0):
            src_ip6 = " "
        else:
            src_ip6 = input('\nEnter the source IPV6 address you want to restrict :  ')
        rule["Source IPV6"] = src_ip6
        cal = input('\nChange Destination IP (0/1)')
        if (int(cal) == 0):
            des_ip6 = " "
        else:
            des_ip6 = input('\nEnter the destination IPV6 address you want to restrict :  ')
        rule["Destination IPV6"] = des_ip6
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Source Port"] = temp1
    
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Destination Port"] = temp1
        rule["ICMP Type"] = ""
        rule["ICMP Code"] = ""

    elif choice == 4 or choice == 5:
        
        idx = int(input('\nEnter a uniqe ID : '))
        rule["Rule ID"] = idx
        rule["Source MAC"] = " "
        rule["Destination MAC"] = " "
        rule["Source IPV4"] = " "
        rule["Destination IPV4"] = " "
        rule["Source IPV6"] = " "
        rule["Destination IPV6"] = " "
        cal = input("\nChange Source Port(0/1): ")
        if(int(cal) == 0):
            start_port = 0
            end_port = 0
        else:
            print('\nEnter the range of source Port you want to restrict (Enter same port if do not want to provide range): ')
            start_port = int(input('\nEnter starting port number : '))
            end_port = int(input('\nEnter ending port number : '))
        temp = {}
        temp["Start"] = start_port
        temp["End"] = end_port
        temp1 = []
        temp1.append(temp)
        rule["Source Port"] = temp1


        cal = input("\nChange Destination Port(0/1): ")    
        if(int(cal) == 0):
            start_port = 0
            end_port = 0
        else:
            print('\nEnter the range of destination Port you want to restrict (Enter same port if do not want to provide range): ')
            start_port = int(input('\nEnter starting port number : '))
            end_port = int(input('\nEnter ending port number : '))
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Destination Port"] = temp1
        rule["ICMP Type"] = ""
        rule["ICMP Code"] = ""

    elif choice == 6:

        idx = int(input('\nEnter a uniqe ID : '))
        rule["Rule ID"] = idx
        rule["Source MAC"] = " "
        rule["Destination MAC"] = " "
        rule["Source IPV4"] = " "
        rule["Destination IPV4"] = " "
        rule["Source IPV6"] = " "
        rule["Destination IPV6"] = " "
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Source Port"] = temp1
    
        temp = {}
        temp["Start"] = 0
        temp["End"] = 0
        temp1 = []
        temp1.append(temp)
        rule["Destination Port"] = temp1
        icmp_type = input('\nEnter the ICMPv4/v6 type : ')
        rule["ICMP Type"] = icmp_type
        icmp_code = input('\nEnter the ICMPv4/v6 code : ')
        rule["ICMP Code"] = icmp_code
    
    fl = open("new_rule_file.json",'r+')
    rule_list = json.load(fl)
    rule_list["rules"].append(rule)
    fl.seek(0)
    json.dump(rule_list,fl,indent = 4)
    fl.close()

# cheking the range of IP address if in different format (e.g.-x.w.*.*)
def check_range_IP(src,srcl):
    srcl = srcl.split('.')
    if(len(srcl) == 0 or len(src) == 0):
        return 1
    if srcl[0] == " ":
        return 1
    flag = 0
    count = 0
    for x in srcl:
        if(x == "*"):
            flag=0
            count += 1
        else:
            flag=1

    flag1=0
    if(not flag):
        print("Count ", count)
        for i in range(4-count):
            if(src[i] == srcl[i]):
                flag1=1
                continue
            else:
                flag1=0
                break
    else:
        if(src == srcl):
            flag1 = 1
    return flag1

# checks whether given packet is allowed to send. If it's MAC, IP or Port is blocked,i.e included in rule_file.json file than this function returns true.
def check_rule(pkg, p_type):
    global to_print
    f = open("new_rule_file.json","r")
    data = json.load(f)
    f.close()

    e_SRC_IP = " "
    e_DST_IP = " "
    e_SRC_PORT = -1
    e_DST_PORT = -1
    e_SRC_MAC = " "
    e_DST_MAC = " "
    flag=0
    flag1=0
    empty = 0
    empty1 = 0
    src = []
    dst = []
    # storing the header fields from the packet to match if any of the field is restricted
    for i in pkg:
        for j in pkg[i] :
            if j == 'Source IPV4':
                e_SRC_IP = str(pkg[i][j]) 
                if to_print:
                    print("\n"+j+"----"+e_SRC_IP)
                src = e_SRC_IP.split(".")
            if j == 'Destination IPV4':
                e_DST_IP = str(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+e_DST_IP)
                dst = e_DST_IP.split(".")
            if j == 'Source IPV6':
                e_SRC_IP = str(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+e_SRC_IP)
                src = e_SRC_IP.split(":") 
            if j == 'Destination IPV6':
                e_DST_IP = str(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+e_DST_IP)
                dst = e_DST_IP.split(":") 
            if j == 'Source Port':
                e_SRC_PORT = int(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+str(e_SRC_PORT))
            if j == 'Destination Port':
                e_DST_PORT = int(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+str(e_DST_PORT))
            if j == 'Source MAC':
                e_SRC_MAC = str(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+e_SRC_MAC)
            if j == 'Destination MAC':
                e_DST_MAC = str(pkg[i][j])
                if to_print:
                    print("\n"+j+"----"+e_DST_MAC)


    # matching each of the fields from the json file
    for rule in data["rules"]:
        if (check_range_IP(src,rule["Source IPV4"])):
            if (check_range_IP(src,rule["Source IPV6"])):
                if (check_range_IP(dst,rule["Destination IPV4"])):
                    if(check_range_IP(dst, rule["Destination IPV6"])):
                        if (e_SRC_MAC == rule["Source MAC"] or rule["Source MAC"] == " "):
                            if (e_DST_MAC == rule["Destination MAC"] or rule["Destination MAC"] == " "):
                                if (int(rule["Source Port"][0]["Start"]) <= e_SRC_PORT and e_SRC_PORT <= int(rule["Source Port"][0]["End"])  or int(rule["Source Port"][0]["End"]) == 0):
                                    if (int(rule["Destination Port"][0]["Start"]) <= e_DST_PORT and e_DST_PORT <= int(rule["Destination Port"][0]["End"]) or int(rule["Destination Port"][0]["End"]) == 0):
                                        #print("-----------------------dropped-------------------------------------------")
                                        return True

    return False

# checks the json file for the rule with given index, if yes than remove else do nothing
def delete_rule(idx):
    fl = open("new_rule_file.json",'r+')
    rule_list = json.load(fl)
    
    if len(rule_list["rules"]) == 0:
        print("There are no rules present in the file.")

    else :
        flag = False
        for headers in rule_list["rules"] :
            if headers["Rule ID"] == idx :
                rule_list["rules"].remove(headers)
                flag = True
                print("\nDeleted successfully")
        
        if not flag :
            print("\nRequested id not present")


    fl.seek(0)
    json.dump(rule_list,fl,indent = 4)
    fl.truncate()
    fl.close()


 # Updates the given rule based on user's input.       
def update_rule(id,choice):
    fl = open("new_rule_file.json","r+")
    data = json.load(fl)
    

    for rule in data["rules"]:
        if rule["Rule ID"] == id :
            if(choice == 1):
                src = input("\nEnter new source MAC")
                rule["Source MAC"] = src
            
            elif(choice==2):
                dst = input("\nEnter new destination MAC")
                rule["Destination MAC"] = dst
            
            elif(choice==3):
                src = input("\nEnter new source IPV4")
                rule["Source IPV4"] = src
                
            elif(choice==4):
                dst = input("\nEnter new destination IPV4")
                rule["Destination IPV4"] = dst

            elif(choice==5):
                src = input("\nEnter new source IPV6")
                rule["Source IPV6"] = src
            
            elif(choice==6):
                dst = input("\nEnter new destination IPV6")
                rule["Destination IPV6"] = dst

            elif(choice==7):
                print('\nEnter the range of source port you want to restrict (Enter same port if do not want to provide range): ')
                s_src = int(input("\nEnter the starting port : "))
                rule["Source Port"]["Start"] = s_src
                e_src = int(input("\nEnter the ending port : "))
                rule["Source Port"]["End"] = e_src

            elif(choice==8):
                print('\nEnter the range of destination port you want to restrict (Enter same port if do not want to provide range): ')
                s_dest = int(input("\nEnter the starting port : "))
                rule["Destination Port"]["Start"] = s_dest
                e_dest = int(input("\nEnter the ending port : "))
                rule["Destination Port"]["End"] = e_dest

    fl.seek(0)
    json.dump(data,fl,indent = 4)
    fl.truncate()
    fl.close()

# it shows the number of allowed and discarded packets with respect to time
def show_stat():
    print("No of packets allowed : ",accepted_count ,"\n")
    print("No of packets dropped : ",discarded_count,"\n")
    plt.plot(np.array(time_list),np.array(accepted_list))
    plt.plot(np.array(time_list),np.array(discarded_list))
    plt.xlabel("Time (Seconds)")
    plt.ylabel("No of Allowed/Discarded packet)")
    plt.title("Packets Processing")
    plt.legend(['Allowed','Discarded'])
    plt.savefig("allow_dis.png")

#
def cal_threshold(dos_threshold):
    k=1
    global dos_attack
    for i in dos_attack:
        if (dos_threshold < dos_attack[i]):
            k=0
    if(k==0):
        print("DOS Detected \n")
    else:
        print("DOS not Detected \n")
    
    print("Count of each IP Address \n")
    print(dos_attack)


def menu():
    global to_print
    print('\n1. Add rule')
    print('\n2. Delete rule')
    print('\n3. Update rule')
    print('\n4. Show statistics')
    print('\n5. Detect DOS attack')
    print('\n6. Exit')

    choice = int(input("Please enter your choice !! : "))
        
    if choice == 1 :
        
        print('\n1. Ethernet Header')
        print('\n2. IPV4 Header')
        print('\n3. IPV6 Header')
        print('\n4. TCP Header')
        print('\n5. UDP Header')
        print('\n6. ICMP Header')
        head_choice = int(input('\n Enter where you want to make changes : '))
        add_rule(head_choice)   

    elif choice == 2 :

        id =  int(input("Enter the rule id from where you want to delete : "))
        delete_rule(id)

    elif choice == 3 :
        id =  int(input("Enter the rule id from where you want to Update : "))
        
        print('\n1. Update Source MAC')
        print('\n2. Update Destination MAC')
        print('\n3. Update Source IPV4')
        print('\n4. Update Destination IPV4')
        print('\n5. Update Source IPV6')
        print('\n6. Update Destination IPV6')
        print('\n7. Update Source Port')
        print('\n8. Update Destination Port')
        choice = int(input('\n Enter where you want to make changes : '))
        update_rule(id,choice)

    elif choice == 4 :
        print('\nStatistics of Number of Acccepted/Discarded Packets Vs Time ')
        show_stat()

    elif choice == 5 :
        #sta = input("Want to Turn on DoS detection? (y/n)")
        #if(sta == "y"):
        dos_threshold = int(input("Enter new threshold limit : \n"))
        cal_threshold(dos_threshold)

    elif choice == 6:
        os._exit(0)
    to_print = True


def main():
    # taking interface names as input
    interface1 = sys.argv[1]
    interface2 = sys.argv[2]
    
    while True:
        print('\n1. Start firewall')
        print('\n2. Add rule')
        print('\n3. Delete rule')
        print('\n4. Update rule')
        print('\n5. Show statistics')
        print('\n6. Detect DOS attack')
        
        choice = int(input("Please enter your choice !! : "))
        
        if choice == 1 :
            start_firewall(interface1, interface2)

        elif choice == 2 :
            
            print('\n1. Ethernet Header')
            print('\n2. IPV4 Header')
            print('\n3. IPV6 Header')
            print('\n4. TCP Header')
            print('\n5. UDP Header')
            print('\n6. ICMP Header')
            head_choice = int(input('\n Enter where you want to make changes : '))
            add_rule(head_choice)   

        elif choice == 3 :

            id =  int(input("Enter the rule id from where you want to delete : "))
            delete_rule(id)

        elif choice == 4 :
            id =  int(input("Enter the rule id from where you want to Update : "))
            
            print('\n1. Update Source MAC')
            print('\n2. Update Destination MAC')
            print('\n3. Update Source IPV4')
            print('\n4. Update Destination IPV4')
            print('\n5. Update Source IPV6')
            print('\n6. Update Destination IPV6')
            print('\n7. Update Source Port')
            print('\n8. Update Destination Port')
            choice = int(input('\n Enter where you want to make changes : '))
            update_rule(id,choice)

        elif choice == 5 :
            print('\nStatistics of Number of Acccepted/Discarded Packets Vs Time ')
            show_stat()

        elif choice == 6 :
            #sta = input("Want to Turn on DoS detection? (y/n)")
            #if(sta == "y"):
            dos_threshold = int(input("Enter new threshold limit : \n"))
            cal_threshold(dos_threshold)


main()


