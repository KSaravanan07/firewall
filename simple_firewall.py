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
import binascii
from colorama import Fore

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
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15 )*4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) 
    data = raw_data[header_length:]
    src = '.'.join(map(str, src))
    target = '.'.join(map(str, target))
    
    if src == '192.168.102.215' or target == '192.168.101.144':         # to vm1
    	print("SENT TO VM111111111111111111111")
    	dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', old_data[:14])
    	dest_mac = binascii.unhexlify("52:54:00:cd:29:41".replace(':', ''))
    	new_data = struct.pack('! 6s 6s H', dest_mac, src_mac, type_mac)
    	new_data = new_data + old_data[14:]
    elif src == '192.168.101.144' or target == '192.168.102.215':
    	print("SENT TO VM222222222222222222222")
    	dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', old_data[:14])
    	dest_mac = binascii.unhexlify("52:54:00:5d:5a:74".replace(':', ''))
    	new_data = struct.pack('! 6s 6s H', dest_mac, src_mac, type_mac)
    	new_data = new_data + old_data[14:]
    else:
    	print("SENT TO INTERNEEEEEEEEEEEETTTTT")
    	
    	dest_mac, src_mac, type_mac = struct.unpack('! 6s 6s H', old_data[:14])
    	dest_mac = binascii.unhexlify("52:54:00:cd:29:41".replace(':', ''))
    	src_mac = binascii.unhexlify("52:54:00:5d:5a:74".replace(':', ''))
    	
    	new_data = struct.pack('! 6s 6s H', dest_mac, src_mac, type_mac)
    	
    	new_data = new_data + old_data[14:]
    	
    return version, header_length, ttl, proto, src, target, data, new_data

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
    new_pkg = raw_data
    pkg = {}
    eth = ethernet_header(raw_data)
    e_pkg = {}
    i_pkg = {}
    t_pkg = {}
    e_pkg["Destination MAC"] = eth[0]
    e_pkg["Source MAC"] = eth[1]
    pkg["ETHERNET"] = e_pkg

    if eth[2] == 2048:
        ipv4 = ipv4_header(eth[3], raw_data)
        new_pkg = ipv4[7]
        i_pkg["Source IP"] = ipv4[4]
        i_pkg["Destination IP"] = ipv4[5]    
        pkg["IP"] = i_pkg
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

    return pkg, new_pkg

# sends the packets to destination(VM) if it is allowed, i.e, rule is set to true.
def vm_1_inf(inf1, inf2):
    
    while True:
        dropped = False
        raw_data = inf1.recvfrom(65535)
        pkg, new_raw = packet_parse(raw_data[0])
        for i in pkg:
            print(i + ":")
            for j in pkg[i]:
                if str(pkg[i][j]) == '188.166.104.231':
                    print("\033[1;31m" + j + ": " + str(pkg[i][j]), end = '\t')    
                    print("\033[1;32m")
                    dropped = True
                else:
                    print("\033[1;32m" + j + ": " + str(pkg[i][j]), end = '\t')
            print('\n')    
        print("\033[1;32m ==========================")
        if(not dropped):
            inf2.sendall(new_raw)

#sends the packets to destination(VM) if it is allowed, i.e, rule is set to true.           
def vm_2_inf(inf1, inf2):
    
    while True:
        dropped = False
        raw_data = inf1.recvfrom(65535)
        pkg, new_raw = packet_parse(raw_data[0])
        for i in pkg:
            print(i + ":")
            for j in pkg[i]:
                if str(pkg[i][j]) == '188.166.104.231':
                    print("\033[1;31m" + j + ": " + str(pkg[i][j]), end = '\t')    
                    print("\033[1;32m")
                    dropped = True
                else:
                    print("\033[1;32m" + j + ": " + str(pkg[i][j]), end = '\t')
            print('\n')    
        print("\033[1;32m ==========================")
        if(not dropped):
            inf2.sendall(new_raw)


 # taking interface names as input
interface_1 = sys.argv[1]
interface_2 = sys.argv[2]

ETH_P_ALL = 3
action = 0      # action = 0 drop and
                # action = 1 pass through 
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

ifr1 = ifreq()
ifr1.ifr_ifrn = bytes(interface_1, 'UTF-8')

ifr2 = ifreq()
ifr2.ifr_ifrn = bytes(interface_2, 'UTF-8')

#create and bind socket
s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s1.bind((interface_1, 0))

s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s2.bind((interface_2, 0))

 # G for Get
fcntl.ioctl(s1.fileno(), SIOCGIFFLAGS, ifr1)
fcntl.ioctl(s2.fileno(), SIOCGIFFLAGS, ifr2)

ifr1.ifr_flags |= IFF_PROMISC
ifr2.ifr_flags |= IFF_PROMISC

# S for Set
fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr1) 
fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr2)

print("Firewall is Running ")

#declare two threads, start them and run them parallely. Thread t1 wil run the function vm_1_inf and thread 2 will run vm_2_inf
try:
    t1 = threading.Thread(target = vm_1_inf, args = (s1,s2,) )
    t1.start()
    t2 = threading.Thread(target = vm_2_inf, args = (s2,s1,) )
    t2.start()
    t1.join()
    t2.join()
finally:
    ifr1.ifr_flags &= ~IFF_PROMISC
    fcntl.ioctl(s1.fileno(), SIOCSIFFLAGS, ifr1)
    s1.close()
    ifr2.ifr_flags &= ~IFF_PROMISC
    fcntl.ioctl(s2.fileno(), SIOCSIFFLAGS, ifr2)
    s2.close()
 


