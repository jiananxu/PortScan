# /usr/bin/python
# coding:utf-8

from logging import getLogger, ERROR  # Import Logging Things


getLogger("scapy.runtime").setLevel(ERROR)  # Get Rid if IPv6 Warning
from scapy.all import *  # The One and Only Scapy
from scapy.layers.inet import IP, ICMP, TCP
import sys
from datetime import datetime  # Other stuff
from time import strftime

SYNACK = 0x12  # Set flag values for later reference
RSTACK = 0x14

#input data
dest_ip = "10.254.63.196"
# dest_ip = "www.baidu.com"
# s_ip = "172.33.8.1"
# e_ip = "172.33.8.255"
# ip = s_ip+"-"+e_ip
# print(ip)
# min_port = 0
# max_port = 80

def checkhost(ip):  # Function to check if target is up
    conf.verb = 0  # Hide output
    try:
        ping = sr1(IP(dst=ip) / ICMP())  # Ping the target
        print(ping)
        print( "\n[*] Target is Up, Beginning Scan...")
    except Exception:  # If ping fails
        print( "\n[!] Couldn't Resolve Target")
        print("[!] Exiting...")
        sys.exit(1)

# 扫描特定端口
def scanport(port):  # Function to scan a given port
    try:
        srcport = RandShort()  # Generate Port Number
        conf.verb = 0  # Hide output
        SYNACKpkt = sr1(IP(dst=dest_ip) / TCP(sport=srcport, dport=port, flags="S"))  # Send SYN and recieve RST-ACK or SYN-ACK

        pktflags = SYNACKpkt.getlayer(TCP).flags  # Extract flags of recived packet
        if pktflags == SYNACK:  # Cross reference Flags
            return True  # If open, return true
            print(port +"  "+"open")

        else:
            return False  # If closed, return false

        RSTpkt = IP(dst=dest_ip) / TCP(sport=srcport, dport=port, flags="R")  # Construct RST packet
        send(RSTpkt)  # Send RST packet

    except KeyboardInterrupt:  # In case the user needs to quit
        RSTpkt = IP(dst=dest_ip) / TCP(sport=srcport, dport=port, flags="R")  # Built RST packet
        send(RSTpkt)  # Send RST packet to whatever port is currently being scanned
        print( "\n[*] User Requested Shutdown...")
        print("[*] Exiting...")
        sys.exit(1)
# 获取IP和MAC地址
def getMAC(ip):
    try:
        ans,unans= srp(Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(pdst=ip), timeout=2, verbose=False)
    except Exception as e:
        print(str(e))
    else:
        for snd,rcv in ans:
            list_mac = rcv.sprintf("%Ether.src% - %ARP.psrc%")
            print(list_mac)
# checkhost(dest_ip)  # Run checkhost() function from earlier
# 扫描端口段
def scanports(start_port,end_port):
    ports = range(int(start_port), int(end_port) + 1)  # Build range from given port numbers
    for port in ports:  # Iterate through range of ports
        status = scanport(port)  # Feed each port into scanning function
        if status == True:  # Test result
            print("Port " + str(port) + ": Open")  # Print status

# 扫描制定端口
def synscan(domain, port):
    result = sr1(IP(dst=domain) / TCP(sport=RandShort(),dport=port, flags="S"))
    if result:
        print('got answer',result)
        if result[TCP].flags == 18:
            print('port open')
        else:
            print("port not open")
    else:
        print('not got answer')


# checkhost(dest_ip)
# getMAC(dest_ip)
# scanports(1, 150)


synscan("172.16.37.2",13)


