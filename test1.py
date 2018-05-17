from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, inet_ntoa, htons, AF_PACKET
from struct import *
from binascii import hexlify as readHex
import sys

def receivePacket(netSocket):

    #Dictionary to store the captured packet
    PCAP = {}

    #Receive a message from a socket
    packet = netSocket.recvfrom(65565)
    packet = packet[0]

    #Layer 2 - Link Layer (Ethernet Header)
    ethHeader = unpack(">6s6s2s", packet[0:14])
    PCAP["Source Ethernet Address"] = readHex(ethHeader[1])
    PCAP["Destination Ethernet Address"] = readHex(ethHeader[0])
    PCAP["Ethernet Type"] = readHex(ethHeader[2])

    #Layer 3 - TCP/IP (IP Header and TCP header)
    ipHeader = unpack(">1s1s2s2s2s1s1s2s4s4s", packet[14:34])
    protocolNum = readHex(ipHeader[6])
    PCAP["Source IP Address"] = inet_ntoa(ipHeader[8])
    PCAP["Destination IP Address"] = inet_ntoa(ipHeader[9])

    #Layer 4 - Transport Layer
    if protocolNum == "06":
        PCAP["Protocol"] = "TCP (%s)" % (protocolNum)
        transportLayerHeader = unpack(">HHLLBBHHH", packet[34:54])
        PCAP["Data"] = packet[54:]
        PCAP["Source Port"] = transportLayerHeader[0]
        PCAP["Destination Port"] = transportLayerHeader[1]
        PCAP["SEQ"] = transportLayerHeader[2]
        PCAP["ACK"] = transportLayerHeader[3]
        PCAP["Offset"] = transportLayerHeader[4]

        flag = transportLayerHeader[5]
        if flag == 1:
            flag = "FIN"
        elif flag == 2:
            flag = "SYN"
        elif flag == 4:
            flag = "RST"
        elif flag == 8:
            flag = "PSH"
        elif flag == 16:
            flag = "ACK"
        elif flag == 32:
            flag = "URG"
        PCAP["flag"] = flag
        PCAP["Window"] = transportLayerHeader[6]
        PCAP["Checksum"] = transportLayerHeader[7]

    elif protocolNum == "11": 
        PCAP["Protocol"] = "UDP (%s)" % (protocolNum)
        transportLayerHeader = unpack(">HHHH", packet[34:42])
        PCAP["Data"] = packet[42:]
        PCAP["Source Port"] = transportLayerHeader[0]
        PCAP["Destination Port"] = transportLayerHeader[1]
        PCAP["Length"] = transportLayerHeader[2]
        PCAP["Checksum"] = transportLayerHeader[3]

    return PCAP

#Create socket object
netSocket = socket(AF_INET, SOCK_RAW, htons(0x0800))

#Packet counter
ctr = 1

#Receive packets for unlimited amount of time
while True:

    try:
        PCAP = receivePacket(netSocket)

        #Make sure PCAP is TCP, has port 22 as destination (SSH only) and the flag is SYN
        #Short circuit (alternative to nested ifs)
        if PCAP.has_key("flag") and PCAP["Destination Port"] == 22 and PCAP["flag"] == "SYN":
            print "=" * 30 + "Packet Captured No. %s" % (ctr) + "=" * 30 + "\n"
            print "[*] Src. MAC: %s -> Dest. MAC: %s" % (PCAP["Source Ethernet Address"], PCAP["Destination Ethernet Address"])
            print "[*] Protocol: %s" % (PCAP["Protocol"])
            print "[*] Src IP: %s:%s -> Dest. IP: %s:%s" % (PCAP["Source IP Address"], PCAP["Source Port"], PCAP["Destination IP Address"], PCAP["Destination Port"])
            print "[*] Seq. Number: %s \t Ack Number: %s \tFlag: %s" % ( PCAP["SEQ"], PCAP["ACK"], PCAP["flag"])
            print "[*] Data/Payload:"
            print "     %s" % (PCAP["Data"])
            print "\n"
            ctr +=1
    except KeyboardInterrupt:
        print "Bye ... You interrupted me ... You S"
        sys.exit()

