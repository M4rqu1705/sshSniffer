#!/usr/bin/env python
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, inet_ntoa, htons, PF_PACKET
from struct import *
from binascii import hexlify as readHex
import sys
import time

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

def printPacketInfo(PCAP, packetNumber):
    print "=" * 30 + "Packet Captured Number %s" % (packetNumber) + "=" * 30 + "\n"
    print "[*] Source MAC: %s -> Destination MAC: %s" % (PCAP["Source Ethernet Address"], PCAP["Destination Ethernet Address"])
    print "[*] Protocol: %s" % (PCAP["Protocol"])
    print "[*] Source IP: %s:%s -> Destination IP: %s:%s" % (PCAP["Source IP Address"], PCAP["Source Port"], PCAP["Destination IP Address"], PCAP["Destination Port"])
    print "[*] Seq. Number: %s \t Ack Number: %s \tFlag: %s" % ( PCAP["SEQ"], PCAP["ACK"], PCAP["flag"])
    print "\n"


#Create socket object
netSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))

#Packet counters and time of increment
previousPacketCounter = [0, 0]
currentPacketCounter = [0, 0]

#Warning counter and consecutive warning counter
warningsCounter, consecutiveWarningsCounter = 0, 0

#Amount of time between requests. If it is below this number, request is interpreted as automatic login attempt and a warning is printed
timeThreshold = 4 

#Amount of consecutive warnings needed to raise an alert
consecutiveWarningsLimit = 0

#Dictionary to collect the IP addresses of the attackers
loginAttempts = {}

#Receive packets for unlimited amount of time
while True:
    try:
        PCAP = receivePacket(netSocket)

        #Make sure PCAP is TCP, has port 22 as destination (We wish to caputre ssh packets) and the flag is SYN (there is an attempt to capture the packet)
        #Short circuit (alternative to nested ifs)
        if PCAP.has_key("flag") and PCAP["Destination Port"] == 22 and PCAP["flag"] == "SYN":

            #Make a copy of the current list before we change it to save it as previousPacketCounter
            previousPacketCounter = currentPacketCounter[:]
            #Increase counter (first value of the list) and update time packet was received (second value of the list)
            currentPacketCounter[0] +=1
            currentPacketCounter[1] = time.time()

            #Print relevant packet information
            print '='*30 + ' Packet No. ' + currentPacketCounter[0] + ' ' + '='*30
            print '\n[*] Source:  %s:%s -> Destination: %s:%s' % (PCAP["Source IP"] , PCAP["Source Port"], PCAP["Destination IP"], PCAP["Destination Port"]



            #Determine if warning should be rised if time interval between SYN is less than 4 seconds 
            if currentPacketCounter[1] - previousPacketCounter[1] < timeThreshold:
                print '[!] Login attempt was made too little time ago'
                warningsCounter += 1
                consecutiveWarningsCounter += 1
                if consecutiveWarningsCounter > consecutiveWarningsLimit:
                    print "*" * 30 + str(consecutiveWarningsCounter) + " consecutive warnings " + "*" * 30
            else:
                #Reset the consecutive warning counter because a "Normal" request has been made
                consecutiveWarningsCounter = 0

            #Record IP addresses
            if len(loginAttempts) < 100:
                if loginAttempts.has_key(PCAP["Source IP Address"]):
                    loginAttempts[PCAP["Source IP Address"]] += 1
                else:
                    loginAttempts[PCAP["Source IP Address"]] = 1

    except KeyboardInterrupt:
        print "Terminated program"
        print "[*] Total amount of warnings:", warningsCounter, "\n[*] Consecutive warnings:", consecutiveWarningsCounter
        for key, value in loginAttempts.iteritems():
            print "[*] " + str(key) + " -> " + str(value)
        sys.exit()
