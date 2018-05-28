#!/usr/bin/env python

#Import specific elements from the socket module to reduce load time and increase efficiency
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, inet_ntoa, htons, PF_PACKET
#Import every element from struct module
from struct import *
#From binascii module uniquely import function hexlify, named in this program as readHex
from binascii import hexlify as readHex
#Import the sys module
import sys
#Import the time module
import time

def receivePacket(netSocket):
    '''
    Declare and define function receive packet, which takes a
    socket object instance as a parameter and returns a dictionary
    with collected data from packet
    '''

    #Declare and initialize dictionary to store the captured packet
    PCAP = {}

    #Receive a message from a socket with buffer size of 65565
    packet = netSocket.recvfrom(65565)
    #Only use the data from the returned tuple. Discard the socket address
    packet = packet[0]

    #LAYER 2 - LINK LAYER (ETHERNET HEADER)

    #Unpack the first 14 characters of the packet as specified by the format parameter
    ethHeader = unpack(">6s6s2s", packet[0:14])
    #Convert extracted information to hexadecimal
    PCAP["Source Ethernet Address"] = readHex(ethHeader[1])
    PCAP["Destination Ethernet Address"] = readHex(ethHeader[0])
    PCAP["Ethernet Type"] = readHex(ethHeader[2])

    #LAYER 3 - TCP/IP (IP HEADER AND TCP HEADER)

    #Unpack the next 20 characters of the packet as specified by the format parameter. 
    ipHeader = unpack(">1s1s2s2s2s1s1s2s4s4s", packet[14:34])

    #Convert extracted information to hexadecimal
    protocolNum = readHex(ipHeader[6])

    #Convert packed IP addresses to dot-quad notation
    PCAP["Source IP Address"] = inet_ntoa(ipHeader[8])
    PCAP["Destination IP Address"] = inet_ntoa(ipHeader[9])

    #LAYER 4 - TRANSPORT LAYER

    #Treat TCP and UDP packets differently
    if protocolNum == "06":

        PCAP["Protocol"] = "TCP (%s)" % (protocolNum)
        transportLayerHeader = unpack(">HHLLBBHHH", packet[34:54])
        PCAP["Data"] = packet[54:]
        PCAP["Source Port"] = transportLayerHeader[0]
        PCAP["Destination Port"] = transportLayerHeader[1]
        PCAP["SEQ"] = transportLayerHeader[2]
        PCAP["ACK"] = transportLayerHeader[3]
        PCAP["Offset"] = transportLayerHeader[4]

        #Interpret numerical form of flags and label them as finalize, synchronize, reset, push, acknowledgment, and urgent
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

    #Return dictionary containing all relevant packet data
    return PCAP

def printPacketInfo(PCAP, packetNumber):
    '''
    Utilizing PCAP dictionary containing packet information and
    the packet number, print all the relevant metadata 
    '''

    print "=" * 30 + "Packet Captured Number %s" % (packetNumber) + "=" * 30 + "\n"
    print "[*] Source MAC: %s -> Destination MAC: %s" % (PCAP["Source Ethernet Address"], PCAP["Destination Ethernet Address"])
    print "[*] Protocol: %s" % (PCAP["Protocol"])
    print "[*] Source IP: %s:%s -> Destination IP: %s:%s" % (PCAP["Source IP Address"], PCAP["Source Port"], PCAP["Destination IP Address"], PCAP["Destination Port"])
    print "[*] Seq. Number: %s \t Ack Number: %s \tFlag: %s" % ( PCAP["SEQ"], PCAP["ACK"], PCAP["flag"])
    print "\n"

def main():
    #Create socket object to read raw sockets via Ethernet cable
    netSocket = socket(PF_PACKET, SOCK_RAW, htons(0x0800))

    #Initialize lists variables containing packet counters and times of increment
    previousPacketCounter = [0, 0]
    currentPacketCounter = [0, 0]

    #Initialize variables containing warning counters and consecutive warning counters
    warningsCounter, consecutiveWarningsCounter = 0, 0

    #Amount of time between requests. If it is below this number, request is interpreted as automatic login attempt and a warning is printed
    timeThreshold = 4 

    #Amount of consecutive warnings needed to raise an alert
    consecutiveWarningsLimit = 0

    #Dictionary to collect the IP addresses of the attackers
    loginAttempts = {}

    #Receive packets for unlimited amount of time, hence why the "True" condition for the while loop
    while True:
        try:
            PCAP = receivePacket(netSocket)

            #Make sure PCAP is TCP, has port 22 as destination (We wish to capture ssh packets) and the flag is SYN (there is an attempt to capture the packet)
            #Short circuit (alternative to nested ifs)
            if PCAP.has_key("flag") and PCAP["Destination Port"] == 22 and PCAP["flag"] == "SYN":

                #Make a copy of the current list before we change it to save it as previousPacketCounter
                previousPacketCounter = currentPacketCounter[:]
                #Increase counter (first value of the list) and update time packet was received (second value of the list)
                currentPacketCounter[0] +=1
                currentPacketCounter[1] = time.time()

                #Print minimal relevant packet information
                print '='*30 + ' Packet No. ' + str(currentPacketCounter[0]) + ' ' + '='*30
                print '\n[*] Source:  %s:%s -> Destination: %s:%s\n' % (PCAP["Source IP Address"] , PCAP["Source Port"], PCAP["Destination IP Address"], PCAP["Destination Port"])



                #Determine if warning should be rised if time interval between SYN is less than 4 seconds 
                if (currentPacketCounter[1] - previousPacketCounter[1] < timeThreshold):
                    print '[!] Login attempt was made too little time ago'
                    warningsCounter += 1
                    consecutiveWarningsCounter += 1
                    if consecutiveWarningsCounter > consecutiveWarningsLimit:
                        print "*" * consecutiveWarningsCounter + str(consecutiveWarningsCounter) + " consecutive warnings " + "*" * consecutiveWarningsCounter + "\n"*2
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
            print "[*] Total amount of warnings:", warningsCounter, "\n[*] Consecutive warnings:", consecutiveWarningsCounter, "\n"
            for key, value in loginAttempts.iteritems():
                print "[*] " + str(key) + " -> " + str(value)
            sys.exit()


if __name__ == "__main__":
    main()
