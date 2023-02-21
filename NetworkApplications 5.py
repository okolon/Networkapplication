#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import select


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout, ttl, timeSent):
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
         while True:
            timeLeft = timeout
            startTime = time.time()
            isReady = select.select([icmpSocket], [], [], timeLeft)

            if isReady [0] == []:
                return

            timeReceived = time.time()
            receivedPacket, destinationAddress = icmpSocket.recvfrom(1024)
            header = receivedPacket[20:28]
            ipHeader = receivedPacket[:20]
            packetType, code, check_sum, packetID, sequence = struct.unpack("bbHHh", header)

            data = struct.unpack("!BBHHHBBHII", ipHeader)
            packetLength = data[2]
            networkDelay = timeReceived - timeSent

            if packetID == ID:
                return networkDelay, packetLength

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        # 2. Checksum ICMP packet using given function
        # 3. Insert checksum into packet
        # 4. Send packet using socket
        # 5. Record time of sending
        check_sum = 0
        header = struct.pack("bbHHh", 8, 0, check_sum, ID, 1)
        check_sum = self.checksum(header) # creating a sample header to get check_sum

        header = struct.pack("bbHHh", 8, 0, check_sum, ID, 1) # hew header using check_sum

        icmpSocket.sendto(header, (destinationAddress, 0))
        timeSent = time.time() # my socket which sends packet to destination address

        return timeSent

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        # 2. Call sendOnePing function
        # 3. Call receiveOnePing function
        # 4. Close ICMP socket
        # 5. Return total network delay
        
        icmp = socket.getprotobyname("icmp")

        try:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as e: 
                if e == 1:
                    e = ("")
                raise socket.error(e)

        packetID = os.getpid() & 0xFFFF
        timeSent = self.sendOnePing(icmpSocket, destinationAddress, packetID)
        totalData = self.receiveOnePing(icmpSocket, destinationAddress, packetID, timeout, ttl, timeSent)
        icmpSocket.close()

        return totalData

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        destinationAddress = socket.gethostbyname(args.hostname)
        # 2. Call doOnePing function, approximately every second
        data = self.doOnePing(destinationAddress, args.timeout)
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
        self.printOneResult(destinationAddress, data[1], data[0], 0, args.timeout)
        # 4. Continue this process until stopped

class Traceroute(NetworkApplication):

    def receiveTrace(self, icmpSocket, ID, timeout, destinationAddres, timeSent, ttl):

        while True:
            timeLeft = timeout
            startTime = time.time()
            isReady = select.select([icmpSocket], [], [], timeLeft)

            if isReady [0] == []:
                return

            timeReceived = time.time()
            receivedPacket, destinationAddress = icmpSocket.recvfrom(1024)
            header = receivedPacket[20:28]
            ipHeader = receivedPacket[:20]
            packetType, code, check_sum, packetID, sequence = struct.unpack("bbHHh", header)

            data = struct.unpack("!BBHHHBBHII", ipHeader)
            packetLength = data[2]
            networkDelay = timeReceived - timeSent

            if packetType == 11:
                self.printOneResult(destinationAddress[0], packetLength, networkDelay * 1000, ttl)
                return (networkDelay, destinationAddress[0], None)
            elif packetType == 0:
                self.printOneResult(destinationAddress[0], packetLength, networkDelay * 1000, ttl)
                return (networkDelay, destinationAddress[0], 1)

    def sendTrace(self, icmpSocket, destinationAddress, ID):
        check_sum = 0
        header = struct.pack("bbHHh", 8, 0, check_sum, ID, 1)
        check_sum = self.checksum(header) # creating a sample header to get check_sum

        header = struct.pack("bbHHh", 8, 0, check_sum, ID, 1) # hew header using check_sum

        icmpSocket.sendto(header, (destinationAddress, 0)) # my socket which sends packet to destination address
        timeSent = time.time() 

        return timeSent

    def doTrace(self, destinationAddress, timeout):

        maximumHops = 30
        tries = 3
        destinatationReached = 0

        for ttl in range(1, maximumHops):
            if(destinatationReached):
                break
        
            for t_ries in range(0, tries):

                icmp = socket.getprotobyname("icmp")

                try:
                    icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                except socket.error as e:
                    print(e)

                icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl))
                packetID = os.getpid() & 0xFFFF

                timeSent = self.sendTrace(icmpSocket, destinationAddress, packetID)
                totalData = self.receiveTrace(icmpSocket, packetID, timeout, destinationAddress, timeSent, ttl)
                destinatationReached = totalData[2]

                return totalData
        
            icmpSocket.close()



    def __init__(self, args):
        
        timeout = args.timeout
        destinationAddress = socket.gethostbyname(args.hostname)
        print('Traceroute to: %s...' % (args.hostname))
        data = self.doTrace(destinationAddress, timeout)
    


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
