#!/usr/bin/python3

import os, sys, subprocess
import struct
import traceback
import time
import threading
import json
import random
import ssl

from copy import deepcopy
from socket import socket, timeout, AF_INET, SOCK_DGRAM, SOCK_STREAM

SERVER_ADDRESS = '192.168.2.250'
DNS_TLS_PORT = 853
DNS_PORT = 53
TCP = 6
UDP = 17

START_TIME = round(time.time())

class DNSRelay:
    def __init__(self):
        self.tls_retry = 600
        self.udp_fallback = False
        self.protocol = TCP

        self.thread_lock = threading.Lock()

        self.dns_connection_tracker = {}
        self.dns_tls_queue = []

        self.dns_servers = {}
        self.dns_servers['1.1.1.1'] = {'Reach': True, 'TLS': True}
        self.dns_servers['1.0.0.1'] = {'Reach': True, 'TLS': True}
               
    def Start(self):
         
        threading.Thread(target=self.TLSQueryQueue).start()    
        self.Main()

    def Main(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((SERVER_ADDRESS, DNS_PORT))

        print(f'[+] Listening -> {SERVER_ADDRESS}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(1024)
                print(f'Receved data from client: {data_from_client}.')
                if (data_from_client):
                    packet = PacketManipulation(data_from_client, protocol=UDP)
                    packet.Parse()
                    ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
                    ## to handle the rest of the process and sending client data in for relay to dns server        
                    if (packet.qtype == 1):
                        if (self.protocol == TCP):
                            self.TLSQueue(data_from_client, client_address)
            except IndexError as IE:
                traceback.print_exc()
                with open('wtf_log.txt', 'a+') as log:
                    timestamp = self.LogTime()
                    log.write(f'{timestamp} | MAIN SOCKET EXCEPTION! | {IE} ://\n')
                    log.write(f'{timestamp} -----------------------------------\n')
                    log.write(f'{timestamp} | {data_from_client} ://\n')
                    log.write(f'{timestamp} -----------------------------------\n')            
            except Exception as E:
                traceback.print_exc()
                with open('wtf_log.txt', 'a+') as log:
                    timestamp = self.LogTime()
                    log.write(f'{timestamp} | MAIN SOCKET EXCEPTION! | {E} ://\n')
            
    def UDPRelay(self, data_from_client, client_address, fallback=False):
        sock = socket(AF_INET, SOCK_DGRAM)
        ## -------------- ##
        ## Iterating over DNS Server List and Sending to first server that is available.
        for server_ip, server_info in self.dns_servers:
            if (server_info['Reach'] is True):
                sock.sendto(data_from_client, (server_ip, DNS_PORT))
#                print(f'Request Relayed to {server_ip}: {DNS_PORT}')

                ## Waiting for response from server then parsing packet and rewriting
                ## TTL to 5 minutes.
                data_from_server, _ = sock.recvfrom(1024)
                packet = PacketManipulation(data_from_server, protocol=UDP)
                packet.Rewrite()

                ## Relaying packet from server back to host
                packet_from_server = packet.send_data
#                print('Request Received')
                break

        self.sock.sendto(packet_from_server, client_address)
#        print(f'Request Relayed to {client_address[0]}: {client_address[1]}')

    def TLSQueue(self, data_from_client, client_address):
#        print('Adding Request to TLS Queue.')
        packet = PacketManipulation(data_from_client, protocol=UDP)
        client_dns_id = packet.DNS()

        tcp_dns_id = self.GenerateIDandStore()
        dns_payload = packet.UDPtoTLS(tcp_dns_id)
#        print(f'Relayed Client Request {client_address[0]}:{client_address[1]} with DNS ID: {tcp_dns_id}')
        ## Adding client connection info to tracker to be used by response handler
        self.dns_connection_tracker.update({tcp_dns_id: {'Client ID': client_dns_id, 'Client Address': client_address}})
        timestamp = self.FormatTime()
#        print(f'{timestamp} | ADDED:', struct.unpack('!H', dns_payload[2:4])[0])
        self.dns_tls_queue.append(dns_payload)

    def TLSQueryQueue(self):
        while True:
            try:
                secure_socket = None
                msg_queue = list(self.dns_tls_queue)
                print(msg_queue)
                if (msg_queue):
                    for secure_server, server_info in self.dns_servers.items():
                        now = time.time()
                        retry = now - server_info.get('Retry', now)
                        if (server_info['TLS'] or retry >= self.tls_retry):
                            secure_socket = self.Connect(secure_server)
                        if (secure_socket):
                            break
                    else:
                        ##Fallback to UDP if configured ||||ASDFASFGASDFAS FFSGDFGXDSDG SDGVSDFG SD
                        if (self.udp_fallback):
                            pass
                
                if (secure_socket):
                    msg_count = len(msg_queue)
                    threading.Thread(target=self.TLSResponseHandler, args=(secure_socket, msg_count)).start()
    #                print(f'QUEUE LENGTH: {len(msg_queue)}')
                    for message in msg_queue:
                        try:
                            timestamp = self.FormatTime()
                            secure_socket.send(message)
#                            print(f'{timestamp} | SENT:', struct.unpack('!H', message[2:4])[0])
    #                        print('Secure Request Relayed to DNS over TLS Server.')
                            self.dns_tls_queue.pop(0)                  
                        except Exception as E:
                            traceback.print_exc()
                            print(f'SEND: {E}')
                time.sleep(.05) 
                ## TUNE THIS VALUE! TRY TO MAXMIMIZE PERFORMANCE OF WAITING VS SENDING. 
                ## WAITING LONGER WILL RESULT IN LESS CONNECTIONS OPENED
            except Exception:
                traceback.print_exc()

    def TLSResponseHandler(self, secure_socket, msg_count):
        recv_count = 0
        try:
            while True:
                data_from_server = secure_socket.recv(4096)
                recv_count += 1
                if (not data_from_server):
                    break
                # Checking the DNS ID in packet, Adjusted to ensure uniqueness
                packet = PacketManipulation(data_from_server, protocol=TCP)
#                    packet.Parse()
                tcp_dns_id = packet.DNS()
#                    print(f'Secure Request Received from Server. DNS ID: {tcp_dns_id}')
                timestamp = self.FormatTime()
#                print(f'{timestamp} | RECEIVED:', tcp_dns_id)
                # Checking client DNS ID and Address info to relay query back to host
                client_dns_id = self.dns_connection_tracker[tcp_dns_id]['Client ID']
                client_address = self.dns_connection_tracker[tcp_dns_id]['Client Address']

                ## Parsing packet and rewriting TTL to 5 minutes and changing DNS ID back to original.
                packet.Rewrite(dns_id=client_dns_id)
                packet_from_server = packet.send_data

                ## Relaying packet from server back to host
                self.sock.sendto(packet_from_server, client_address)
#                    print(f'{packet.qname} Relayed {client_address[0]}: {client_address[1]}')
                self.dns_connection_tracker.pop(tcp_dns_id)
                
                if (recv_count == msg_count):
                    secure_socket.close()
                    break
                
        except timeout:
            ##LOG timeout | most means some requests did not get delivered
            secure_socket.close()
        except Exception as E:
            secure_socket.close()
            traceback.print_exc()
            print(f'RECEIVE: {E}')

    def GenerateIDandStore(self):
        while True:
            self.thread_lock.acquire()
            self.dns_id_lock = True
            dns_id = random.randint(1, 32000)
            if (dns_id not in self.dns_connection_tracker):
                
                self.dns_connection_tracker.update({dns_id: ''})
                self.thread_lock.release()
                return dns_id

    def LogTime(self):
        epoch = round(time.time())
        f_time = time.ctime(epoch - START_TIME)
        f_time = f_time.split()
        format_time = f_time[3]
    
        return format_time

    def FormatTime(self):
        epoch = round(time.time())
#        f_time = time.ctime(epoch - START_TIME)
#        f_time = f_time.split()
        hours = epoch - START_TIME
        hours = round(hours / 3600, 3)
        format_time = f'RUNNING TIME: {hours} hrs'    #{f_time[3]}

        return format_time

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method
    def Connect(self, secure_server):
        attempt = 0
        while True:
            try:
                sock = socket(AF_INET, SOCK_STREAM)
                sock.settimeout(2)

                context = ssl.create_default_context()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
                context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)

                # Wrap socket and Connect. If exception will add to attempt value and mark as status
                # as false. If successful connect will break while loop and allow queue handler to
                # send DNS query

#                print(f'Opening Secure socket to {secure_server}: 853')
                secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
                secure_socket.connect((secure_server, DNS_TLS_PORT))
                #print(self.secure_socket.getpeercert())
            except Exception as E:
                traceback.print_exc()
                print(f'CONNECT: {E}')
                secure_socket = None
                attempt += 1

            if (secure_socket):
                self.dns_servers[secure_server].update({'TLS': True})
                break
            elif (attempt >= 3):
                now = round(time.time())
                self.dns_servers[secure_server].update({'TLS': False, 'Retry': now})          

        return secure_socket

class PacketManipulation:
    def __init__(self, data, protocol):
        if (protocol == UDP):
            self.data = data
        elif (protocol == TCP):
            self.data = data[2:]

    def Parse(self):
        self.DNS()
        self.QType()
        self.QName()

    def DNS(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def QType(self):
        self.dns_payload = self.data[12:]
        j = self.dns_payload.index(0) + 1 + 4
        self.qtype = self.dns_payload[j-3:j-2]

    def QName(self):
        qn = self.data[12:].split(b'\x00',1)
        qt = qn[1]
        qn = qn[0]
        b = len(qn)
        eoqname = b + 1

        qname = struct.unpack(f'!{b}B', qn[0:eoqname])
        dnsQ = struct.unpack('!2H', qt[0:4])
        self.qtype = dnsQ[0]

        # coverting query name from bytes to string
        length = qname[0]
        self.qname = ''
        for byte in qname[1:]:
            if (length != 0):
                self.qname += chr(byte)
                length -= 1
                continue
                
            length = byte
            self.qname += '.'
    
    def Rewrite(self, dns_id=None):
        qname = self.data[12:].split(b'\x00',1)[0]
        dns_id = struct.pack('!H', dns_id)

        offset = len(qname) + 1         
        eoqname = 12+offset
        eoquery = eoqname + 4
        rrecord = self.data[eoquery:]
        
        pointer = b'\xc0\x0c'
        ttl_bytes_override = b'\x00\x00\x01+'
        
        if (rrecord[0:2] == pointer):                
            splitdata = self.data.split(pointer)
            rrname = pointer
        else:
            splitdata = self.data.split(qname)
            rrname = qname
            
        rr = b''
        for i, rrpart in enumerate(splitdata, 1):
            if i != 1:
                ttl_bytes = rrpart[4:8]
                ttl_check = struct.unpack('>L', ttl_bytes)[0]
                if (ttl_check > 299):
                    rr += rrname + rrpart[:4] + ttl_bytes_override + rrpart[8:]
                else:
                    rr += rrname + rrpart

        # Replacing tcp dns id with original client dns id if id is present
        if (not dns_id):
            self.send_data = splitdata[0] + rr
        else:
            self.send_data = dns_id + splitdata[0][2:] + rr

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return(tcp_dns_payload)

if __name__ == '__main__':
    DNSRelay = DNSRelay()
    DNSRelay.Start()
