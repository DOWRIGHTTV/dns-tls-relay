#!/usr/bin/env python3

import os, sys, subprocess
import struct
import traceback
import time
import threading
import json
import random
import ssl

from collections import deque
from socket import socket, timeout, AF_INET, SOCK_DGRAM, SOCK_STREAM, SHUT_WR

TCP = 6
UDP = 17

# must support DNS over TLS (not https/443, tcp/853)
PUBLIC_SERVER_1 = '1.1.1.1'
PUBLIC_SERVER_2 = '1.0.0.1'
DNS_TLS_PORT = 853

LISTENING_ADDRESS = '192.168.2.250'
DNS_PORT = 53

A_RECORD = 1

class DNSRelay:
    def __init__(self):
        self.tls_retry = 60

        self.unique_id_lock = threading.Lock()

        self.dns_connection_tracker = {}
        self.dns_tls_queue = deque()

        self.dns_servers = {}
        self.dns_servers[PUBLIC_SERVER_1] = {'reach': True, 'tls': True}
        self.dns_servers[PUBLIC_SERVER_2] = {'reach': True, 'tls': True}

    def Start(self):

        threading.Thread(target=self.TLSQueryQueue).start()
        self.Main()

    def Main(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((LISTENING_ADDRESS, DNS_PORT))

        print(f'[+] Listening -> {LISTENING_ADDRESS}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(1024)
#                print(f'Receved data from client: {client_address[0]}:{client_address[1]}.')
                if (not data_from_client):
                    break
                packet = PacketManipulation(data_from_client, protocol=UDP)
                packet.Parse()

                ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
                ## to handle the rest of the process and sending client data in for relay to dns server
                if (packet.qtype == 1):
                    self.TLSQueue(data_from_client, client_address)
                    time.sleep(.01)
            except Exception as E:
                print(f'MAIN: {E}')

        self.Main()

    def TLSQueue(self, data_from_client, client_address):
        packet = PacketManipulation(data_from_client, protocol=UDP)
        client_dns_id = packet.DNS()

        tcp_dns_id = self.GenerateIDandStore()
        dns_payload = packet.UDPtoTLS(tcp_dns_id)

        ## Adding client connection info to tracker to be used by response handler
        self.dns_connection_tracker.update({tcp_dns_id: {'client_id': client_dns_id, 'client_address': client_address}})

        self.dns_tls_queue.append(dns_payload)

    ## Queue Handler will make a TLS connection to remote dns server/ start a response handler thread and send all requests
    # in queue over the connection.
    def TLSQueryQueue(self):
        while True:
            try:
                secure_socket = None
                msg_queue = self.dns_tls_queue.copy()
                if (msg_queue):
                    for secure_server, server_info in self.dns_servers.items():
                        now = time.time()
                        retry = now - server_info.get('retry', now)
                        if (server_info['tls'] or retry >= self.tls_retry):
                            secure_socket = self.Connect(secure_server)
                        if (secure_socket):
                            break

                if (secure_socket):
                    threading.Thread(target=self.TLSResponseHandler, args=(secure_socket,)).start()
                    # prevents double free and ssllib crashes/ python segmentation faults
                    time.sleep(.001)
                    for message in msg_queue:
                        try:
                            secure_socket.send(message)

                        except Exception as E:
                            print(f'TLSQUEUE | SEND: {E}')

                        self.dns_tls_queue.popleft()

                    secure_socket.shutdown(SHUT_WR)
                # waiting 10ms before checking queue again, this will make idle performance lower.
                time.sleep(.01)
            except Exception as E:
                print(f'TLSQUEUE | GENERAL: {E}')

    # Response Handler will match all recieved request responses from the server, match it to the host connection
    # and relay it back to the correct host/port. this will happen as they are recieved. the socket will be closed
    # once the recieved count matches the expected/sent count or from socket timeout
    def TLSResponseHandler(self, secure_socket):
        while True:
            try:
                dns_query_response = None
                data_from_server = secure_socket.recv(4096)
                if (not data_from_server):
                    break

            except (timeout, BlockingIOError):
                break
            except Exception:
                traceback.print_exc()
                break

            try:
                # Checking the DNS ID in packet, Adjusted to ensure uniqueness
                packet = PacketManipulation(data_from_server, protocol=TCP)
                tcp_dns_id = packet.DNS()
#                print(f'Secure Request Received from Server. DNS ID: {tcp_dns_id}')

                # Checking client DNS ID and Address info to relay query back to host
                dns_query_info = self.dns_connection_tracker.get(tcp_dns_id, None)
                if (dns_query_info):
                    client_dns_id = dns_query_info.get('client_id')
                    client_address = dns_query_info.get('client_address')

                    ## Parsing packet and rewriting TTL to 5 minutes and changing DNS ID back to original.
                    packet.Rewrite(dns_id=client_dns_id)
                    dns_query_response = packet.send_data

                    ## Relaying packet from server back to host
                    self.sock.sendto(dns_query_response, client_address)
#                    print(f'Request Relayed to {client_address[0]}: {client_address[1]}')
            except ValueError:
                # to troubleshoot empty separator error
                print('empty separator error')
                print(data_from_server)
            except Exception:
                traceback.print_exc()

            self.dns_connection_tracker.pop(tcp_dns_id, None)

        secure_socket.close()

    def GenerateIDandStore(self):
        with self.unique_id_lock:
            while True:
                dns_id = random.randint(1, 32000)
                if (dns_id not in self.dns_connection_tracker):

                    self.dns_connection_tracker.update({dns_id: ''})

                    return dns_id

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method
    def Connect(self, secure_server):
        now = round(time.time())
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((LISTENING_ADDRESS, 0))

            context = ssl.create_default_context()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

            # Wrap socket and Connect. If exception will return None which will have
            # the queue handler try the other server if available and will mark this
            # server as down

            secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, DNS_TLS_PORT))
        except Exception:
            secure_socket = None

        if (secure_socket):
            self.dns_servers[secure_server].update({'tls': True})
        else:
            self.dns_servers[secure_server].update({'tls': False, 'retry': now})

        return secure_socket

class PacketManipulation:
    def __init__(self, data, protocol):
        if (protocol == UDP):
            self.data = data
        elif (protocol == TCP):
            self.data = data[2:]

        self.qtype = 0
        self.qclass = 0

        self.send_data = b''

    def Parse(self):
        self.QueryInfo()
        if (self.qtype):
            self.QName()

    def DNS(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def QueryInfo(self):
        self.dns_payload = self.data[12:]
        dns_query = self.dns_payload.split(b'\x00',1)

        if (len(dns_query) >= 2 and len(dns_query[1]) >= 4):
            dnsQ = struct.unpack('!2H', dns_query[1][0:4])
            self.qtype = dnsQ[0]
            self.qclass = dnsQ[1]
            self.dns_query = dns_query[0]

    def QName(self):
        b = len(self.dns_query)
        eoqname = b + 1

        qname = struct.unpack(f'!{b}B', self.dns_query[:eoqname])

        # coverting query name from bytes to string
        length = qname[0]
        qname_raw = ''
        for byte in qname[1:]:
            if (length != 0):
                qname_raw += chr(byte)
                length -= 1
                continue

            length = byte
            qname_raw += '.'

        self.qname = qname_raw.lower()

    def Rewrite(self, dns_id=None):
        qname = self.data[12:].split(b'\x00',1)[0]

        offset = len(qname) + 1
        end_of_qname = 12 + offset
        end_of_query = end_of_qname + 4
        start_of_record = end_of_query
        request_header = self.data[:end_of_query]
        request_record = self.data[start_of_record:]

        # assigning pointer variable, which is a protocol constant and ttl for 1 hour in packet form.
        pointer = b'\xc0\x0c'
        ttl_bytes_override = b'\x00\x00\x0e\x10'

        # splitting the dns packet on the compressed pointer if present, if not splitting on qname.
        if (request_record[0:2] == pointer):
            rr_splitdata = request_record.split(pointer)
            rr_name = pointer
        else:
            rr_splitdata = request_record.split(qname)
            rr_name = qname

        # reset request record var then iterating over record recieved from server and rewriting the dns record TTL
        # to 5 minutes if present or not already lower to ensure clients to not keep records cached for exessive
        # periods making dns proxy ineffective.
        request_record = b''
        for rr_part in rr_splitdata[1:]:
            bytes_check = rr_part[2:8]
            type_check, ttl_check = struct.unpack('!HL', bytes_check)
            if (type_check == A_RECORD and ttl_check > 299):
                request_record += rr_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]
            else:
                request_record += rr_name + rr_part

        # Replacing tcp dns id with original client dns id if converting back from tcp/tls.
        if (dns_id):
            request_header = request_header[2:]
            self.send_data += struct.pack('!H', dns_id)

        self.send_data += request_header + request_record

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return(tcp_dns_payload)

if __name__ == '__main__':
    DNSRelay = DNSRelay()
    DNSRelay.Start()
