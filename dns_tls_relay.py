#!/usr/bin/python3

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

SERVER_ADDRESS = '192.168.2.250'
DNS_TLS_PORT = 853
DNS_PORT = 53
TCP = 6
UDP = 17
A_RECORD = 1

class DNSRelay:
    def __init__(self):
        self.tls_retry = 60

        self.thread_lock = threading.Lock()

        self.dns_connection_tracker = {}
        self.dns_tls_queue = deque()

        self.dns_servers = {}
        self.dns_servers['1.1.1.1'] = {'reach': True, 'tls': True}
        self.dns_servers['1.0.0.1'] = {'reach': True, 'tls': True}

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
#                print(f'Receved data from client: {client_address[0]}:{client_address[1]}.')
                if (not data_from_client):
                    break
                packet = PacketManipulation(data_from_client, protocol=UDP)
                packet.Parse()

                ## Matching IPV4 DNS queries only. All other will be dropped. Then creating a thread
                ## to handle the rest of the process and sending client data in for relay to dns server
                if (packet.qtype == 1):
                    self.TLSQueue(data_from_client, client_address)
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
                    time.sleep(.001)
                    for message in msg_queue:
                        try:
                            secure_socket.send(message)

                        except Exception as E:
                            print(f'TLSQUEUE | SEND: {E}')

                        self.dns_tls_queue.popleft()

                    secure_socket.shutdown(SHUT_WR)
                # This value is optional, but is in place to test efficiency of tls connections vs udp requests recieved.
                time.sleep(.05)
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

                ## Relaying packet from server back to host if dns response portion is not empty
                if (dns_query_response):
                    self.sock.sendto(dns_query_response, client_address)
#                    print(f'Request Relayed to {client_address[0]}: {client_address[1]}')
            except Exception:
                traceback.print_exc()

            self.dns_connection_tracker.pop(tcp_dns_id, None)

        secure_socket.close()

    def GenerateIDandStore(self):
        with self.thread_lock:
            while True:
                dns_id = random.randint(1, 32000)
                if (dns_id not in self.dns_connection_tracker):

                    self.dns_connection_tracker.update({dns_id: ''})

                    print(dns_id)
                    return dns_id

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method
    def Connect(self, secure_server):
        now = round(time.time())
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((SERVER_ADDRESS, 0))

            context = ssl.create_default_context()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
            context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)

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

    def Parse(self):
        self.QueryInfo()
        self.QName()

    def DNS(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def QueryInfo(self):
        self.dns_payload = self.data[12:]
        self.query_response = self.dns_payload.split(b'\x00',1)

        dnsQ = struct.unpack('!2H', self.query_response[1][0:4])
        self.qtype = dnsQ[0]
        self.qclass = dnsQ[1]

    def QName(self):
        qn = self.query_response[0]
        b = len(qn)
        eoqname = b + 1

        qname = struct.unpack(f'!{b}B', qn[:eoqname])

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
        if (dns_id):
            dns_id = struct.pack('!H', dns_id)

        offset = len(qname) + 1
        end_of_qname = 12 + offset
        end_of_query = end_of_qname + 4
        start_of_record = end_of_query
        request_header = self.data[:end_of_query]
        request_record = self.data[start_of_record:]

        # assigning pointer variable (protocol constant) and ttl for 60 minutes in packet form.
        pointer = b'\xc0\x0c'
        ttl_bytes_override = b'\x00\x00\x0e\x10'

        # splitting the dns packet on the compressed pointer if present, if not splitting on qname.
        if (request_record[0:2] == pointer):
            rr_splitdata = request_record.split(pointer)
            rr_name = pointer
            offset = 0
        else:
            rr_splitdata = request_record.split(qname)
            rr_name = qname

        # checking to see whether a record is present in response. if so, reset record and prep to rewrite.
        # rewrite the dns record TTL to 5 minutes if not already lower to ensure clients to not keep records
        # cached for exessive periods making dns proxy ineffective.
        send_data = False
        if (request_record):
            send_data = True
            request_record = b''
            for rr_part in rr_splitdata[1:]:
                type_check = rr_part[offset + 2:offset + 4]
                type_check = struct.unpack('!H', type_check)[0]
                if (type_check == A_RECORD):
                    ttl_bytes = rr_part[offset + 4:offset + 8]
                    ttl_check = struct.unpack('>L', ttl_bytes)[0]
                    if (ttl_check > 3600):
                        request_record += rr_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]
                    else:
                        request_record += rr_name + rr_part
                else:
                    request_record += rr_name + rr_part

        # Replacing tcp dns id with original client dns id if id is present
        if (send_data and dns_id):
            self.send_data = dns_id + request_header[2:] + request_record
        elif (send_data and not dns_id):
            self.send_data = request_header + request_record
        else:
            self.send_data = None

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return(tcp_dns_payload)

if __name__ == '__main__':
    DNSRelay = DNSRelay()
    DNSRelay.Start()
