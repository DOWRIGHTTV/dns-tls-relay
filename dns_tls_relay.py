#!/usr/bin/env python3

import os, sys
import subprocess
import traceback
import time
import threading
import json
import random
import ssl

from copy import deepcopy
from collections import deque, Counter
from socket import socket, timeout,error, AF_INET, SOCK_DGRAM, SOCK_STREAM, SHUT_WR

from dns_packet_parser import PacketManipulation

# address which the relay will receive dns requests
LISTENING_ADDRESS = '192.168.2.250'

# adress which the relay will use to talk to a public resolver
CLIENT_ADDRESS = '192.168.2.250'

# must support DNS over TLS (not https/443, tcp/853)
PUBLIC_SERVER_1 = '1.1.1.1'
PUBLIC_SERVER_2 = '1.0.0.1'

# protocol constants
TCP = 6
UDP = 17
A_RECORD = 1
DNS_PORT = 53
DNS_TLS_PORT = 853
DEFAULT_TTL = 3600

TOP_DOMAIN_COUNT = 20

class DNSRelay:
    def __init__(self):
        self.dns_servers = {}
        self.dns_servers[PUBLIC_SERVER_1] = {'reach': True, 'tls': True}
        self.dns_servers[PUBLIC_SERVER_2] = {'reach': True, 'tls': True}

        self.tls_retry = 60

        self.cache_lock = threading.Lock()

    def Start(self):
        self.DNSCache = DNSCache(self)
        self.TLSRelay = TLSRelay(self)

        threading.Thread(target=self.DNSCache.AutoClear).start()
        threading.Thread(target=self.DNSCache.TopDomains).start()
        threading.Thread(target=self.TLSRelay.ProcessQueue).start()
        self.Main()

    def Main(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((LISTENING_ADDRESS, DNS_PORT))

        print(f'[+] Listening -> {LISTENING_ADDRESS}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(1024)
 #               print(f'Receved data from client: {client_address[0]}:{client_address[1]}.')
                if (not data_from_client):
                    break

                self.ParseRequests(data_from_client, client_address)
            except error:
                break

        self.Main()

    def ParseRequests(self, data_from_client, client_address):
        try:
            packet = PacketManipulation(data_from_client, protocol=UDP)
            packet.Parse()

            ## Matching IPV4 DNS queries only. All other will be dropped.
            if (packet.dns_query and packet.qtype == A_RECORD):
                threading.Thread(target=self.ProcessQuery, args=(packet, client_address)).start()

        except Exception as E:
            print(f'MAIN: {E}')

    def SendtoClient(self, packet, client_address, from_cache=False):
        ## Relaying packet from server back to host
        self.sock.sendto(packet.send_data, client_address)
#        print(f'Request Relayed to {client_address[0]}: {client_address[1]}')

    # will check to see if query is cached/ has been requested before. if not will add to queue for standard query
    def ProcessQuery(self, packet, client_address):
        cached_packet = self.DNSCache.Search(packet.request, packet.dns_id)
        if (cached_packet):
            self.SendtoClient(cached_packet, client_address, from_cache=True)
            print(f'CACHED RESPONSE | NAME: {packet.request} TTL: {cached_packet.cache_ttl}')
        else:
            self.TLSRelay.AddtoQueue(packet, client_address)

class DNSCache:
    def __init__(self, DNSRelay):
        self.DNSRelay = DNSRelay
        self.dns_cache = {}

        self.domain_counter = Counter()
        self.top_domains = {}

        self.domain_counter_lock = threading.Lock()

    # queries will be added to cache if it is not already cached or has expired or if the dns response is the
    # result from an internal dns request for top domains
    def Add(self, packet, client_address):
        cache_expired = False
        now = time.time()
        expire = int(now) + packet.cache_ttl
        client_ip, client_port = client_address
        already_cached = self.dns_cache.get(packet.request, None)
        # checking to see if cached packet is expired to ensure it is recached with updated information
        if (already_cached and already_cached['expire'] <= now):
            cache_expired = True
        # will cache packet if not already cached or if it is from the top domains list
        if ((not already_cached or cache_expired) or (not client_ip and not client_port)
                and packet.data_to_cache):
            self.dns_cache.update({packet.request: {
                                            'packet': packet.data_to_cache,
                                            'expire': expire}})

            print(f'CACHE ADD | NAME: {packet.request} TTL: {packet.cache_ttl}')

    def Search(self, request, client_dns_id):
        now = int(time.time())
        cached_query = self.dns_cache.get(request, None)
        if (cached_query and cached_query['expire'] > now):
            cached_packet = PacketManipulation(cached_query['packet'], protocol=UDP)
            cached_packet.Parse()

            calculated_ttl = cached_query['expire'] - now
            if (calculated_ttl > DEFAULT_TTL):
                calculated_ttl = DEFAULT_TTL

            cached_packet.Rewrite(dns_id=client_dns_id, response_ttl=calculated_ttl)

            return cached_packet

    def IncrementCounter(self, domain):
        with self.domain_counter_lock:
            self.domain_counter[domain] += 1

    # automated process to flush the cache if expire time has been reached. runs every 1 minute.
    def AutoClear(self):
        while True:
            now = time.time()
            self.top_domains = {domain for count, domain in enumerate(self.domain_counter) \
                if count < TOP_DOMAIN_COUNT}
            query_cache = deepcopy(self.dns_cache)
            for domain, info in query_cache.items():
                if (info['expire'] > now and domain not in self.top_domains):
                    self.dns_cache.pop(domain, None)

            print('CLEARED EXPIRED CACHE.')

            time.sleep(5 * 60)

    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to generate
    # a new packet and add to the standard tls queue. the recieving end will know how to handle this by settings the client address
    # to none in the session tracker.
    def TopDomains(self):
        client_address = (None, None)
        while True:
            for domain in self.top_domains:
                cached_packet_info = self.dns_cache.get(domain, None)
                if (cached_packet_info):
                    # reverting the dns response packet to a standard query
                    packet = PacketManipulation(cached_packet_info['packet'], protocol=UDP)
                    packet.RevertResponse()

                    self.DNSRelay.TLSRelay.AddtoQueue(packet, client_address)

            print(f'RE CACHED TOP DOMAINS. TOTAL: {len(self.top_domains)}')
            # logging top domains in cache for reference. if top domains are useless, will work on a way to ensure only important domains
            # are cached. worst case can make them configurable.
            with open('top_domains_cached.txt', 'a+') as top_domains:
                top_domains.write(f'{self.top_domains}\n')

            time.sleep(5 * 60)


class TLSRelay:
    def __init__(self, DNSRelay):
        self.DNSRelay = DNSRelay

        self.dns_connection_tracker = {}
        self.dns_tls_queue = deque()

        self.unique_id_lock = threading.Lock()
        self.dns_queue_lock = threading.Lock()

    def AddtoQueue(self, packet, client_address):
        tcp_dns_id = self.GenerateIDandStore()
        dns_query = packet.UDPtoTLS(tcp_dns_id)

        ## Adding client connection info to tracker to be used by response handler
        self.dns_connection_tracker.update({tcp_dns_id: {'client_id': packet.dns_id, 'client_address': client_address}})

        self.dns_tls_queue.append(dns_query)

    ## Queue Handler will make a TLS connection to remote dns server/ start a response handler thread and send all requests
    # in queue over the connection.
    def ProcessQueue(self):
        while True:
            now = time.time()
#            with self.dns_queue_lock:
            if (not self.dns_tls_queue):
                # waiting 1ms before checking queue again for idle perf
                time.sleep(.001)
                continue

            for secure_server, server_info in self.DNSRelay.dns_servers.items():
                retry = now - server_info.get('retry', now)
                if (server_info['tls'] or retry >= self.DNSRelay.tls_retry):
                    secure_socket = self.Connect(secure_server)
                if (secure_socket):
                    self.QueryThreads(secure_socket)

                    break

    def QueryThreads(self, secure_socket):
        threading.Thread(target=self.ReceiveQueries, args=(secure_socket,)).start()
        time.sleep(.001)
        self.SendQueries(secure_socket)

    def SendQueries(self, secure_socket):
        try:
#            with self.dns_queue_lock:
            while self.dns_tls_queue:
                message = self.dns_tls_queue.popleft()

                secure_socket.send(message)

            secure_socket.shutdown(SHUT_WR)

        except error as E:
            print(f'TLSQUEUE | SEND: {E}')

    def ReceiveQueries(self, secure_socket):
        while True:
            try:
                data_from_server = secure_socket.recv(4096)
                if (not data_from_server):
                    break

                self.ParseServerResponse(data_from_server)
            except (timeout, error):
                break

        secure_socket.close()

    # Response Handler will match all recieved request responses from the server, match it to the host connection
    # and relay it back to the correct host/port. this will happen as they are recieved. the socket will be closed
    # once the recieved count matches the expected/sent count or from socket timeout
    def ParseServerResponse(self, data_from_server):
        try:
            # Checking the DNS ID in packet, Adjusted to ensure uniqueness
            packet = PacketManipulation(data_from_server, protocol=TCP)
            dns_id = packet.DNSID()
            # Checking client DNS ID and Address info to relay query back to host
            dns_query_info = self.dns_connection_tracker.get(dns_id, None)
            if (dns_query_info):
                packet.Parse()
                print(f'Secure Request Received from Server. DNS ID: {packet.dns_id} | {packet.request}')

                client_dns_id = dns_query_info.get('client_id')
                client_address = dns_query_info.get('client_address')
                ## Parsing packet and rewriting TTL to minimum 5 minutes/max 1 hour and changing DNS ID back to original.
                packet.Rewrite(dns_id=client_dns_id)

                client_ip, client_port = client_address
                # these vars will be set to none if it was a request generated by the caching system.
                if (client_ip and client_port):
                    self.DNSRelay.SendtoClient(packet, client_address)

                # adding packets to cache if not already in and incrimenting the counter for the requested domain.
                self.DNSRelay.DNSCache.Add(packet, client_address)
                self.DNSRelay.DNSCache.IncrementCounter(packet.request)

            #see if this can be in the if statement. cant remember why it was pulled out.
            self.dns_connection_tracker.pop(packet.dns_id, None)
        except ValueError:
            print(data_from_server)
            traceback.print_exc()
        except Exception:
            traceback.print_exc()

    # Acquire ID Lock, then generates a random number until a unique number is found. Once found
    # it will be stored and used for the external TLS query to ensure all requests are unique
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
        now = time.time()
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.bind((CLIENT_ADDRESS, 0))

            context = ssl.create_default_context()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

            # Wrap socket and Connect. If exception will return None which will have
            # the queue handler try the other server if available and will mark this
            # server as down

            secure_socket = context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, DNS_TLS_PORT))
        except error:
            secure_socket = None

        if (secure_socket):
            self.DNSRelay.dns_servers[secure_server].update({'tls': True})
        else:
            self.DNSRelay.dns_servers[secure_server].update({'tls': False, 'retry': now})

        return secure_socket

if __name__ == '__main__':
    Relay = DNSRelay()
    Relay.Start()
