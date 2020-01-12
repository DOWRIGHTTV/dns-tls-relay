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
from socket import socket, timeout, error
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

import basic_tools as tools
from dns_packet_parser import RequestHandler, PacketManipulation

# address which the relay will receive dns requests
LISTENING_ADDRESS = '127.0.0.1'

# adress which the relay will use to talk to a public resolver
CLIENT_ADDRESS = '192.168.5.135'

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
        self.dns_servers[PUBLIC_SERVER_1] = {'tls': True}
        self.dns_servers[PUBLIC_SERVER_2] = {'tls': True}

        self.request_mapper = {}
        self.unique_id_lock = threading.Lock()
        self.cache_lock = threading.Lock()

    def Start(self):
        self.DNSCache = DNSCache(self)
        self.TLSRelay = TLSRelay(self)

        threading.Thread(target=self.TLSRelay.tls_reachability).start()
        threading.Thread(target=self.DNSCache.auto_clear_cache).start()
        threading.Thread(target=self.DNSCache.auto_top_domains).start()
        threading.Thread(target=self.TLSRelay.process_queue).start()
        self._ready_interface_service()

    def _main(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((LISTENING_ADDRESS, DNS_PORT))

        tools.p(f'[+] Listening -> {LISTENING_ADDRESS}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(1024)
 #               tools.p(f'Receved data from client: {client_address[0]}:{client_address[1]}.')
                if (not data_from_client):
                    break

                self.parse_queries(data_from_client, client_address)
            except error:
                break

        self._ready_interface_service()

    def parse_queries(self, data_from_client, client_address):
        try:
            client_query = RequestHandler(data_from_client, client_address)
            client_query.parse()

            ## Matching IPV4 DNS queries only. All other will be dropped.
            if (not client_query.qr and client_query.qtype == A_RECORD):
                threading.Thread(target=self._process_query, args=(client_query,)).start()

        except Exception as E:
            tools.p(f'MAIN: {E}')

    def send_to_client(self, server_response, client_address):
        ## Relaying packet from server back to host
        self.sock.sendto(server_response.send_data, client_address)
        tools.p(f'Request: {server_response.request} RELAYED TO {client_address[0]}: {client_address[1]}')

    def _process_query(self, client_query):
        self.DNSCache.increment_counter(client_query.request)
        cached_packet = self.DNSCache.search(client_query)
        if (cached_packet):
            self.send_to_client(client_query, client_query.address)
            tools.p(f'CACHED RESPONSE | NAME: {client_query.request} TTL: {client_query.calculated_ttl}')
        else:
            self.external_query(client_query)

    # will check to see if query is cached/ has been requested before. if not will add to queue for standard query
    def external_query(self, client_query):
        new_dns_id = self._generate_id_and_store()
        self.request_mapper[new_dns_id] = client_query
        client_query.generate_dns_query(new_dns_id)

        self.TLSRelay.add_to_queue(client_query)

    # Generate a unique DNS ID to be used by TLS connections only. Applies a lock on the function to ensure this
    # id is thread safe and uniqueness is guranteed. IDs are stored in a dictionary for reference.
    def _generate_id_and_store(self):
        with self.unique_id_lock:
            while True:
                dns_id = random.randint(1, 32000)
                if (dns_id not in self.request_mapper):
                    self.request_mapper.update({dns_id: 1})

                    return dns_id

    def _ready_interface_service(self):
        while True:
            error = self._create_service_socket()
            if (error):
                time.sleep(1)
                continue

            self._main()

    def _create_service_socket(self):
        try:
            self.sock = socket(AF_INET, SOCK_DGRAM)
            self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.sock.bind((LISTENING_ADDRESS, DNS_PORT))
        except error:
            # failed to create socket. interface may be down.
            return True


class DNSCache:
    def __init__(self, DNSRelay):
        self.DNSRelay = DNSRelay
        self.dns_cache = {}

        self.domain_counter = Counter()
        self.top_domains = {}

        self.domain_counter_lock = threading.Lock()

    # queries will be added to cache if it is not already cached or has expired or if the dns response is the
    # result from an internal dns request for top domains
    def add(self, server_response, client_address):
        now = time.time()
        expire = int(now) + server_response.cache_ttl
        already_cached = self.dns_cache.get(server_response.request, None)
        # will cache packet if not already cached or if it is from the top domains list(no client address)
        if ((not already_cached or already_cached['expire'] <= now) or (not client_address)
                and server_response.data_to_cache):
            self.dns_cache.update({
                server_response.request: {
                    'records': server_response.data_to_cache,
                    'expire': expire,
                    'normal_cache': bool(client_address)
                    }
                })

            tools.p(f'CACHE ADD | NAME: {server_response.request} TTL: {server_response.cache_ttl}')

    def search(self, client_query):
        now = int(time.time())
        cached_query = self.dns_cache.get(client_query.request, None)
        if (cached_query and cached_query['expire'] > now):
            records = cached_query['records']
            calculated_ttl = cached_query['expire'] - now
            if (calculated_ttl > DEFAULT_TTL):
                calculated_ttl = DEFAULT_TTL

            client_query.generate_cached_response(calculated_ttl, records)

            return True

    def increment_counter(self, domain):
        with self.domain_counter_lock:
            self.domain_counter[domain] += 1

    # automated process to flush the cache if expire time has been reached. runs every 1 minute.
    def auto_clear_cache(self):
        while True:
            now = time.time()
            query_cache = deepcopy(self.dns_cache)
            for domain, info in query_cache.items():
                if (info['expire'] < now and domain not in self.top_domains):
                    self.dns_cache.pop(domain, None)

            # here for testing purposes || consider reporting the cache size to the front end
#            tools.p('CLEARED EXPIRED CACHE.')
            cache_size = sys.getsizeof(self.dns_cache)
            num_records = len(self.dns_cache)
            tools.p(f'CACHE SIZE: {cache_size} | NUMBER OF RECORDS: {num_records} | CACHE: {self.dns_cache}')

#            time.sleep(5*60)
            time.sleep(10)

    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to generate
    # a new packet and add to the standard tls queue. the recieving end will know how to handle this by settings the client address
    # to none in the session tracker.
    def auto_top_domains(self):
        while True:
            self.top_domains = {domain[0]:count for count, domain
                in enumerate(self.domain_counter.most_common(TOP_DOMAIN_COUNT), 1)}

            for domain in self.top_domains:
                # creating empty class object, then assigning required fields. this will allow compatibility with standard server
                # operations for locally generated requests/queries
                new_query = RequestHandler(None, None)
                new_query.set_required_fields(domain)
                self.DNSRelay.external_query(new_query)

            tools.p(f'RE CACHED TOP DOMAINS. TOTAL: {len(self.top_domains)}')
            # logging top domains in cache for reference. if top domains are useless, will work on a way to ensure only important domains
            # are cached. worst case can make them configurable.
            top_domains = {'top_domains': self.top_domains}
            with open('top_domains_cache.txt', 'a+') as top_domains:
                top_domains.write(f'{self.top_domains}\n')

#            time.sleep(3*60)
            time.sleep(15)


class TLSRelay:
    def __init__(self, DNSRelay):
        self.DNSRelay = DNSRelay

        self.dns_tls_queue = deque()

        self.secure_socket = None
        self.socket_available = False

        self.tls_context = self._create_tls_context()

    def add_to_queue(self, client_query):
        self.dns_tls_queue.append(client_query)

    def process_queue(self):
        while True:
            if (not self.dns_tls_queue):
            # waiting 1ms before checking queue again for idle perf
                time.sleep(.001)
                continue

            client_query = self.dns_tls_queue.popleft()
            # if socket is not available, we will attempt to connect to remote servers before sending request
            if (not self.secure_socket):
                self._logic_handler()
            else:
                tools.p('PIPELINING REQUEST.')

            if (self.secure_socket):
                self._send_query(client_query)

    # Iterating over dns server list and calling to create a connection to first available. this will only happen
    # if a socket connection isnt already established.
    def _logic_handler(self):
        for secure_server, status in self.DNSRelay.dns_servers.items():
            if (status['tls']):
                error = self._tls_connect(secure_server)
                if (not error):
                    break
        else:
            tools.p('NO SECURE SERVER AVAILABLE!')

    def _send_query(self, client_query):
        try:
            tools.p(f'SENDING SECURE DATA FOR REQUEST: {client_query.request}')
            self.secure_socket.sendall(client_query.send_data)
        except error:
            self.secure_socket.close()
            self.secure_socket = None

    def _receive_queries(self):
        try:
            while True:
                data_from_server = self.secure_socket.recv(4096)
                if (not data_from_server):
                    tools.p('PIPELINE CLOSED BY REMOTE SERVER.')
                    break

                self._parse_server_response(data_from_server)
        except (timeout, error) as e:
            tools.p(e)
        finally:
            self.secure_socket.close()
            self.secure_socket = None

    # Response Handler will match all recieved request responses from the server, match it to the host connection
    # and relay it back to the correct host/port. this will happen as they are recieved. the socket will be closed
    # once the recieved count matches the expected/sent count or from socket timeout
    def _parse_server_response(self, data_from_server):
        # Checking the DNS ID in packet, Adjusted to ensure uniqueness
        server_response = PacketManipulation(data_from_server)
        dns_id = server_response.get_dns_id()
#        tools.p(f'RECEIVED SOMETHING| ID: {dns_id} | MAPPER: {self.DNSRelay.request_mapper}')
        # Checking client DNS ID and Address info to relay query back to host
        client_query = self.DNSRelay.request_mapper.pop(dns_id, None)
        if (client_query):
            server_response.parse()
            tools.p(f'Secure Request Received from Server. DNS ID: {server_response.dns_id} | {server_response.request}')
            server_response.rewrite(dns_id=client_query.dns_id)
            if (client_query.address):
                ## Parsing packet and rewriting TTL to minimum 5 minutes/max 1 hour and changing DNS ID back to original.
                self.DNSRelay.send_to_client(server_response, client_query.address)

            # adding packets to cache if not already in and incrimenting the counter for the requested domain.
            self.DNSRelay.DNSCache.add(server_response, client_query.address)

    # Connect will retry 3 times if issues, then mark TLS server as inactive and timestamp
    # timestamp will be used to re attempt to connect after retry limit exceeded in message
    # queue handler method
    def _tls_connect(self, secure_server):
        tools.p(f'PIPELINE CLOSED. REESTABLISHING CONNECTION TO SERVER: {secure_server}.')
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(30)

            # Wrap socket and Connect. If exception will return None which will have
            # the queue handler try the other server if available and will mark this
            # server as down
            self.secure_socket = self.tls_context.wrap_socket(sock, server_hostname=secure_server)
            self.secure_socket.connect((secure_server, DNS_TLS_PORT))

            threading.Thread(target=self._receive_queries).start()
        except error as e:
            self.secure_socket = None
            return e

    def _create_tls_context(self):
        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

        return context

    def tls_reachability(self):
        while True:
            for secure_server in self.DNSRelay.dns_servers.keys():
                error = self._tls_connection_handler(secure_server)
                if error:
                    tools.p(f'TLS reachability failed for: {secure_server}')
                    self.DNSRelay.dns_servers[secure_server].update({'tls': False})
                else:
                    tools.p(f'TLS reachability successful for: {secure_server}')
                    self.DNSRelay.dns_servers[secure_server].update({'tls': True})

            time.sleep(10)

    def _tls_connection_handler(self, secure_server):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(2)
            secure_socket = self.tls_context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, DNS_TLS_PORT))
        except (error,timeout) as e:
            return e
        finally:
            secure_socket.close()

if __name__ == '__main__':
    Relay = DNSRelay()
    Relay.Start()
