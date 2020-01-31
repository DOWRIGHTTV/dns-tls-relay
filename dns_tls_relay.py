#!/usr/bin/env python3

import os, sys
import subprocess
import traceback
import time
import threading
import json
import random
import ssl
import select

from copy import deepcopy
from collections import deque, Counter
from socket import socket, timeout
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

import basic_tools as tools
from dns_packet_parser import RequestHandler, PacketManipulation

# toggle verbose command line outputs regarding application operation
VERBOSE = False

# address which the relay will receive dns requests
LISTENING_ADDRESS = '127.0.0.1'

# adress which the relay will use to talk to a public resolver
CLIENT_ADDRESS = '10.0.2.15'

# must support DNS over TLS (not https/443, tcp/853)
PUBLIC_SERVER_1 = '1.1.1.1'
PUBLIC_SERVER_2 = '1.0.0.1'

# protocol constants
TCP = 6
UDP = 17
A_RECORD = 1
NS_RECORD = 2
DNS_PORT = 53
DNS_TLS_PORT = 853
DEFAULT_TTL = 3600

DNS_QUERY = 0
TOP_DOMAIN_COUNT = 20
KEEP_ALIVE_DOMAIN = 'duckduckgo.com'


class DNSRelay:
    def __init__(self):
        self.dns_servers = {}
        self.dns_servers[PUBLIC_SERVER_1] = {'tls_up': True}
        self.dns_servers[PUBLIC_SERVER_2] = {'tls_up': True}

        self.request_map = {}
        self.unique_id_lock = threading.Lock()
        self.cache_lock = threading.Lock()

    def start(self):
        if (os.geteuid()):
            print('MUST RUN PROXY AS ROOT! Exiting...')
            sys.exit(1)

        self.DNSCache = DNSCache(self)
        self.TLSRelay = TLSRelay(self)

        threading.Thread(target=self.DNSCache.auto_clear_cache).start()
        threading.Thread(target=self.DNSCache.auto_top_domains).start()
        threading.Thread(target=self.TLSRelay.start).start()
        self._ready_interface_service()

    def _main(self):
        print(f'[+] Listening -> {LISTENING_ADDRESS}:{DNS_PORT}')
        while True:
            try:
                data_from_client, client_address = self.sock.recvfrom(1024)
                if (data_from_client):
#                    tools.p(f'Receved data from client: {client_address[0]}:{client_address[1]}.')
                    self.parse_queries(data_from_client, client_address)
            except OSError:
                break

        self._ready_interface_service()

    # if no parse errors will match IPv4 DNS queries (all others will be dropped) then send packet data
    # to be handled by cache or added to external resolver queue.
    def parse_queries(self, data_from_client, client_address):
        try:
            client_query = RequestHandler(data_from_client, client_address)
            client_query.parse()
        except Exception:
            traceback.print_exc()
        else:
            if (client_query.qr == DNS_QUERY and client_query.qtype in [A_RECORD, NS_RECORD]):
                self._process_query(client_query)

    def _process_query(self, client_query):
        if client_query.request and self.DNSCache.valid_top_domain(client_query.request):
            self.DNSCache.increment_counter(client_query.request)
        cached_packet = self.DNSCache.search(client_query)
        if (cached_packet):
            self.send_to_client(client_query, client_query.address)
            tools.p(f'CACHED RESPONSE | NAME: {client_query.request} TTL: {client_query.calculated_ttl}')
        else:
            self.external_query(client_query)

    def send_to_client(self, server_response, client_address):
        ## Relaying packet from server back to host
        self.sock.sendto(server_response.send_data, client_address)
        tools.p(f'Request: {server_response.request} RELAYED TO {client_address[0]}: {client_address[1]}')

    # will check to see if query is cached/ has been requested before. if not will add to queue for standard query
    def external_query(self, client_query):
        # this if for keep alive queries only so we can identify them on return and not process.
        if (not client_query.keepalive):
            new_dns_id = 69
        else:
            new_dns_id = self._generate_id_and_store()
        self.request_map[new_dns_id] = client_query
        client_query.generate_dns_query(new_dns_id)

        self.TLSRelay.add_to_queue(client_query)

    # parse all valid data from the server, get the client request object from request mapper dict,
    # then relay the dns message to the correct host/port. this will happen as they are recieved.
    def parse_server_response(self, data_from_server):
        server_response = PacketManipulation(data_from_server)
        dns_id = server_response.get_dns_id()
        client_query = self.request_map.pop(dns_id, None)
        if (not client_query):
            return

        try:
            server_response.parse()
        except Exception as E:
            print(f'RCV PARSE ERROR: {E}')
        else:
            tools.p(f'Secure Request Received from Server. DNS ID: {server_response.dns_id} | {server_response.request}')
            server_response.rewrite(dns_id=client_query.dns_id)
            if (client_query.address):
                ## Parsing packet and rewriting TTL to minimum 5 minutes/max 1 hour and changing DNS ID back to original.
                self.send_to_client(server_response, client_query.address)

            # adding packets to cache if not already in and incrimenting the counter for the requested domain.
            self.DNSCache.add(server_response, client_query.address)

    # Generate a unique DNS ID to be used by TLS connections only. Applies a lock on the function to ensure this
    # ID is thread safe and uniqueness is guranteed. IDs are stored in a dictionary for reference.
    def _generate_id_and_store(self):
        with self.unique_id_lock:
            while True:
                dns_id = random.randint(70, 32000)
                if (dns_id not in self.request_map):
                    self.request_map[dns_id] = 1

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
        except OSError:
            # failed to create socket. interface may be down.
            return True


class DNSCache:
    def __init__(self, DNSRelay):
        self.DNSRelay = DNSRelay
        self.dns_cache = {}

        self.domain_counter = Counter()
        self.top_domains = {}

        self.domain_counter_lock = threading.Lock()

        self._load_top_domains()

    # queries will be added to cache if it is not already cached or has expired or if the dns response is the
    # result from an internal dns request for top domains
    def add(self, server_response, client_address):
        now = time.time()
        expire = int(now) + server_response.cache_ttl
        already_cached = self.dns_cache.get(server_response.request, None)
        # will cache packet if not already cached or if it is from the top domains list(no client address)
        if ((not already_cached or already_cached['expire'] <= now or not client_address)
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
        print('[+] Starting automated standard cache clearing.')
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

            time.sleep(3*60)

    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to generate
    # a new packet and add to the standard tls queue. the recieving end will know how to handle this by settings the client address
    # to none in the session tracker.
    def auto_top_domains(self):
        print('[+] Starting automated top domains caching.')
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
            tools.write_cache(top_domains, 'top_domains_cache.json')

            time.sleep(3*60)

    # load top domains from file for persistence between restarts/shutdowns
    def _load_top_domains(self):
        dns_cache = tools.load_cache('top_domains_cache.json')
        self.top_domains = dns_cache['top_domains']

        temp_dict = reversed(list(self.top_domains))
        self.domain_counter = Counter({domain: count for count, domain in enumerate(temp_dict)})

        dns_cache_filter = tools.load_filter('top_domains_filter.json')
        self.top_domains_filter = dns_cache_filter['filter']

    def valid_top_domain(self, request):
        for td_filter in self.top_domains_filter:
            if (td_filter in request):
                return False

        return True


class TLSRelay:
    def __init__(self, DNSRelay):
        self.DNSRelay = DNSRelay

        self.dns_tls_queue = deque()
        self.socket_lock = threading.Lock()

        self.tls_context = self._create_tls_context()

    def add_to_queue(self, client_query):
        self.dns_tls_queue.append(client_query)

    def start(self):
        threading.Thread(target=self._tls_reachability).start()
        threading.Thread(target=self._tls_keepalive).start()

        self._server_connection_handler()
        threading.Thread(target=(self._recv_handler)).start()

        self._query_handler()

    # iterating over dns server list and calling to create a connection to first available server. this will only happen
    # if a socket connection isnt already established when attempting to send query.
    def _server_connection_handler(self):
        for secure_server, status in self.DNSRelay.dns_servers.items():
            if (status['tls_up']):
                error = self._tls_connect(secure_server)
                if (not error):
                    break
        else:
            tools.p('NO SECURE SERVER AVAILABLE!')

    # general loop for processing dns queries. if queue is empty will sleep for 1MS for idle performance.
    def _query_handler(self):
        print('[+] Started tls dns query handler thread.')
        while True:
            if (not self.dns_tls_queue):
                time.sleep(.001)
                continue

            client_query = self.dns_tls_queue.popleft()
            self._send_query(client_query)

    # attempt to send query, if socket error will reconnect and try again.
    def _send_query(self, client_query):
        for i in range(3):
            try:
                self.secure_socket.send(client_query.send_data)
                print(f'SENT SECURE [{i}]: {client_query.request}')
            except OSError:
                self._server_connection_handler()
                threading.Thread(target=self._recv_handler).start()
            else:
                break

    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self):
        try:
            while True:
                data_from_server = self.secure_socket.recv(1024)
                if (not data_from_server):
                    tools.p('PIPELINE CLOSED BY REMOTE SERVER!')
                    break
                self.DNSRelay.parse_server_response(data_from_server)
        except (timeout, OSError):
            pass
        finally:
           self.secure_socket.close()

    # attempt to connect to tls server sent in from server logic method. if connection fails, will return error else return none
    def _tls_connect(self, secure_server):
        tools.p(f'PIPELINE CLOSED. REESTABLISHING CONNECTION TO SERVER: {secure_server}.')
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(10)

            self.secure_socket = self.tls_context.wrap_socket(sock, server_hostname=secure_server)
            self.secure_socket.connect((secure_server, DNS_TLS_PORT))
        except OSError as e:
            return e

    # main loop to probe remote server for TLS connectivity to detect either downed, slow response(2 seconds), or non TLS
    # ready servers.
    def _tls_reachability(self):
        print('[+] Starting TLS reachability tests.')
        while True:
            for secure_server, server_info in self.DNSRelay.dns_servers.items():
                error = self._tls_reachability_worker(secure_server)
                if (error):
                    tools.p(f'TLS reachability failed for: {secure_server}')
                    server_info['tls_up'] = False
                else:
                    tools.p(f'TLS reachability successful for: {secure_server}')
                    server_info['tls_up'] = True

            time.sleep(60)

    # worker method for tls reachability functionality. will return error if failure to connect or timeout (2 seconds.)
    def _tls_reachability_worker(self, secure_server):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(2)

            secure_socket = self.tls_context.wrap_socket(sock, server_hostname=secure_server)
            secure_socket.connect((secure_server, DNS_TLS_PORT))
        except (OSError,timeout) as e:
            return e
        finally:
            secure_socket.close()

    # thread to ensure pipe to public server never idles to prevent remote end from forcing a disconnect. time might be
    # tuned depending, but dont want it to be too low, because under high load the remote end might need to close more
    # rapidly and that is something we must somewhat respect.
    def _tls_keepalive(self):
        while True:
            time.sleep(5)
            new_query = RequestHandler(None, None)
            new_query.set_required_fields(KEEP_ALIVE_DOMAIN, keepalive=True)
            self.DNSRelay.external_query(new_query)
            print('added keepalive to TLS queue')

    # general tls context used/reused by all sockets created for the tls relay. loading verify locations from file is slow.
    def _create_tls_context(self):
        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

        return context

if __name__ == '__main__':
    Relay = DNSRelay()
    Relay.start()
