#!/usr/bin/env python3

import threading
import socket
import select

from random import randint
from collections import Counter

import basic_tools as tools

from dns_tls_constants import *

from basic_tools import Log
from advanced_tools import relay_queue

from dns_tls_protocols import TLSRelay, Reachability
from dns_tls_packets import ClientRequest, ttl_rewrite

__all__ = (
    'DNSRelay'
)


class DNSRelay:
    protocol = PROTO.DNS_TLS

    # flag used to check status of relay. if one remote server is up, tls_up=True. both remote servers have to be down
    # for tls_up=False.
    tls_up = False
    keepalive_interval = 0

    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.DNS_TLS: False},
        {'ip': None, PROTO.DNS_TLS: False}
    )

    _epoll = select.epoll()
    _registered_socks = {}
    _request_map = {}
    _id_lock = threading.Lock()

    def __init__(self):
        threading.Thread(target=self.responder).start()

        # assigning object methods to prevent lookup
        self._request_map_pop = self._request_map.pop

        self._records_cache_add = self._records_cache.add
        self._records_cache_search = self._records_cache.search

    @classmethod
    def run(cls, listening_addresses, keepalive_interval):
        Log.system('Initializing primary service...')

        cls.keepalive_interval = keepalive_interval

        # running main epoll/ socket loop. threaded so proxy and server can run side by side
        # NOTE: threading.Thread(target=service_loop._listener).start() starting a registration thread for all available
        # interfaces. once registered the threads will exit.
        for ip_addr in listening_addresses:
            threading.Thread(target=cls._register, args=(f'{ip_addr}',)).start()

        Reachability.run(cls)
        TLSRelay.run(cls)

        # initializing dns cache/ sending in reference to needed methods for top domains
        cls._records_cache = DNSCache(
            dns_packet=ClientRequest.generate_local_query,
            request_handler=cls._handle_query
        )

        threading.Thread(target=cls()._listener).start()

    @classmethod
    def _register(cls, listener_ip):
        '''will register interface with listener. requires subclass property for listener_sock returning valid socket
         object. once registration is complete the thread will exit.'''

        Log.system(f'[{listener_ip}] Started registration.')

        l_sock = cls._listener_sock(listener_ip)
        cls._registered_socks[l_sock.fileno()] = L_SOCK(listener_ip, l_sock, l_sock.sendto, l_sock.recvfrom)

        cls._epoll.register(l_sock.fileno(), select.EPOLLIN)

        Log.system(f'[{listener_ip}][{l_sock.fileno()}] Listener registered.')

    def _listener(self):
        epoll_poll = self._epoll.poll
        registered_socks_get = self._registered_socks.get
        parse_packet = self._parse_packet

        for _ in RUN_FOREVER():

            l_socks = epoll_poll()
            for fd, _ in l_socks:

                sock = registered_socks_get(fd)

                try:
                    data, address = sock.recvfrom(2048)

                # can happen if poll returns, but packet invalid
                except OSError:
                    continue

                parse_packet(data, address, sock)

    def _parse_packet(self, data, address, sock):
        client_query = ClientRequest(address, sock)
        try:
            local_domain = client_query.parse(data)
        except Exception as E:
            Log.error(f'[parser/client request] {E}')
        else:
            # if query flag is not set the packet will be assumed malformed and silently dropped
            if (local_domain or client_query.qr != DNS.QUERY): return

            # A and NS records will have a cache pre-check before sending out
            if (client_query.qtype in [DNS.A, DNS.NS]):

                # no further action is required if cache contains matching record, otherwise request will be processed,
                # then added to queue for secure transmission to remote resolver.
                if not self._cached_response(client_query):
                    self._handle_query(client_query)

            # AAAA records does not get cached so the check will be skipped
            elif (client_query.qtype in [DNS.AAAA]):
                self._handle_query(client_query)

            # NOTE: a request reaching this point falls outside the scope of the relay and will be silently dropped

    def _cached_response(self, client_query):
        '''search cache for qname. if a record is found, a response will be generated and sent back to the client.'''

        cached_dom = self._records_cache_search(client_query.qname)
        if (cached_dom.records):

            client_query.generate_cached_response(cached_dom)
            self.send_to_client(client_query.send_data, client_query)

            return True

    @classmethod
    def _handle_query(cls, client_query):
        new_dns_id = cls._get_unique_id()
        cls._request_map[new_dns_id] = client_query

        client_query.generate_dns_query(new_dns_id)

        TLSRelay.relay.add(client_query)

    @classmethod
    def _get_unique_id(cls):
        request_map = cls._request_map

        with cls._id_lock:
            # NOTE: maybe tune this number. under high load collisions could occur and we don't want it to waste time
            # because other requests must wait for this process to complete since we are now using a queue system for
            # while waiting for a decision instead of individual threads.
            for _ in range(100):

                dns_id = randint(70, 32000)
                if (dns_id not in request_map):

                    request_map[dns_id] = 1

                    return dns_id

    @relay_queue(Log, name='DNSRelay')
    def responder(self, received_data):
        # dns id is the first 2 bytes in the dns header
        dns_id = short_unpackf(received_data)[0]

        client_query = self._request_map_pop(dns_id, None)
        if (not client_query):
            return

        try:
            server_response, cache_data = ttl_rewrite(received_data, client_query.dns_id)
        except Exception as E:
            Log.error(f'[parser/server response] {E}')
        else:
            if (dns_id != DNS.TOP_DOMAIN):
                self.send_to_client(server_response, client_query)

            if (cache_data):
                self._records_cache_add(client_query.qname, cache_data)

    @staticmethod
    def send_to_client(server_response, client_query):
        try:
            client_query.sendto(server_response, client_query.address)
        except OSError:
            Log.error(f'[send] Failed response to {client_query.address}.')

    @staticmethod
    def _listener_sock(listen_ip):
        l_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            l_sock.bind((f'{listen_ip}', PROTO.DNS))
        except OSError:
            Log.error(f'[{listen_ip}] Failed to bind address!')
            hard_out()

        l_sock.setblocking(False)
        l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        return l_sock


class DNSCache(dict):
    '''subclass of dict to provide a custom data structure for dealing with the local caching of dns records.

    containers handled by class:
        general dict - standard cache storage
        private Counter - tracking number of times domains are queried

    initialization is the same as a dict, with the addition of two required method calls for callback references
    to the dns server.

        packet (*reference to packet class*)
        request_handler (*reference to dns server request handler function*)

    if the above callbacks are not set the top domains caching system will NOT actively update records, though the counts
    will still be accurate/usable.
    '''

    __slots__ = (
        '_dns_packet', '_request_handler',

        '_dom_counter', '_top_domains',
        '_cnter_lock', '_top_dom_filter'
    )

    def __init__(self, *, dns_packet=None, request_handler=None):
        self._dns_packet = dns_packet
        self._request_handler = request_handler

        self._dom_counter = Counter()
        self._top_dom_filter = []
        self._cnter_lock  = threading.Lock()

        self._load_top_domains()
        threading.Thread(target=self._auto_clear_cache).start()
        if (dns_packet and request_handler):
            threading.Thread(target=self._auto_top_domains).start()

    # searching key directly will return calculated ttl and associated records
    def __getitem__(self, key):
        # filtering root lookups from checking cache
        if (not key):
            return DNS_CACHE(NOT_VALID, None)

        record = dict.__getitem__(self, key)
        # not present
        if (record == NOT_VALID):
            return DNS_CACHE(NOT_VALID, None)

        calcd_ttl = record.expire - int(fast_time())
        if (calcd_ttl > DEFAULT_TTL):
            return DNS_CACHE(DEFAULT_TTL, record.records)

        elif (calcd_ttl > 0):
            return DNS_CACHE(calcd_ttl, record.records)
        # expired
        else:
            return DNS_CACHE(NOT_VALID, None)

    # if missing will return an expired result
    def __missing__(self, key):
        return NOT_VALID

    def add(self, qname, data_to_cache):
        '''add query to cache after calculating expiration time.'''
        self[qname] = data_to_cache

        Log.verbose(f'[{qname}:{data_to_cache.ttl}] Added to standard cache. ')

    def search(self, qname):
        '''if client requested domain is present in cache, will return namedtuple of time left on ttl
        and the dns records, otherwise will return None. top domain count will get automatically
        incremented if it passes filter.'''

        self._increment_if_valid_top(qname)

        return self[qname]

    def _increment_if_valid_top(self, domain):
        # list comp result will be a list containing any filter string found within the domain. if the list contains
        # anything, then we know the domain being resolved should not be included in top domains cache. This could
        # be used later to identify which filters are being hit and which are not effective.
        if (domain and not [fltr for fltr in self._top_dom_filter if fltr in domain]):
            with self._cnter_lock:
                self._dom_counter[domain] += 1

    @tools.looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def _auto_clear_cache(self):
        now = fast_time()
        expired = [dom for dom, record in self.items() if now > record.expire]

        for domain in expired:
            del self[domain]

    @tools.looper(THREE_MIN)
    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to
    # generate a new packet and add to the standard tls queue. the receiving end will know how to handle this by
    # settings the client address to none in the session tracker.
    def _auto_top_domains(self):
        top_domains = {
            dom[0]: cnt for cnt, dom in enumerate(self._dom_counter.most_common(TOP_DOMAIN_COUNT), 1)
        }

        request_handler, dns_packet = self._request_handler, self._dns_packet
        for domain in top_domains:
            request_handler(dns_packet(domain))
            fast_sleep(.1)

        tools.write_cache(top_domains)

    # loads top domains from file for persistence between restarts/shutdowns and top domains filter
    def _load_top_domains(self):
        dns_cache = tools.load_cache('top_domains')

        self._top_dom_filter = set(dns_cache['filter'])

        self._dom_counter = Counter({
            domain: count for count, domain in enumerate(reversed(list(dns_cache['top_domains'])))
        })
