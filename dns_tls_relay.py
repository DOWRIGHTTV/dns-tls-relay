#!/usr/bin/env python3

import os, sys
import traceback
import time
import threading
import random
import ssl
import socket
import select
import argparse

from sys import argv
from copy import copy
from collections import deque, Counter
from ipaddress import IPv4Address

import basic_tools as tools

from basic_tools import Log
from advanced_tools import relay_queue
from dns_tls_constants import * # pylint: disable=unused-wildcard-import
from dns_tls_protocols import TLSRelay
from dns_tls_packets import ClientRequest, ServerResponse

__all__ = (
    'DNSRelay'
)

class DNSRelay:
    protocol = PROTO.TCP
    tls_up = True # assuming servers are up on startup
    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.TCP: True},
        {'ip': None, PROTO.TCP: True}
    )

    _request_map = {}
    _records_cache = None
    _id_lock = threading.Lock()

    # dynamic inheritance reference
    _packet_parser = ClientRequest

    def __init__(self, l_ip):
        self._l_ip = l_ip

        if (self.is_service_loop):
            self._epoll = select.epoll()
            self._registered_socks = {}

            # assigning methods as local objects to prevent lookups
            self._epoll_poll = self._epoll.poll
            self._registered_socks_get = self._registered_socks.get

            threading.Thread(target=self.responder).start()

        self._records_cache_add = self._records_cache.add
        self._records_cache_search = self._records_cache.search
        self._request_map_pop = self._request_map.pop

    @classmethod
    def run(cls, listening_addresses):
        Log.console('INITIALIZING: Primary service.')

        # initializing dns cache/ sending in reference to needed methods for top domains
        cls._records_cache = DNSCache(
            packet=ClientRequest.generate_local_query,
            request_handler=cls._handle_query
        )

        # defining main epoll/ socket loop prior for register methods reference.
        service_loop = cls(None)

        # starting a registration thread for all available interfaces
        # upon registration the threads will exit
        for ip in listening_addresses:
            self = cls(ip)
            threading.Thread(target=self._register, args=(service_loop,)).start()

        TLSRelay.run(cls)

        # engaging epoll listener. local traffic processing starts here.
        service_loop._listener()

    def _register(self, listener):
        '''will register interface with listener. requires subclass property for listener_sock returning valid socket object.
        once registration is complete the thread will exit.'''

        Log.console(f'REGISTERING: {self._l_ip}.')

        l_sock = self.listener_sock

        listener._registered_socks[l_sock.fileno()] = l_sock
        listener._epoll.register(l_sock.fileno(), select.EPOLLIN)

        Log.console(f'COMPLETE: {self._l_ip}.')

    @tools.looper(NO_DELAY)
    def _listener(self):
        l_socks = self._epoll_poll()
        for fd, _ in l_socks:
            sock = self._registered_socks_get(fd)
            try:
                data, address = sock.recvfrom(2048)
            except OSError:
                continue # can happen if epoll returns, but packet invalid

            self._parse_packet(data, address, sock)

    def _parse_packet(self, data, address, sock):
        client_query = ClientRequest(data, address, sock)
        try:
            client_query.parse()
        except:
            traceback.print_exc()
        else:
            if (client_query.qr != DNS.QUERY or client_query.qtype not in [DNS.AR, DNS.NS] or client_query.dom_local): return

            if not self._cached_response(client_query):
                self._handle_query(client_query)

    def _cached_response(self, client_query):
        cached_dom = self._records_cache_search(client_query.request)
        if (not cached_dom.records): return False

        client_query.generate_cached_response(cached_dom)
        self.send_to_client(client_query, client_query)

        return True

    @classmethod
    def _handle_query(cls, client_query):
        new_dns_id = cls._get_unique_id()
        cls._request_map[new_dns_id] = client_query

        client_query.generate_dns_query(new_dns_id, cls.protocol)

        TLSRelay.relay.add(client_query)

    @classmethod
    # NOTE: maybe put a sleep on iteration, use a for loop?
    def _get_unique_id(cls):
        with cls._id_lock:
            while True:
                dns_id = random.randint(70, 32000)
                if (dns_id in cls._request_map): continue

                cls._request_map[dns_id] = 1

                return dns_id

    @relay_queue(Log, name='DNSRelay')
    def responder(self, server_response):
        server_response = ServerResponse(server_response)
        try:
            server_response.parse()
        except Exception:
            raise
        else:
            client_query = self._request_map_pop(server_response.dns_id, None)
            if (not client_query): return

            # generate response for client, if top domain generate for cache storage
            server_response.generate_server_response(client_query.dns_id)
            if (not client_query.top_domain):
                self.send_to_client(server_response, client_query)

            if (server_response.data_to_cache):
                self._records_cache_add(client_query.request, server_response.data_to_cache)

    @staticmethod
    def send_to_client(server_response, client_query):
        try:
            client_query.sock.sendto(server_response.send_data, client_query.address)
        except OSError:
            pass # socket will persist through errors.

    @property
    def listener_sock(self):
        l_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            l_sock.bind((str(self._l_ip), PROTO.DNS))
        except OSError:
            raise RuntimeError(f'{self._l_ip} was unable to bind!')
        else:
            l_sock.setblocking(0)
            l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        return l_sock

    @property
    def is_service_loop(self):
        '''boolean value representing whether current instance managing the epoll loop.'''
        return self._l_ip is None


class DNSCache(dict):
    '''subclass of dict to provide a custom data structure for dealing with the local caching of dns records.

    containers handled by class:
        general dict - standard cache storage
        private dict - top domains cache storage
        private Counter - tracking number of times domains are queried

    initialization is the same as a dict, with the addition of two required method calls for callback references
    to the dns server.

        set_query_generator(*reference to packet class*)
        set_query_handler(*reference to dns server request handler function*)

    if the above callbacks are not set the top domains caching system will actively update records, though the counts
    will still be accurate/usable.
    '''

    __slots__ = (
        # protected vars
        '_dns_packet', '_request_handler',

        # private vars
        '__dom_counter', '__top_domains',
        '__cnter_lock', '__top_dom_filter'
    )

    def __init__(self, *, packet=None, request_handler=None):
        self._dns_packet = packet
        self._request_handler = request_handler

        self.__dom_counter = Counter()
        self.__top_domains = {}
        self.__top_dom_filter = []
        self.__cnter_lock  = threading.Lock()

        self._load_top_domains()

        threading.Thread(target=self._auto_clear_cache).start()
        if (self._dns_packet and self._request_handler):
            threading.Thread(target=self._auto_top_domains).start()

    def __str__(self):
        return ' '.join([
            f'TOP DOMAIN COUNT: {len(self.__top_domains)} | TOP DOMAINS: {self.__top_domains}',
            f'CACHE SIZE: {sys.getsizeof(self)} | NUMBER OF RECORDS: {len(self)} | CACHE: {super().__str__()}'
        ])

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

    def add(self, request, data_to_cache):
        '''add query to cache after calculating expiration time.'''
        self[request] = data_to_cache

        Log.p(f'CACHE ADD | NAME: {request} TTL: {data_to_cache.ttl}')

    def search(self, query_name):
        '''if client requested domain is present in cache, will return namedtuple of time left on ttl
        and the dns records, otherwise will return None. top domain count will get automatically
        incremented if it passes filter.'''
        if (query_name):
            self._increment_if_valid_top(query_name)

        return self[query_name]

    def _increment_if_valid_top(self, domain):
        for fltr in self.__top_dom_filter:
            if (fltr in domain): break

        else:
            with self.__cnter_lock:
                self.__dom_counter[domain] += 1

    @tools.looper(FIVE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def _auto_clear_cache(self):
        cache, now = self.items, fast_time()
        expired = [dom for dom, record in cache() if now > record.expire]

        for domain in expired:
            del self[domain]

    @tools.looper(THREE_MIN)
    # automated process to keep top 20 queried domains permanently in cache. it will use the current caches packet to generate
    # a new packet and add to the standard tls queue. the recieving end will know how to handle this by settings the client address
    # to none in the session tracker.
    def _auto_top_domains(self):
        self.__top_domains = {dom[0]:cnt for cnt, dom
            in enumerate(self.__dom_counter.most_common(TOP_DOMAIN_COUNT), 1)}

        for domain in self.__top_domains:
            self._request_handler(self._dns_packet(domain))

        tools.write_cache(self.__top_domains)

    # loads top domains from file for persistence between restarts/shutdowns and top domains filter
    def _load_top_domains(self):
        dns_cache = tools.load_cache('top_domains')
        self.__top_domains = dns_cache['top_domains']
        self.__top_dom_filter = set(dns_cache['filter'])

        temp_dict = reversed(list(self.__top_domains))
        self.__dom_counter = Counter({domain: count for count, domain in enumerate(temp_dict)})
