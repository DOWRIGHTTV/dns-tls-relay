#!/usr/bin/env python3

import time
import threading
import ssl
import socket

from collections import deque

import basic_tools as tools
from basic_tools import Log
from advanced_tools import DNXQueue
from dns_tls_constants import * # pylint: disable=unused-wildcard-import
from dns_tls_packets import ClientRequest


class _ProtoRelay:
    '''parent class for udp and tls relays providing standard built in methods to start, check status, or add
    jobs to the work queue.'''
    _protocol  = PROTO.NOT_SET
    queue = DNXQueue(Log)

    __run = False
    __slots__ = (
        # callbacks
        'DNSRelay', '_fallback',

        # protected vars
        '_relay_conn', '_send_cnt', '_last_sent'
    )
    # if (_dns_queue is None):
    #     raise NotImplementedError('_dns_queue must be overridden in subclass.')

    def __new__(cls, *args, **kwargs):
        if (cls is _ProtoRelay):
            raise TypeError('Listener can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, DNSRelay):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        if (self.__run is False):
            raise TypeError(f'{self.__class__.__name__} must be started through run class method.')

        Log.console(f'INITIALIZING: {self.__class__.__name__}')

        self.DNSRelay = DNSRelay
        self._relay_conn = RELAY_CONN(None, socket.socket())

        self._send_cnt  = 0
        self._last_sent = 0

        threading.Thread(target=self.__fail_detection).start()
        threading.Thread(target=self.__queue_handler, args=(self,)).start()

    @classmethod
    def run(cls, DNSRelay):
        '''starts the protocol relay. DNSRelay object is the class handling client side requests which
        we can call back to. all internal process will be called as threads then will return.'''
        cls.__run = True

        cls(DNSRelay)

    # @classmethod
    # def add_to_queue(cls, client_query):
    #     '''add query to protocol specific dns queue.'''
    #     cls._dns_queue.add(client_query)

    @queue
    def __queue_handler(self, client_query):
        '''main relay process for handling the relay queue. will block and run forever.

        May be overridden.

        '''
        self.__send_query(client_query)

    def __send_query(self, client_query):
        for attempt in range(2):
            try:
                self._relay_conn.sock.send(client_query.send_data)
                Log.console(f'SENT SECURE[{attempt}]: {client_query.request}')
            except OSError:
                if not self._register_new_socket(): break

                threading.Thread(target=self._recv_handler).start()
            else:
                self._increment_fail_detection()
                break

    def _recv_handler(self):
        '''called in a thread after creating new socket to handle all responses from remote server.'''

        raise NotImplementedError('_recv_handler method must be overridden in subclass.')

    def _register_new_socket(self):
        '''logic to create socket object used for external dns queries.'''

        raise NotImplementedError('_register_new_socket method must be overridden in subclass.')

    @tools.looper(FIVE_SEC)
    def __fail_detection(self):
        now = time.time()
        Log.p(f'NOTICE: fail detection | now={now}, last_sent={self._last_sent}, send_count={self._send_cnt}')
        if (now - self._last_sent >= FIVE_SEC
                and self._send_cnt >= HEARTBEAT_FAIL_LIMIT):

            self.mark_server_down()

    def mark_server_down(self):
        if (self.socket_available):
            self._relay_conn.sock.close()
            Log.p(f'NOTICE: {self._relay_conn.remote_ip} failed to respond to 3 messages. marking as down.')

            for server in self.DNSRelay.dns_servers:
                if (server['ip'] == self._relay_conn.remote_ip):
                    server[self._protocol] = False

    def _reset_fail_detection(self):
        self._send_cnt = 0

#        Log.p(f'reset fail detection | count={self._send_cnt}')

    def _increment_fail_detection(self):
        self._send_cnt += 1
        self._last_sent = time.time()

#        Log.p(f'NOTICE: fail detection | count={self._send_cnt}, last_seen={self._last_sent}')

    @property
    def socket_available(self):
        '''returns true if current relay socket object has not been closed.'''
        if (self._relay_conn.sock.fileno() != NOT_VALID): return True

        return False

    @staticmethod
    def is_keepalive(data):
        if (short_unpackf(data)[0] == DNS.KEEPALIVE): return True

        return False


class TLSRelay(_ProtoRelay):
    _protocol   = PROTO.TCP
    _keepalives = KEEPALIVES_ENABLED
    _dns_packet = ClientRequest.generate_keepalive

    __slots__ = (
        '_tls_context'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._create_tls_context()
        threading.Thread(target=self._tls_keepalive).start()
        threading.Thread(target=Reachability.run, args=(self.DNSRelay,)).start()

    # iterating over dns server list and calling to create a connection to first available server. this will only happen
    # if a socket connection isnt already established when attempting to send query.
    def _register_new_socket(self, client_query=None):
        for secure_server in self.DNSRelay.dns_servers:
            if (not secure_server[self._protocol]): continue

            if self._tls_connect(secure_server['ip']): return True

            self.mark_server_down()
        else:
            Log.p('NO SECURE SERVERS AVAILABLE!')
            self.DNSRelay.tls_up = False

    # receive data from server. if dns response will call parse method else will close the socket.
    def _recv_handler(self):
        recv_buffer = []
        while True:
            try:
                data_from_server = self._relay_conn.sock.recv(1024)
            except (socket.timeout, OSError) as e:
                Log.p(f'RECV HANDLER: {e}')
                break

            else:
                self._reset_fail_detection()
                if (not data_from_server):
                    Log.p('RECV HANDLER: PIPELINE CLOSED BY REMOTE SERVER!')
                    break

                recv_buffer.append(data_from_server)
                while recv_buffer:
                    current_data = b''.join(recv_buffer)[2:]
                    data_len = short_unpackf(recv_buffer[0])[0]
                    if (len(current_data) == data_len):
                        recv_buffer = []
                    elif (len(current_data) > data_len):
                        recv_buffer = [current_data[data_len:]]
                    else: break

                    if not self.is_keepalive(current_data):
                        self.DNSRelay.queue.add(current_data[:data_len])

        self._relay_conn.sock.close()

#    @profiler
    def _tls_connect(self, secure_server):
        Log.p(f'Opening Secure socket to {secure_server}: 853')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # NOTE: this should improve sending performance since we expect a dns record to only be a small
        # portion of available bytes in MTU/max bytes(1500). seems to provide no improvement after 1 run.
        # there could be other bottlenecks in play so we can re evaluate later.
        # sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        dns_sock = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            dns_sock.connect((secure_server, PROTO.DNS_TLS))
        except OSError:
            return None
        else:
            return True
        finally:
            self._relay_conn = RELAY_CONN(secure_server, dns_sock)

    @tools.looper(KEEPALIVE_INTERVAL)
    # will send a valid dns query every ^ seconds to ensure the pipe does not get closed by remote server for
    # inactivity. this is only needed if servers are rapidly closing connections and can be enable/disabled.
    def _tls_keepalive(self):
        if (not self._keepalives): return

        self.queue.add(self._dns_packet(KEEP_ALIVE_DOMAIN, self._protocol))

    def _create_tls_context(self):
        self._tls_context = ssl.create_default_context()
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')


class Reachability:
    __slots__ = (
        'DNSRelay', '_protocol', '_tls_context', '_udp_query'
    )
    def __init__(self, DNSRelay):
        self._protocol = PROTO.TCP
        self.DNSRelay = DNSRelay

        self._create_tls_context()

    @classmethod
    def run(cls, DNSRelay):
        '''starting remote server responsiveness detection as a thread. the remote servers will only
        be checked for connectivity if they are mark as down during the polling interval.'''

        self = cls(DNSRelay)
        threading.Thread(target=self.tls).start()

    @tools.dyn_looper
    def tls(self):
        if (not self.is_enabled): return TEN_SEC

        for secure_server in self.DNSRelay.dns_servers:
            if (secure_server[self._protocol]): continue # not checking if server/proto is known up

            if self._tls_reachable(secure_server['ip']):
                secure_server[self._protocol] = True
                self.DNSRelay.tls_up = True

                Log.p('NOTICE: TLS server {} has recovered.'.format(secure_server['ip']))

        return THIRTY_SEC

    def _tls_reachable(self, secure_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        secure_socket = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            secure_socket.connect((secure_server, PROTO.DNS_TLS))
        except (OSError, socket.timeout):
            return False
        else:
            return True
        finally:
            secure_socket.close()

    def _create_tls_context(self):
        self._tls_context = ssl.create_default_context()
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

    @property
    def is_enabled(self):
        return self._protocol == self.DNSRelay.protocol
