#!/usr/bin/env python3

import threading
import ssl

from socket import socket, AF_INET, SOCK_STREAM

from dns_tls_constants import *

from basic_tools import Log, looper
from advanced_tools import relay_queue, Initialize

from dns_tls_packets import ClientRequest


class ProtoRelay:
    '''parent class for udp and tls relays providing standard built in methods to start, check status, or add jobs to
     the work queue. '''
    _protocol  = PROTO.NOT_SET

    __slots__ = (
        'DNSRelay', '_relay_conn', '_responder_add',

        '_send_cnt', '_last_rcvd',
    )

    def __new__(cls, *args, **kwargs):
        if (cls is ProtoRelay):
            raise TypeError('ProtoRelay can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, DNSRelay):
        '''general constructor. can only be reached through subclass.

        May be expanded.

        '''
        self.DNSRelay = DNSRelay

        sock = socket()
        self._relay_conn = RELAY_CONN(None, sock, sock.send, sock.recv, None)

        self._send_cnt  = 0
        self._last_rcvd = 0

    @classmethod
    def run(cls, DNSRelay):
        '''starts the protocol relay. DNSServer object is the class handling client side requests which we can call back
        to and fallback is a secondary relay that can get forwarded a request post failure. initialize will be called
        to run any subclass specific processing then query handler will run indefinitely.'''
        self = cls(DNSRelay)

        threading.Thread(target=self._fail_detection).start()
        threading.Thread(target=self.relay).start()

    def relay(self):
        '''main relay process for handling the relay queue. will block and run forever.'''

        raise NotImplementedError('relay must be implemented in the subclass.')

    def _send_query(self, client_query):
        for attempt in [0, 1]:
            try:
                self._relay_conn.send(client_query.send_data)
            except OSError:
                if not self._register_new_socket(): return

                threading.Thread(target=self._recv_handler).start()

            else:
                break

        # incrementing fail detection count
        self._send_cnt += 1

        # general log for queries being sent which also shows if new tls connection had to be established.
        Log.console(
            f'[{self._relay_conn.remote_ip}/{self._relay_conn.version}][{attempt}] Sent {client_query.qname}'
        )

    def _recv_handler(self):
        '''called in a thread after creating new socket to handle all responses from remote server.'''

        raise NotImplementedError('_recv_handler method must be overridden in subclass.')

    def _register_new_socket(self):
        '''logic to create socket object used for external dns queries.'''

        raise NotImplementedError('_register_new_socket method must be overridden in subclass.')

    @looper(FIVE_SEC)
    def _fail_detection(self):
        if (fast_time() - self._last_rcvd >= FIVE_SEC and self._send_cnt >= HEARTBEAT_FAIL_LIMIT):
            self.mark_server_down()

    # processes that were unable to connect/ create a socket will send in the remote server ip that was attempted. if a
    # remote server isn't specified the active relay socket connection's remote ip will be used. we dont know which
    # ip goes to which server position so we have to iterate over the pair and match. this works out better because
    # it allows us to not have to track position/server ips, especially when users can change them while running (only
    # applicable to dnxfirewall, but i want the codebase to emulate one another.)
    def mark_server_down(self, *, remote_server=None):
        remote_server = remote_server if remote_server else self._relay_conn.remote_ip

        for server in self.DNSRelay.dns_servers:
            if (server['ip'] != remote_server): continue

            server[self._protocol] = False

            # keeping this under the remote/server ip match condition
            try:
                self._relay_conn.sock.close()
            except:
                Log.error(f'[{self._relay_conn.remote_ip}] Failed to close socket while marking server down.')


class TLSRelay(ProtoRelay):
    _protocol   = PROTO.DNS_TLS
    _keepalives = KEEPALIVES_ENABLED
    _dns_packet = ClientRequest.generate_keepalive

    __slots__ = (
        '_tls_context', 'keepalive_status'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # INITIALIZING TLS CONTEXT
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.verify_mode = ssl.CERT_REQUIRED
        tls_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

        self._tls_context = tls_context

        self.keepalive_status = threading.Event()

        threading.Thread(target=self._keepalive_run).start()

    # iterating over dns server list and calling to create a connection to first available server. this will only happen
    # if a socket connection isn't already established when attempting to send query.
    def _register_new_socket(self, client_query=None):
        for tls_server in self.DNSRelay.dns_servers:

            # skipping over known down server
            if (not tls_server[self._protocol]): continue

            # attempt to connect. if successful will return True, otherwise mark server as down and try next server.
            if self._tls_connect(tls_server['ip']): return True

            self.mark_server_down(remote_server=tls_server['ip'])

        else:
            self.DNSRelay.tls_up = False

            Log.console(f'[{self._protocol}] No DNS servers available.')

    @relay_queue(Log, name='TLSRelay')
    # NOTE: this function seems basic, but was stripped down from dnxfirewall which contains ability to fallback to UDP.
    def relay(self, client_query):

        self._send_query(client_query)

    # receive data from server. if dns response will call parse method else will close the socket.
    # NOTE: only one recv handler will be active at a time so the mutable argument is safe from shared state
    def _recv_handler(self, recv_buffer=[]):
        Log.verbose(f'[{self._relay_conn.remote_ip}/{self._protocol.name}] Remote server response handler started.')
        recv_buff_append = recv_buffer.append
        recv_buff_clear  = recv_buffer.clear
        conn_recv = self._relay_conn.recv
        responder_add = self.DNSRelay.responder.add

        while True:
            try:
                data_from_server = conn_recv(2048)
            except TimeoutError:
                # will close the socket as part of the marking process
                self.mark_server_down()

                Log.error(f'[{self._relay_conn.remote_ip}/{self._protocol.name}] Remote server timeout, marked down.')

                return

            except OSError:
                break

            else:
                # if no data is received/EOF the remote end has closed the connection
                if (not data_from_server): break

                # resetting fail detection
                self._last_rcvd = fast_time()
                self._send_cnt = 0

                # resetting keepalive to configured interval
                self._keepalive_reset()

                recv_buff_append(data_from_server)
                while recv_buffer:
                    current_data = byte_join(recv_buffer)
                    data_len, data = short_unpackf(current_data)[0], current_data[2:]

                    # more data is needed for a complete response. NOTE: this scenario is kind of dumb and shouldn't
                    # happen unless the server sends length of record and record separately.
                    if (len(data) < data_len): break

                    # clearing the buffer since we either have nothing left to process or we will re add the leftover
                    # bytes back with the next condition.
                    recv_buff_clear()

                    # if expected data length is greater than local buffer, multiple records were returned in a batch
                    # so appending leftover bytes after removing the current records data from buffer.
                    if (len(data) > data_len):
                        recv_buff_append(data[data_len:])

                    # ignoring internally generated connection keepalives
                    if (data[0] != DNS.KEEPALIVE):
                        responder_add(data[:data_len])

        self._relay_conn.sock.close()

    def _tls_connect(self, tls_server):

        Log.verbose(f'[{tls_server}/{self._protocol.name}] Opening secure socket.')
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(RELAY_TIMEOUT)

        dns_sock = self._tls_context.wrap_socket(sock, server_hostname=tls_server)
        try:
            dns_sock.connect((tls_server, PROTO.DNS_TLS))
        except OSError as ose:
            Log.error(f'[{tls_server}/{self._protocol.name}] Failed to connect. {ose}')

        except Exception as E:
            Log.error(f'[{tls_server}/{self._protocol.name}] TLS context error while attempting to connect. {E}')

        else:
            self._relay_conn = RELAY_CONN(
                tls_server, dns_sock, dns_sock.send, dns_sock.recv, dns_sock.version()
            )

            return True

        return None

    # TODO: (for dnx) see if configured interval changes should be reset or if it would be ok to let them take effect
    #  on the next iteration.
    def _keepalive_run(self):
        keepalive_interval = self.DNSRelay.keepalive_interval
        keepalive_status = self.keepalive_status.wait

        relay_add = self.relay.add

        while True:
            if (not keepalive_interval):
                fast_sleep(TEN_SEC)

                continue

            # returns True if reset which means we do not need to send a keep alive. If timeout is reached will return
            # False notifying that a keepalive should be sent
            if keepalive_status(keepalive_interval):
                Log.verbose(f'[keepalive] Timer reset to {keepalive_interval}.')
                continue

            relay_add(self._dns_packet(KEEP_ALIVE_DOMAIN, self._protocol)) # pylint: disable=no-member

            Log.verbose(f'[keepalive] Added to relay queue and cleared')

    # TODO: is the set/clear action thread safe in conjunction with the keepalive status? can the thread change before
    #  clear can be called where the keepalive status would immediately return again.
    #   - this isnt necessarily a big deal, but it would be high strung busy loop until the clear goes into effect. it
    #   - may not actually matter at all and im just in sleepy brain mode.
    def _keepalive_reset(self):
        self.keepalive_status.set()
        self.keepalive_status.clear()


class Reachability:
    '''this class is used to determine whether a remote dns server has recovered from an outage or
    slow response times.'''

    __slots__ = (
        '_protocol', 'DNSRelay', '_initialize',


        '_tls_context', '_udp_query'
    )

    def __init__(self, protocol, DNSRelay):
        self._protocol = protocol
        self.DNSRelay = DNSRelay

        self._initialize = Initialize(DNSRelay.__name__)

        # INITIALIZING TLS CONTEXT
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.verify_mode = ssl.CERT_REQUIRED
        tls_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

        self._tls_context = tls_context

    @classmethod
    def run(cls, DNSServer):
        '''starting remote server responsiveness detection as a thread. the remote servers will only
        be checked for connectivity if they are mark as down during the polling interval.'''

        # initializing tls instance and starting thread
        reach_tls = cls(PROTO.DNS_TLS, DNSServer)
        threading.Thread(target=reach_tls.tls).start()

        reach_tls._initialize.wait_for_threads(count=1)

    @looper(FIVE_SEC)
    def tls(self):
        for secure_server in self.DNSRelay.dns_servers:

            # no check needed if server/proto is known up
            if (secure_server[self._protocol]): continue

            Log.verbose(f'[{secure_server["ip"]}/{self._protocol.name}] Checking reachability of remote DNS server.')

            # if server responds to connection attempt, it will be marked as available
            if self._tls_reachable(secure_server['ip']):
                secure_server[PROTO.DNS_TLS] = True
                self.DNSRelay.tls_up = True

                Log.console(f'[{secure_server["ip"]}/{self._protocol.name}] DNS server is reachable.')

        self._initialize.done()

    def _tls_reachable(self, secure_server):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(2)

        secure_socket = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            secure_socket.connect((secure_server, PROTO.DNS_TLS))
        except OSError:
            return False

        else:
            return True

        finally:
            secure_socket.close()
