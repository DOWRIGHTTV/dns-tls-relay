#!/usr/bin/env python3

import struct
import traceback

from socket import inet_aton

import basic_tools as tools
from dns_tls_constants import * # pylint: disable=unused-wildcard-import


class ClientRequest:
    __slots__ = (
        # protected vars
        '_data', '_dns_header', '_dns_query',

        # public vars - init
        'address', 'sock', 'intf', 'top_domain',
        'keepalive', 'dom_local', 'fallback',
        'dns_id', 'request', 'send_data',
        'arc', 'additional_data',

        # public vars - dns
        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'requests', 'qtype', 'qclass', 'question_record'
    )

    def __init__(self, data, address, sock):
        self._data   = data
        self.address = address
        self.sock = sock
        if (data):
            self._dns_header = data[:12]
            self._dns_query  = data[12:]

        self.top_domain = False
        self.keepalive  = False
        self.dom_local  = False
        self.fallback   = False

        self.dns_id    = 1
        self.request   = None
        self.send_data = b''

        # OPT record defaults
        self.arc = 0
        self.additional_data = b''

    def __str__(self):
        return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.request})'

    def parse(self):
        if (not self._data):
            raise TypeError(f'{__class__.__name__} cannot parse data set to None.')

        self._parse_header()
        self._parse_dns_query()

    def _parse_header(self):
        dns_header = dns_header_unpack(self._dns_header)
        self.dns_id = dns_header[0]
        self.qr = dns_header[1] >> 15 & 1
        self.op = dns_header[1] >> 11 & 15
        self.aa = dns_header[1] >> 10 & 1
        self.tc = dns_header[1] >> 9  & 1
        self.rd = dns_header[1] >> 8  & 1
        self.ra = dns_header[1] >> 7  & 1
        self.zz = dns_header[1] >> 6  & 1
        self.ad = dns_header[1] >> 5  & 1
        self.cd = dns_header[1] >> 4  & 1
        self.rc = dns_header[1]       & 15

    def _parse_dns_query(self):
        self.request, offset = tools.parse_query_name(self._dns_query, qname=True) # www.micro.com or micro.com || sd.micro.com
        if ('.' not in self.request or self.request.endswith('.local')):
            self.dom_local = True

        self.qtype, self.qclass = double_short_unpack(self._dns_query[offset:])
        self.question_record = self._dns_query[:offset+4] # ofsset + 4 byte info
        self.additional_data = self._dns_query[offset+4:]

    def generate_cached_response(self, cached_dom):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        send_data = [tools.create_dns_response_header(
            self.dns_id, len(cached_dom.records), rd=self.rd, cd=self.cd
        )]
        send_data.append(self.question_record)
        for record in cached_dom.records:
            record.update('ttl', long_pack(cached_dom.ttl))
            send_data.append(b''.join(record))

        self.send_data = b''.join(send_data)

    def generate_dns_query(self, dns_id, protocol):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        # if additional data seen after question record, will mark additional record count as 1 in dns header
        if (self.additional_data):
            self.arc = 1
        send_data = [b'\x00\x00', tools.create_dns_query_header(dns_id, self.arc, cd=self.cd)]
        send_data.append(tools.convert_dns_string_to_bytes(self.request))
        send_data.append(double_short_pack(self.qtype, 1))
        send_data.append(self.additional_data)

        # replacing first 2 bytes with data len
        send_data[0] = short_pack(len(b''.join(send_data[1:])))

        self.send_data = b''.join(send_data)

    @classmethod
    def generate_local_query(cls, request, cd=1):
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(None, NULL_ADDR, None)
        # harcorded qtype can change if needed.
        self.top_domain = True
        self.request    = request
        self.qtype      = 1
        self.cd         = cd

        return self

    @classmethod
    def generate_keepalive(cls, request, protocol, cd=1):
        '''alternate construct for creating locally generated keep alive queries.'''
        self = cls(None, NULL_ADDR, None)
        # harcorded qtype can change if needed.
        self.request   = request
        self.qtype     = 1
        self.cd        = cd

        self.generate_dns_query(DNS.KEEPALIVE, protocol)

        return self


class ServerResponse:
    __slots__ = (
        '_data', '_dns_header', '_dns_query',
        '_offset', '_a_rec_count',

        'dns_id', 'dns_flags', 'question_count',
        'records', 'additional_count',

        'qtype', 'qclass', 'question_record',
        'resource_record', 'cache_ttl', 'is_valid',
        'send_data'
    )

    def __init__(self, data):
        self._data       = data
        self._dns_header = data[:12]
        self._dns_query  = data[12:]
        self.dns_id      = 0
        self.cache_ttl   = 0
        self.send_data   = b''

        self._offset      = 0
        self._a_rec_count = 0
        self.records      = {
            'resource': {
                'rcv_count': 0,
                'records': []
            },
            'authority': {
                'rcv_count': 0,
                'records': []
                }
            }

    def parse(self):
        self._header()
        self._question_record_handler()
        self._resource_record_handler()

    def _header(self):
        dns_header = dns_header_unpack(self._dns_header)
        self.dns_id           = dns_header[0]
        self.dns_flags        = dns_header[1]
        self.question_count   = dns_header[2]
        self.records['resource']['rcv_count']  = dns_header[3]
        self.records['authority']['rcv_count'] = dns_header[4]
        self.additional_count = dns_header[5]

    def _question_record_handler(self):
        offset = tools.parse_query_name(self._dns_query) # www.micro.com or micro.com || sd.micro.com

        self.qtype, self.qclass = double_short_unpack(self._dns_query[offset:])
        self.question_record = self._dns_query[:offset+4] # ofsset + 4 byte info
        self.resource_record = self._dns_query[offset+4:]

    # grabbing the records contained in the packet and appending them to their designated lists to be inspected by other methods.
    # count of records is being grabbed/used from the header information
    def _resource_record_handler(self):
        # parsing standard and authority records
        for info in self.records.values():
            for _ in range(info['rcv_count']):
                record = self._parse_resource_record()
                # incrementing a record counter to limit amount of records in response/held in cache to configured ammount
                if (record.qtype[1] == DNS.AR):
                    self._a_rec_count += 1
                    if (self._a_rec_count > MAX_A_RECORD_COUNT): continue

                info['records'].append(record)

        self.is_valid = bool(self.records['resource']['records'])

    # creating byte container of dns record values to be used later. now rewriting ttl here.
    def _parse_resource_record(self):
        local_record = self.resource_record[self._offset:]

        offset = tools.parse_query_name(local_record, self._dns_query)
        name   = local_record[:offset]
        qtype  = local_record[offset:offset+2]
        qclass = local_record[offset+2:offset+4]
        ttl    = local_record[offset+4:offset+8]
        dt_len = short_unpack(local_record[offset+8:offset+10])[0]
        data   = local_record[offset+8:offset+10+dt_len]

        self._offset += offset + dt_len + 10 # length of data + 2 bytes(length field) + 8 bytes(type, class, ttl)

        return RESOURCE_RECORD(name, qtype, qclass, ttl, data)

    def generate_server_response(self, dns_id):
        send_data = [b'\x00'*14, self.question_record]
        for r_type, info in self.records.items():
            for record in info['records']:
                record.update('ttl', self._get_new_ttl(r_type, record.ttl))
                send_data.append(b''.join(record))

        # prepending dns header to records. this is so we have new count calculated before header creation.
        send_data[0] = self._create_header(dns_id)

        # additional records will remain intact until otherwise needed
        if (self.additional_count):
            send_data.append(self.resource_record[self._offset:])

        self.send_data = b''.join(send_data)

    def _get_new_ttl(self, r_type, record_ttl):
        record_ttl = long_unpack(record_ttl)[0]
        if (record_ttl < MINIMUM_TTL):
            new_record_ttl = MINIMUM_TTL
        # rewriting ttl to the remaining amount that was calculated from cached packet or to the maximum defined TTL
        elif (record_ttl > DEFAULT_TTL):
            new_record_ttl = DEFAULT_TTL
        # anything in between the min and max TTL will be retained
        else:
            new_record_ttl = record_ttl

        # if its a resource record and the ttl is greater than what is marked currently as cache length
        # the cache ttl will be updated. this will change on first record, or for highest ttl if they are different.
        if (r_type == 'resource' and new_record_ttl > self.cache_ttl):
            self.cache_ttl = new_record_ttl

        return long_pack(new_record_ttl)

    def _create_header(self, dns_id):
        return dns_header_pack(
            dns_id, self.dns_flags,
            self.question_count,
            len(self.records['resource']['records']),
            len(self.records['authority']['records']),
            self.additional_count)
