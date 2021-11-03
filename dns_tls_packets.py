#!/usr/bin/env python3

from collections import namedtuple

from basic_tools import *
from advanced_tools import bytecontainer


class ClientRequest:
    __slots__ = (
        '_data', '_dns_header', '_dns_query',

        'address', 'sendto', 'intf', 'top_domain',
        'keepalive', 'local_domain',
        'dns_id', 'request', 'send_data',
        'additional_data',

        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'qtype', 'qclass', 'question_record'
    )

    def __init__(self, address, sock_info):
        self.address = address

        if (sock_info):
            self.sendto = sock_info.sendto

        self.top_domain = False if address[0] else True
        self.keepalive  = False

        self.dns_id    = 1
        self.send_data = b''

    # if called before the parse method has been called, the request will not be known yet. this is mostly redundant
    # to the console log message output while relaying a request so consider removing this.
    def __str__(self):
        try:
            return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.request})'
        except AttributeError:
            return f'dns_query(host={self.address[0]}, port={self.address[1]}, request=Unknown)'

    def parse(self, data):
        if (not data):
            raise TypeError(f'{__class__.__name__} cannot parse data set to None.')

        _dns_header, _dns_query = data[:12], data[12:]

        # ================
        # REQUEST HEADER
        # ================
        dns_header = dns_header_unpack(_dns_header)
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

        # ================
        # QUESTION RECORD
        # ================
        # www.micro.com or micro.com || sd.micro.com
        request, offset = parse_query_name(_dns_query, qname=True)

        self.local_domain = True if request[-6:] == '.local' or '.' not in request else False

        self.qtype, self.qclass = double_short_unpack(_dns_query[offset:])
        self.question_record = _dns_query[:offset+4]
        self.additional_data = _dns_query[offset+4:]

        self.request = request

    def generate_cached_response(self, cached_dom):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        send_data = bytearray()

        send_data += build_dns_response_hdr(self.dns_id, len(cached_dom.records), rd=self.rd, cd=self.cd)
        send_data += self.question_record

        for record in cached_dom.records:
            record.ttl = long_pack(cached_dom.ttl)

            send_data += record

        self.send_data = send_data

    def generate_dns_query(self, dns_id):
        if (self.send_data):
            raise RuntimeWarning('send data has already been created for this query.')

        # setting additional data flag in dns header if detected
        arc = 1 if self.additional_data else 0

        # initializing byte array with (2) bytes. these get overwritten with query len actual after processing
        send_data = bytearray(2)

        send_data += build_dns_query_hdr(dns_id, arc, cd=self.cd)
        send_data += domain_stob(self.request)
        send_data += double_short_pack(self.qtype, 1)

        if (arc):
            send_data += self.additional_data

        send_data[:2] = short_pack(len(send_data) - 2)

        self.send_data = send_data

    @classmethod
    def generate_local_query(cls, request, cd=1):
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(NULL_ADDR, None)

        # hardcoded qtype can change if needed.
        self.request    = request
        self.qtype      = 1
        self.cd         = cd

        return self

    @classmethod
    def generate_keepalive(cls, request, cd=1):
        '''alternate construct for creating locally generated keep alive queries.'''

        self = cls(NULL_ADDR, None)

        # hardcoded qtype can change if needed.
        self.request   = request
        self.qtype     = 1
        self.cd        = cd

        self.generate_dns_query(DNS.KEEPALIVE)

        return self

_records_container = namedtuple('record_container', 'counts records')
_resource_records = namedtuple('resource_records', 'resource authority')
_RESOURCE_RECORD = bytecontainer('resource_record', 'name qtype qclass ttl data')


class ServerResponse:
    __slots__ = (
        'dns_id', 'dns_flags', 'question_count',
        'additional_count',

        'qtype', 'qclass', 'question_record',
        'resource_record', 'records',
        'additional_record', 'data_to_cache',
        'send_data'
    )

    def __init__(self):
        self.dns_id    = 0
        self.send_data = b''

        # indexes: [rcv_count, override_count]
        self.records = _resource_records(
            _records_container([0, 0], []),
            _records_container([0, 0], [])
        )

    def parse(self, data):
        _dns_header, _dns_query = data[:12], data[12:]

        # ================
        # HEADER
        # ================
        dns_header = dns_header_unpack(_dns_header)
        self.dns_id         = dns_header[0]
        self.dns_flags      = dns_header[1]
        self.question_count = dns_header[2]

        # assigning informed record counts
        self.records.resource.counts[0]  = dns_header[3]
        self.records.authority.counts[0] = dns_header[4]
        self.additional_count = dns_header[5]

        # ================
        # QUESTION RECORD
        # ================
        # www.micro.com or micro.com || sd.micro.com
        offset = parse_query_name(_dns_query)

        self.qtype, self.qclass = double_short_unpack(_dns_query[offset:])
        self.question_record = _dns_query[:offset+4]
        self.resource_record = _dns_query[offset+4:]

        # ================
        # RESOURCE RECORD
        # ================
        # grabbing the records contained in the packet and appending them to their designated lists to be inspected by
        # other methods. count of records is being grabbed/used from the header information. offset is reset to prevent
        # carry over from above.
        a_record_count, offset = 0, 0

        # parsing standard and authority records
        for r_field in self.records:

            # iterating once for every record based on provided record count. if this number is forged/tampered with it
            # will cause the parsing to fail. NOTE: ensure this isn't fatal
            for _ in range(r_field.counts[0]):
                record_type, record, offset = self._parse_resource_record(offset, _dns_query)

                # incrementing counter to reflect overridden record counts if applicable
                if (record_type == DNS.AR):
                    r_field.counts[1] += 1

                # filtering out a records once max count is reached
                if (r_field.counts[1] <= MAX_A_RECORD_COUNT or record_type != DNS.AR):
                    r_field.records.append(record)

        # currently not doing anything with additional record section, but it is defined so it can be included in the
        # send data generated for the client.
        self.additional_record = _dns_query[offset:]

    # creating byte container of dns record values to be used later. now rewriting ttl here.
    def _parse_resource_record(self, total_offset, dns_query):
        local_record = self.resource_record[total_offset:]

        offset = parse_query_name(local_record, dns_query)

        # resource record data len. generally 4 for ip address, but can vary. calculating first so we can single shot
        # create byte container below.
        dt_len = btoia(local_record[offset + 8:offset + 10])

        resource_record = _RESOURCE_RECORD(
            local_record[:offset],
            local_record[offset:offset + 2],
            local_record[offset + 2:offset + 4],
            local_record[offset + 4:offset + 8],
            local_record[offset + 8:offset + 10 + dt_len]
        )

        # name len + 2 bytes(length field) + 8 bytes(type, class, ttl) + data len
        total_offset += offset + 10 + dt_len

        return btoia(resource_record.qtype), resource_record, total_offset

    def generate_server_response(self, dns_id):
        send_data = bytearray(self._create_header(dns_id) + self.question_record)

        original_ttl = 0
        # parsing standard and authority records
        for r_field in self.records:

            # ttl rewrite to configured bounds (clamping)
            for record in r_field.records:
                original_ttl, modified_ttl, record.ttl = self._get_new_ttl(record)

                send_data += record

        # system will cache full ttl, but override to configured amount responding sending to client
        if (self.records.resource.records):
            self.data_to_cache = CACHED_RECORD(
                int(fast_time()) + original_ttl,
                original_ttl, self.records.resource.records
            )
        else:
            self.data_to_cache = None

        # additional records will remain intact until otherwise needed
        if (self.additional_count):
            send_data += self.additional_record

        self.send_data = send_data

    @staticmethod
    def _get_new_ttl(record):
        '''returns dns records original ttl, the rewritten ttl, and the packed form of the rewritten ttl.'''
        record_ttl = long_unpack(record.ttl)[0]
        if (record_ttl < MINIMUM_TTL):
            new_record_ttl = MINIMUM_TTL

        # rewriting ttl to the remaining amount that was calculated from cached packet or to the maximum defined TTL
        elif (record_ttl > DEFAULT_TTL):
            new_record_ttl = DEFAULT_TTL

        # anything in between the min and max TTL will be retained
        else:
            new_record_ttl = record_ttl

        return record_ttl, new_record_ttl, long_pack(new_record_ttl)

    def _create_header(self, dns_id):
        return dns_header_pack(
            dns_id, self.dns_flags,
            self.question_count,
            self.records.resource.counts[1],
            self.records.authority.counts[1],
            self.additional_count
        )
