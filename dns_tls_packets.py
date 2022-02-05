#!/usr/bin/env python3

from collections import namedtuple

from protocol_tools import *
from advanced_tools import bytecontainer


class ClientRequest:
    __slots__ = (
        '_data', '_dns_header', '_dns_query',

        'address', 'sendto', 'intf',
        'dns_id', 'top_domain',

        'qr', 'op', 'aa', 'tc', 'rd',
        'ra', 'zz', 'ad', 'cd', 'rc',

        'qname', 'qtype', 'qclass',
        'question_record', 'additional_records',
        'send_data'
    )

    def __init__(self, address, sock_info):
        self.address = address

        if (sock_info):
            self.sendto = sock_info.sendto

        self.top_domain = False if address[0] else True

        self.dns_id    = 1
        self.send_data = b''
        self.additional_records = b''

    # if called before the parse method has been called, the request will not be known yet. this is mostly redundant
    # to the console log message output while relaying a request so consider removing this.
    def __str__(self):
        try:
            return f'dns_query(host={self.address[0]}, port={self.address[1]}, request={self.qname})'
        except AttributeError:
            return f'dns_query(host={self.address[0]}, port={self.address[1]}, request=Unknown)'

    def parse(self, data):
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
        offset, local_domain, self.qname = parse_query_name(_dns_query, qname=True)

        self.qtype, self.qclass = double_short_unpack(_dns_query[offset:])
        self.question_record = _dns_query[:offset+4]
        self.additional_records = _dns_query[offset+4:]

        return local_domain

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
        arc = 1 if self.additional_records else 0

        # initializing byte array with (2) bytes. these get overwritten with query len actual after processing
        send_data = bytearray(2)

        send_data += build_dns_query_hdr(dns_id, arc, cd=self.cd)
        send_data += domain_stob(self.qname)
        send_data += double_short_pack(self.qtype, 1)

        # condition favors normal case of no additional records present.
        if (arc):
            send_data += self.additional_records

        send_data[:2] = short_pack(len(send_data) - 2)

        self.send_data = send_data

    @classmethod
    def generate_local_query(cls, qname):
        '''alternate constructor for creating locally generated queries (top domains).'''

        self = cls(NULL_ADDR, None)

        # hardcoded qtype can change if needed.
        self.qname = qname
        self.qtype = 1
        self.cd    = 1

        return self


# ================
# SERVER RESPONSE
# ================
_records_container = namedtuple('record_container', 'counts records')
_resource_records = namedtuple('resource_records', 'resource authority')
_RESOURCE_RECORD = bytecontainer('resource_record', 'name qtype qclass ttl data')

_MINIMUM_TTL = long_pack(MINIMUM_TTL)
_DEFAULT_TTL = long_pack(DEFAULT_TTL)

def ttl_rewrite(data, dns_id, len=len, min=min, max=max):
    dns_header, dns_payload = data[:12], data[12:]

    # converting external/unique dns id back to original dns id of client
    send_data = bytearray(short_pack(dns_id))

    # ================
    # HEADER
    # ================
    _dns_header = dns_header_unpack(dns_header)

    resource_count = _dns_header[3]
    authority_count = _dns_header[4]
    # additional_count = _dns_header[5]

    send_data += dns_header[2:]

    # ================
    # QUESTION RECORD
    # ================
    # www.micro.com or micro.com || sd.micro.com
    offset, _ = parse_query_name(dns_payload)

    question_record = dns_payload[:offset + 4]

    send_data += question_record

    # ================
    # RESOURCE RECORD
    # ================
    resource_records = dns_payload[offset + 4:]

    # offset is reset to prevent carry over from above.
    offset, original_ttl, record_cache = 0, 0, []

    # parsing standard and authority records
    for record_count in [resource_count, authority_count]:

        # iterating once for every record based on provided record count. if this number is forged/tampered with it
        # will cause the parsing to fail. NOTE: ensure this isn't fatal.
        for _ in range(record_count):
            record_type, record, offset = _parse_record(resource_records, offset, dns_payload)

            # TTL rewrite done on A records which functionally clamps TTLs between a min and max value. CNAME is listed
            # first, followed by A records so the original_ttl var will be whatever the last A record ttl parsed is.
            # generally all A records have the same ttl. CNAME ttl can differ, but will get clamped with A so will
            # likely end up the same as A records.
            if (record_type in [DNS.A, DNS.CNAME]):
                original_ttl = long_unpack(record.ttl)[0]
                record.ttl = long_pack(
                    max(MINIMUM_TTL, min(original_ttl, DEFAULT_TTL))
                )

                send_data += record

                # limits A record caching so we aren't caching excessive amount of records with the same qname
                if (len(record_cache) < MAX_A_RECORD_COUNT or record_type != DNS.A):
                    record_cache.append(record)

            # dns system level, mail, and txt records don't need to be clamped and will be relayed to client as is
            else:
                send_data += record

    # keeping any additional records intact
    # TODO: see if modifying/ manipulating additional records would be beneficial or even useful in any way
    send_data += resource_records[offset:]

    if (record_cache):
        return send_data, CACHED_RECORD(int(fast_time()) + original_ttl, original_ttl, record_cache)

    return send_data, None

def _parse_record(resource_records, total_offset, dns_query):
    current_record = resource_records[total_offset:]

    offset, _ = parse_query_name(current_record, dns_query)

    # resource record data len. generally 4 for ip address, but can vary. calculating first so we can single shot
    # create byte container below.
    dt_len = btoia(current_record[offset + 8:offset + 10])

    resource_record = _RESOURCE_RECORD(
        current_record[:offset],
        current_record[offset:offset + 2],
        current_record[offset + 2:offset + 4],
        current_record[offset + 4:offset + 8],
        current_record[offset + 8:offset + 10 + dt_len]
    )

    # name len + 2 bytes(length field) + 8 bytes(type, class, ttl) + data len
    total_offset += offset + 10 + dt_len

    return btoia(resource_record.qtype), resource_record, total_offset
