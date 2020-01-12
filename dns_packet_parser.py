#!/usr/bin/env python3

import struct
import traceback

import basic_tools as tools

TCP = 6
UDP = 17

A_RECORD = 1
CNAME = 5
SOA = 6
OPT = 41

DEFAULT_TTL = 3600
MINIMUM_TTL = 300
MAX_A_RECORD_COUNT = 3

DNS_QUERY = 0
DNS_RESPONSE = 128


class RequestHandler:
    def __init__(self, data, address):
        self.data = data
        self.address = address

        self.dns_id = 69
        self.send_data = None
        self.calculated_ttl = None

    def parse(self):
        try:
            self._parse_header()
            self._parse_dns_query()
        except Exception as E:
            tools.p(E)

    def _parse_header(self):
        self.dns_header = self.data[:12]

        self.dns_id = struct.unpack('!H', self.data[:2])[0]
        self.qr = tools.convert_bit(self.dns_header[2] & 1 << 7)
        self.op = tools.convert_bit(self.dns_header[2] & 1 << 3)
        self.aa = tools.convert_bit(self.dns_header[2] & 1 << 2)
        self.tc = tools.convert_bit(self.dns_header[2] & 1 << 1)
        self.rd = tools.convert_bit(self.dns_header[2] & 1 << 0)
        self.ra = tools.convert_bit(self.dns_header[3] & 1 << 7)
        self.zz = tools.convert_bit(self.dns_header[3] & 1 << 6)
        self.ad = tools.convert_bit(self.dns_header[3] & 1 << 5)
        self.cd = tools.convert_bit(self.dns_header[3] & 1 << 4)
        self.rc = tools.convert_bit(self.dns_header[3] & 1 << 0)

    def _parse_dns_query(self):
        dns_query = self.data[12:].split(b'\x00',1)
        query_name = dns_query[0]
        query_info = dns_query[1][:4]
        self.question_record = query_name + b'\x00' + query_info

        self.request = tools.convert_dns_bytes_to_string(query_name) # www.micro.com or micro.com || sd.micro.com

        query_info = struct.unpack('!2H', query_info)
        self.qtype = query_info[0]
        self.qclass = query_info[1]

    def generate_cached_response(self, calculated_ttl, resource_records):
        self.calculated_ttl = calculated_ttl
        if (self.send_data):
            raise ValueError('packet data has already been created for this query.')

        self.send_data = tools.create_dns_response_header(self.dns_id, len(resource_records), rd=self.rd, cd=self.cd)
        self.send_data += self.question_record
        for record in resource_records:
            self.send_data += record[:6] + struct.pack('!L', calculated_ttl) + record[10:]

    def generate_dns_query(self, dns_id):
        if (self.send_data):
            raise ValueError('packet data has already been created for this query.')

        self.send_data = tools.create_dns_query_header(dns_id, cd=self.cd)
        self.send_data += tools.convert_dns_string_to_bytes(self.request)
        self.send_data += struct.pack('!B2H', 0,1,1)
        self.send_data = struct.pack('!H', len(self.send_data)) + self.send_data

    def set_required_fields(self, request, cd=1):
        if (self.data):
            raise ValueError('this method is only to be used for locally generated queries.')

        self.request = request
        self.cd = cd


class PacketManipulation:
    def __init__(self, data):
        self.data = data[2:]
        self.dns_id = 0
        self.qtype = 0
        self.qclass = 0
        self.cache_ttl = 0

        self.request2 = None
        self.dns_opt = False
        self.dns_response = False
        self.dns_pointer = b'\xc0\x0c'

        self.cache_header = b''
        self.send_data = b''

        self.offset = 0
        self.a_record_count = 0
        self.standard_records = []
        self.authority_records =[]
        self.additional_records = []

    def parse(self):
        try:
            self.header()
            self.question_record_handler()
            self.get_qname()
            self.resource_record_handler()
        except Exception as E:
            tools.p(E)

    def get_dns_id(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def header(self):
        self.dns_header = self.data[:12]
        self.dns_id = struct.unpack('!H', self.data[:2])[0]
        self.dns_flags = self.data[2:4]

        content_info = struct.unpack('!4H', self.dns_header[4:12])
        self.question_count = content_info[0]
        self.standard_count = content_info[1] # answer count (name standard for iteration purposes in parsing)
        self.authority_count = content_info[2]
        self.additional_count = content_info[3]

    def question_record_handler(self):
        dns_payload = self.data[12:]

        query_info = dns_payload.split(b'\x00',1)
        record_type_info = struct.unpack('!2H', query_info[1][0:4])
        self.query_name = query_info[0]
        self.qtype = record_type_info[0]
        self.qclass = record_type_info[1]

        self.name_length = len(self.query_name)
        question_length = self.name_length + 5

        self.question_record = dns_payload[:question_length]
        self.resource_record = dns_payload[question_length:]

    def get_record_type(self, data):
        #checking if record starts with a pointer/is a pointer
        if (data.startswith(b'\xc0')):
            record_name = data[:2]
        else:
            record_name = data.split(b'\x00', 1)[0]

        nlen = len(record_name)
        #if record contains a pointer, no action taken, if not 1 will be added to the length to adjust for the pad at the end of the name
        if (b'\xc0' not in record_name):
            nlen += 1

        record_type = struct.unpack('!H', data[nlen:nlen+2])[0]
        if (record_type == A_RECORD):
            record_length = 10 + 4 + nlen

        elif (record_type in {CNAME, SOA}):
            data_length = struct.unpack('!H', data[nlen+8:nlen+10])[0]
            record_length = 10 + data_length + nlen

        record_ttl = struct.unpack('!L', data[nlen+4:nlen+8])[0]

        return record_type, record_length, record_ttl, nlen

    # grabbing the records contained in the packet and appending them to their designated lists to be inspected by other methods.
    # count of records is being grabbed/used from the header information
    def resource_record_handler(self):
        # parsing standard and authority records
        for record_type in ['standard', 'authority']:
            record_count = getattr(self, f'{record_type}_count')
            records_list = getattr(self, f'{record_type}_records')
            for _ in range(record_count):
                data = self.resource_record[self.offset:]
                record_type, record_length, record_ttl, nlen = self.get_record_type(data)

                resource_record = data[:record_length]
                records_list.append((record_type, record_ttl, nlen, resource_record))

                self.offset += record_length

        # parsing additional records
        for _ in range(self.additional_count):
            data = self.resource_record[self.offset:]
            additional_type = struct.unpack('!H', data[1:3])
            if additional_type == OPT:
                self.dns_opt = True

            self.additional_records.append(data)

    def rewrite(self, dns_id, response_ttl=DEFAULT_TTL):
        resource_records = []
        for record_type in ['standard', 'authority']:
            all_records = getattr(self, f'{record_type}_records')
            for record_info in all_records:
                record_type = record_info[0]
                if (record_type != A_RECORD or self.a_record_count < MAX_A_RECORD_COUNT):
                    record = self.ttl_rewrite(record_info, response_ttl)

                    resource_records.append(record)

        # setting add record count to 0 and assigning variable for data to cache prior to appending additional records
        self.data_to_cache = resource_records
        # additional records will remain intact until otherwise needed
        for record in self.additional_records:
            resource_records.append(record)

        self.send_data = struct.pack('!H', dns_id)
        self.send_data += self.dns_flags
        self.send_data += struct.pack('!H', self.question_count)
        self.send_data += struct.pack('!H', self.a_record_count)
        self.send_data += struct.pack('!H', self.authority_count)
        self.send_data += struct.pack('!H', self.additional_count)

        self.send_data += self.question_record
        self.send_data += b''.join(resource_records)

    def ttl_rewrite(self, record_info, response_ttl):
        record_type, record_ttl, nlen, record = record_info
        # incrementing a record counter to limit amount of records in response/held in cache to configured ammount
        if (record_type == A_RECORD):
            self.a_record_count += 1

        if (record_ttl < MINIMUM_TTL):
            new_record_ttl = MINIMUM_TTL
        # rewriting ttl to the remaining amount that was calculated from cached packet or to the maximum defined TTL
        elif (record_ttl > DEFAULT_TTL):
            new_record_ttl = DEFAULT_TTL
        # anything in between the min and max TTL will be retained
        else:
            new_record_ttl = record_ttl
        # setting the ttl amount to cache to the result of the above if statement
        self.cache_ttl = new_record_ttl

        record_front = record[:nlen+4]
        new_record_ttl = struct.pack('!L', new_record_ttl)
        record_back = record[nlen+8:]

        # returning rewrittin resource record
        return record_front + new_record_ttl + record_back

    def get_qname(self):
        b = len(self.query_name)
        qname = struct.unpack(f'!{b}B', self.query_name)

        # coverting query name from bytes to string
        length = qname[0]
        qname_raw = ''
        for byte in qname[1:]:
            if (length != 0):
                qname_raw += chr(byte)
                length -= 1
                continue

            length = byte
            qname_raw += '.'

        self.request = qname_raw.lower() # www.micro.com or micro.com || sd.micro.com
        if ('.' in self.request):
            req = self.request.split('.')
            self.request2 = '.'.join(req[-2:]) # micro.com or co.uk
            self.request_tld = f'.{req[-1]}' # .com
