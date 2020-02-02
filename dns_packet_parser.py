#!/usr/bin/env python3

import struct
import traceback

import basic_tools as tools

TCP = 6
UDP = 17

ROOT = 0
A_RECORD = 1
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

        self.dns_id         = 1
        self.send_data      = None
        self.calculated_ttl = None
        self.keepalive      = False

        # OPT record defaults
        self.arc = 0
        self.additional_data = b''

    def parse(self):
        self._parse_header()
        self._parse_dns_query()

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
        dns_query = self.data[12:]
        self.request, query_info, q_len = tools.convert_question_record(dns_query) # www.micro.com or micro.com || sd.micro.com

        self.qtype, self.qclass = struct.unpack('!2H', query_info)
        self.question_record = dns_query[:q_len]
        self.additional_data = dns_query[q_len:]

    def generate_cached_response(self, calculated_ttl, resource_records):
        self.calculated_ttl = calculated_ttl
        if (self.send_data):
            raise ValueError('packet data has already been created for this query.')

        self.send_data = tools.create_dns_response_header(self.dns_id, len(resource_records), rd=self.rd, cd=self.cd)
        self.send_data += self.question_record
        for offset, record in resource_records:
            self.send_data += record[:offset+4] + struct.pack('!L', calculated_ttl) + record[offset+8:]

    def generate_dns_query(self, dns_id):
        if (self.send_data):
            raise ValueError('packet data has already been created for this query.')

        # if additional data seen after question record, will mark additional record count as 1 in dns header
        if (self.additional_data):
            self.arc = 1
        self.send_data  = tools.create_dns_query_header(dns_id, self.arc, cd=self.cd)
        self.send_data += tools.convert_dns_string_to_bytes(self.request)
        self.send_data += struct.pack('!2H',self.qtype,1)
        self.send_data += self.additional_data
        self.send_data  = struct.pack('!H', len(self.send_data)) + self.send_data

    def set_required_fields(self, request, cd=1, *, keepalive=False):
        if (self.data):
            raise ValueError('this method is only to be used for locally generated queries.')
        # harcorded qtype temporary. can change if needed.
        self.request   = request
        self.qtype     = 1
        self.cd        = cd
        self.keepalive = keepalive


class PacketManipulation:
    def __init__(self, data):
        self.data      = data[2:]
        self.dns_id    = 0
        self.cache_ttl = 0
        self.dns_opt   = False
        self.send_data = b''

        self.offset = 0
        self.a_record_count     = 0
        self.n_resource_count   = 0
        self.n_authority_count  = 0
        self.resource_records   = []
        self.authority_records  = []
        self.additional_records = []
        self.data_to_cache      = []

        # self.records = {
        #     'resource':   [],
        #     'authority':  [],
        #     'additional': []
        # }

    def parse(self):
        self.header()
        self.question_record_handler()
        self.resource_record_handler()

    def get_dns_id(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def header(self):
        self.dns_header = self.data[:12]
        self.dns_id     = struct.unpack('!H', self.data[:2])[0]
        self.dns_flags  = self.data[2:4]

        content_info = struct.unpack('!4H', self.dns_header[4:12])
        self.question_count   = content_info[0]
        self.resource_count   = content_info[1]
        self.authority_count  = content_info[2]
        self.additional_count = content_info[3]

    def question_record_handler(self):
        dns_query = self.data[12:]
        self.request, query_info, q_len = tools.convert_question_record(dns_query) # www.micro.com or micro.com || sd.micro.com

        self.qtype, self.qclass = struct.unpack('!2H', query_info)
        self.question_record = dns_query[:q_len]
        self.resource_record = dns_query[q_len:]

    def get_record_type(self, data):
        #checking if record starts with a pointer
        if (data.startswith(b'\xc0')):
            nlen = 2
        else:
            nlen = len(data.split(b'\x00', 1)[0]) + 1

        record_type = struct.unpack('!H', data[nlen:nlen+2])[0]
        record_ttl  = struct.unpack('!L', data[nlen+4:nlen+8])[0]
        data_length = struct.unpack('!H', data[nlen+8:nlen+10])[0]

        record_length = 10 + data_length + nlen

        return record_type, record_length, record_ttl, nlen

    # grabbing the records contained in the packet and appending them to their designated lists to be inspected by other methods.
    # count of records is being grabbed/used from the header information
    def resource_record_handler(self):
        for record_type in ['resource', 'authority']:
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
        for records in ['resource', 'authority']:
            current_records = getattr(self, f'{records}_records')
            for record_info in current_records:
                record_type, _, name_len, _ = record_info
                if (record_type != A_RECORD or self.a_record_count < MAX_A_RECORD_COUNT):
                    record = self.ttl_rewrite(record_info, response_ttl)
                    record_count  = getattr(self, f'n_{records}_count')
                    setattr(self, f'n_{records}_count', record_count + 1)

                    resource_records.append(record)
                    # preventing root server queries from being cached
                    if (self.request):
                        self.data_to_cache.append((name_len, record))

        # additional records/data will remain intact until otherwise needed
        for record in self.additional_records:
            resource_records.append(record)

        self.send_data  = struct.pack('!H', dns_id)
        self.send_data += self.dns_flags
        self.send_data += struct.pack('!H', self.question_count)
        self.send_data += struct.pack('!H', self.n_resource_count)
        self.send_data += struct.pack('!H', self.n_authority_count)
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
