#!/usr/bin/env python3

import struct
import traceback

TCP = 6
UDP = 17

A_RECORD = 1
DEFAULT_TTL = 3600
MINIMUM_TTL = 300
MAX_A_RECORD_COUNT = 2


class PacketManipulation:
    def __init__(self, data, protocol):
        if (protocol == UDP):
            self.data = data
        elif (protocol == TCP):
            self.data = data[2:]

        self.dns_id = 0
        self.qtype = 0
        self.qclass = 0
        self.cache_ttl = 0

        self.dns_response = False
        self.dns_pointer = b'\xc0\x0c'
#        ttl_bytes_override = 300
        # for testing
        self.ttl_bytes_override = 5

        self.cache_header = b''
        self.send_data = b''

    def Parse(self):
        self.QueryInfo()
        if (self.qtype == A_RECORD):
            self.QName()
            if (self.dns_response):
                self.SplitQuery()

    def DNSID(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def QueryInfo(self):
        self.dns_header = self.data[:12]
        self.dns_payload = self.data[12:]
        self.dns_id = struct.unpack('!H', self.data[:2])[0]

        if (self.dns_header[2] & 1 << 7): # Response
            self.dns_response = True

        try:
            dns_query = self.dns_payload.split(b'\x00',1)
            dnsQ = struct.unpack('!2H', dns_query[1][0:4])
            self.query_name = dns_query[0]
            self.qtype = dnsQ[0]
            self.qclass = dnsQ[1]
            self.request_record = dns_query[1][4:]

            self.dns_query = self.query_name + b'\x00' + dns_query[1][0:4]
        except (struct.error, IndexError):
            pass

    def QName(self):
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
        if ('.' in qname):
            req = qname.split('.')
            self.request2 = f'{req[-2]}.{req[-1]}' # micro.com or co.uk
            self.request_tld = f'.{req[-1]}' # .com

    def SplitQuery(self):
        # splitting the dns packet on the compressed pointer if present, if not splitting on qname.
        if (self.request_record.startswith(self.dns_pointer)):
            self.request_record_split = self.request_record.split(self.dns_pointer)
            self.record_name = self.dns_pointer
        else:
            self.request_record_split = self.request_record.split(self.query_name)
            self.record_name = self.query_name

    def Rewrite(self, dns_id=None, response_ttl=DEFAULT_TTL):
        minmium_ttl_bytes = ttl_bytes_override = struct.pack('!L', MINIMUM_TTL)
        if (response_ttl == DEFAULT_TTL):
            ttl_bytes_override = struct.pack('!L', DEFAULT_TTL)
        else:
            ttl_bytes_override = struct.pack('!L', response_ttl)

        # reset request record var then iterating over record recieved from server and rewriting the dns record TTL
        # to 1 hour | other records like SOA are unaffected
        print(self.data)
        print(self.request_record_split)
        a_record = 0
        request_record = b''
        for count, rr_part in enumerate(self.request_record_split[1:]):
            bytes_check = rr_part[2:8]
            type_check, ttl_check = struct.unpack('!HL', bytes_check)
            if (type_check == A_RECORD):
                if (ttl_check < MINIMUM_TTL):
                    temp_rr = self.record_name + rr_part[:4] + minmium_ttl_bytes + rr_part[8:]

                elif (ttl_check > response_ttl):
                    temp_rr = self.record_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]

                else:
                    temp_rr = self.record_name + rr_part

#                if (count <= MAX_A_RECORD_COUNT or len(rr_part) > 14):
                request_record += temp_rr

#                a_record += 1
            else:
                request_record += self.record_name + rr_part

        if (request_record):
            self.cache_ttl = ttl_check

        # rewriting the answer count to 3 if more were present due to only allowing max of 3 by policy
        if (a_record > 3):
            answer_count = struct.pack('!H', 4)
            self.dns_header = self.dns_header[:6] + answer_count + self.dns_header[8:]
            request_record += self.dns_pointer + self.request_record_split[-1]

        # Replacing tcp dns id with original client dns id if converting back from tcp/tls.
        if (dns_id):
            self.dns_header = self.dns_header[2:]
            self.send_data += struct.pack('!H', dns_id)

        self.send_data += self.dns_header + self.dns_query + request_record

    def RevertResponse(self):
        dns_payload = self.data[12:]

        # creating empty dns header, with standard query flag and recursion flag. will be rewritten with proper dns id
        # at another point in the process
        dns_header = struct.pack('H4B3H', 0,1,0,0,1,0,0,0)

        dns_query = dns_payload.split(b'\x00',1)
        query_name = dns_query[0]

        self.data = dns_header + query_name + b'\x00' + dns_query[1][0:4]

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return tcp_dns_payload
