#!/usr/bin/env python3

import struct

TCP = 6
UDP = 17

A_RECORD = 1
DEFAULT_TTL = 3600
MINIMUM_TTL = 300


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

    def Parse(self,):
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
        if (response_ttl == DEFAULT_TTL):
            ttl_bytes_override = struct.pack('!L', DEFAULT_TTL)
        else:
            ttl_bytes_override = struct.pack('!L', response_ttl)

        # reset request record var then iterating over record recieved from server and rewriting the dns record TTL
        # to 1 hour | other records like SOA are unaffected
        request_record = b''
        for rr_part in self.request_record_split[1:]:
            bytes_check = rr_part[2:8]
            type_check, ttl_check = struct.unpack('!HL', bytes_check)
            if (type_check == A_RECORD and ttl_check < MINIMUM_TTL):
                ttl_bytes_override = ttl_bytes_override = struct.pack('!L', MINIMUM_TTL)
                request_record += self.record_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]
            elif (type_check == A_RECORD and ttl_check > response_ttl):
                request_record += self.record_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]
            else:
                request_record += self.record_name + rr_part

        if (request_record):
            self.cache_ttl = ttl_check

        # Replacing tcp dns id with original client dns id if converting back from tcp/tls.
        if (dns_id):
            self.dns_header = self.dns_header[2:]
            self.send_data += struct.pack('!H', dns_id)

        self.send_data += self.dns_header + self.dns_query + request_record

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return tcp_dns_payload
