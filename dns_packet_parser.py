#!/usr/bin/env python3

import struct

TCP = 6
UDP = 17

A_RECORD = 1


class PacketManipulation:
    def __init__(self, data, protocol):
        if (protocol == UDP):
            self.data = data
        elif (protocol == TCP):
            self.data = data[2:]

        self.dns_id = 0
        self.qtype = 0
        self.qclass = 0

        self.send_data = b''

    def Parse(self):
        self.QueryInfo()
        if (self.qtype == A_RECORD):
            self.QName()

    def DNSID(self):
        dns_id = struct.unpack('!H', self.data[:2])[0]

        return dns_id

    def QueryInfo(self):
        self.dns_payload = self.data[12:]
        self.dns_id = struct.unpack('!H', self.data[:2])[0]

        dns_query = self.dns_payload.split(b'\x00',1)
        if (len(dns_query) >= 2 and len(dns_query[1]) >= 4):
            dnsQ = struct.unpack('!2H', dns_query[1][0:4])
            self.dns_query = dns_query[0]
            self.qtype = dnsQ[0]
            self.qclass = dnsQ[1]

    def QName(self):
        b = len(self.dns_query)
        eoqname = b + 1

        qname = struct.unpack(f'!{b}B', self.dns_query[:eoqname])

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

        self.qname = qname_raw.lower()

    def Rewrite(self, dns_id=None):
        qname = self.data[12:].split(b'\x00',1)[0]

        offset = len(qname) + 1
        end_of_qname = 12 + offset
        end_of_query = end_of_qname + 4
        start_of_record = end_of_query
        request_header = self.data[:end_of_query]
        request_record = self.data[start_of_record:]

        # assigning pointer variable, which is a protocol constant and ttl for 1 hour in packet form.
        pointer = b'\xc0\x0c'
        ttl_bytes_override = b'\x00\x00\x0e\x10'

        # splitting the dns packet on the compressed pointer if present, if not splitting on qname.
        if (request_record[0:2] == pointer):
            rr_splitdata = request_record.split(pointer)
            rr_name = pointer
        else:
            rr_splitdata = request_record.split(qname)
            rr_name = qname

        # reset request record var then iterating over record recieved from server and rewriting the dns record TTL
        # to 1 hour | other records like SOA are unaffected
        request_record = b''
        for rr_part in rr_splitdata[1:]:
            bytes_check = rr_part[2:8]
            type_check, ttl_check = struct.unpack('!HL', bytes_check)
            if (type_check == A_RECORD and ttl_check > 299):
                request_record += rr_name + rr_part[:4] + ttl_bytes_override + rr_part[8:]
            else:
                request_record += rr_name + rr_part

        # Replacing tcp dns id with original client dns id if converting back from tcp/tls.
        if (dns_id):
            request_header = request_header[2:]
            self.send_data += struct.pack('!H', dns_id)

        self.send_data += request_header + request_record

    def UDPtoTLS(self, dns_id):
        payload_length = struct.pack('!H', len(self.data))
        tcp_dns_id = struct.pack('!H', dns_id)

        tcp_dns_payload = payload_length + tcp_dns_id + self.data[2:]

        return tcp_dns_payload
