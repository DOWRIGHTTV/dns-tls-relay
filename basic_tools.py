#!/usr/bin/env python3

import struct
import json

from dns_tls_relay import VERBOSE
from types import SimpleNamespace

ZERO = '0'

def p(thing_to_print):
    if (VERBOSE):
        print(thing_to_print)

def convert_bit(bit):
    return 1 if bit else 0

# parsing question record in dns query and return, name, record info, and length
# to be used by dns query generation method. if the data starts with a null byte,
# it is a root server query and
def convert_question_record(dns_data):
    q_len = 4 # initial length of 4 for fixed ammount size of record information
    query_name = []
    while True:
        length = dns_data[0]
        q_len += length + 1 # name len + interger value of length
        # will break on pad or root name lookup
        if (length == 0):
            break

        query_name.append(dns_data[1:1+length].decode())
        dns_data = dns_data[length+1:]

    query_name = '.'.join(query_name)
    query_info = dns_data[1:5]

    return query_name, query_info, q_len

def convert_dns_string_to_bytes(domain_name):
    if (not domain_name):
        return b'\x00'

    split_domain = domain_name.split('.')
    domain_bytes = b''
    for part in split_domain:
        domain_bytes += struct.pack('B', len(part))
        for char in part:
            domain_bytes += struct.pack('B', ord(char))
    else:
        domain_bytes += b'\x00'

    return domain_bytes

# will create dns header specific to response. default resource record count is 1
def create_dns_response_header(dns_id, record_count=1, *, rd=1, cd=0):
    dns_header = struct.pack('!H', dns_id)

    qr, op, aa, tc, ra, zz, ad, rc = 1,0,0,0,1,0,0,0
    one = (qr << 7) | (op << 3) | (aa << 2) | (tc << 1) | (rd << 0)
    two = (ra << 7) | (zz << 6) | (ad << 5) | (cd << 4) | (rc << 0)
    dns_header += struct.pack('!2B', one, two)
    dns_header += struct.pack('!4H', 1,record_count,0,0)

    return dns_header

# will create dns header specific to request/query. default resource record count is 1
def create_dns_query_header(dns_id, arc=0, *, cd=0):
    dns_header = struct.pack('!H', dns_id)

    qr, op, aa, tc, rd, ra, zz, ad, rc = 0,0,0,0,1,0,0,0,0
    one = (qr << 7) | (op << 3) | (aa << 2) | (tc << 1) | (rd << 0)
    two = (ra << 7) | (zz << 6) | (ad << 5) | (cd << 4) | (rc << 0)
    dns_header += struct.pack('!2B', one, two)
    dns_header += struct.pack('!4H', 1,0,0,arc)

    return dns_header

def load_cache(filename):
    try:
        with open(filename, 'r') as settings:
            cache = json.load(settings)
    except FileNotFoundError:
        cache = {'top_domains': {}, 'filter': []}

    return cache

def load_filter(filename):
    try:
        with open(filename, 'r') as settings:
            domain_filter = json.load(settings)
    except FileNotFoundError:
        domain_filter = {'filter': []}

    return domain_filter

def write_cache(data, filename):
    with open(filename, 'w') as cache_file:
        json.dump(data, cache_file, indent=4)

def record_parse_error(log_info):
    info = SimpleNamespace(**log_info)

    print('+'*30)
    print(f'UNSEEN RECORD TYPE :/ | {info.rtype}')
    print(f'NAME LENGTH: {info.nlen}')
    print(info.data)
    print('='*30)
    with open('dns_tls_relay.error', 'a+') as errors:
        errors.write('++++++++++++++++++++++++++\n')
        errors.write(f'UNSEEN RECORD TYPE :/ | {info.rtype}\n')
        errors.write(f'NAME LENGTH: {info.nlen}\n')
        errors.write(f'{info.data}\n')
        errors.write('==========================\n')
