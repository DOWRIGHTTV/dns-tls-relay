#!/usr/bin/env python3

VERBOSE = True

import struct
import json

from types import SimpleNamespace

def p(thing_to_print):
    if (VERBOSE):
        print(thing_to_print)

def convert_bit(bit):
    return 1 if bit else 0

def convert_dns_bytes_to_string(domain_name):
    length = domain_name[0]
    domain_raw = ''
    for byte in domain_name[1:]:
        if (length != 0):
            domain_raw += chr(byte)
            length -= 1
            continue

        length = byte
        domain_raw += '.'

    return domain_raw.lower()

def convert_dns_string_to_bytes(domain_name):
    split_domain = domain_name.split('.')
    domain_bytes = b''
    for part in split_domain:
        domain_bytes += struct.pack('B', len(part))
        for char in part:
            domain_bytes += struct.pack('B', ord(char))

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
def create_dns_query_header(dns_id, *, cd=0):
    dns_header = struct.pack('!H', dns_id)

    qr, op, aa, tc, rd, ra, zz, ad, rc = 0,0,0,0,1,0,0,0,0
    one = (qr << 7) | (op << 3) | (aa << 2) | (tc << 1) | (rd << 0)
    two = (ra << 7) | (zz << 6) | (ad << 5) | (cd << 4) | (rc << 0)
    dns_header += struct.pack('!2B', one, two)
    dns_header += struct.pack('!4H', 1,0,0,0)

    return dns_header

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

def load_cache(filename):
    try:
        with open(filename, 'r') as settings:
            cache = json.load(settings)
    except FileNotFoundError:
        cache = {'top_domains': {}}

    return cache

def write_cache(data, filename):
    with open(filename, 'w') as cache_file:
        json.dump(data, cache_file, indent=4)