#!/usr/bin/env python3

import time
import json

from copy import copy
from types import SimpleNamespace

from dns_tls_constants import short_unpack, byte_pack, dns_header_pack

def is_pointer(data):
    return True if 192 & data == 192 else False

def calculate_pointer(data):
    '''returns the integer value of the sum of 0-15 bits on 2 byte value. the integer value
    represents the string index of place to look for dns data. 12 bytes will be subtracted
    from the result since we are not including dns header in reference data.'''
    return 16383 & short_unpack(data)[0] - 12

def parse_query_name(data, dns_query=None, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''
    offset, pointer_present = 0, False
    query_name = []
    while True:
        length = data[0]
        if (length == 0):
            if (not pointer_present):
                offset += 1
            break
        # will break on pad or root name lookup
        if (is_pointer(length)):
            data = dns_query[calculate_pointer(data[:2]):]
            if (not pointer_present):
                offset += 2
            pointer_present = True
            continue

        if (not pointer_present):
            offset += length + 1 # name len + interger value of initial length

        query_name.append(data[1:1+length].decode())
        data = data[length+1:]

    if (qname):
        return '.'.join(query_name), offset

    return offset

def convert_dns_string_to_bytes(domain_name):
    if (not domain_name):
        return b'\x00'

    split_domain = domain_name.split('.')
    domain_bytes = []
    for part in split_domain:
        domain_bytes.append(byte_pack(len(part)))
        domain_bytes.append(part.encode('utf-8'))
    else:
        domain_bytes.append(b'\x00')

    return b''.join(domain_bytes)

# will create dns header specific to response. default resource record count is 1
def create_dns_response_header(dns_id, record_count=1, *, rd=1, ad=0, cd=0, rc=0):
    qr, op, aa, tc, ra, zz = 1,0,0,0,1,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, record_count, 0, 0)

# will create dns header specific to request/query. default resource record count is 1, additional record count optional
def create_dns_query_header(dns_id, arc=0, *, cd):
    qr, op, aa, tc, rd, ra, zz, ad, rc = 0,0,0,0,1,0,0,0,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, 0, 0, arc)

def load_cache(filename):
    if (not isinstance(filename, str)):
        raise TypeError('cache file must be a string.')

    if (not filename.endswith('.json')):
        filename += '.json'

    try:
        with open(filename, 'r') as settings:
            cache = json.load(settings)
    except FileNotFoundError:
        cache = {'top_domains': {}, 'filter': []}

    return cache

def write_cache(top_domains):
    with open('top_domains.json', 'r') as cache:
        f_cache = json.load(cache)

    f_cache['top_domains'] = top_domains

    with open('top_domains.json', 'w') as cache:
        json.dump(f_cache, cache, indent=4)

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

def looper(sleep_len):
    def decorator(loop_function):
        def wrapper(*args):
            while True:
                loop_function(*args)

                if (sleep_len):
                    time.sleep(sleep_len)

        return wrapper
    return decorator

def dyn_looper(loop_function):
    '''loop decorator that will sleep for the returned integer amount. functions returning None will
    not sleep on next iter and returning "break" will cancel the loop.'''
    def wrapper(*args):
        while True:
            sleep_amount = loop_function(*args)
            if (sleep_amount == 'break'): break
            elif (not sleep_amount): continue

            time.sleep(sleep_amount)

    return wrapper


class Log:
    _verbose = False

    @classmethod
    def setup(cls, verbose):
        if not isinstance(verbose, bool):
            raise TypeError('setup argument must be a boolean.')

        cls._verbose = verbose

    @classmethod
    def console(cls, thing_to_print):
        print(thing_to_print)

    @classmethod
    def p(cls, thing_to_print):
        if (cls._verbose):
            print(thing_to_print)
