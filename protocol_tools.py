#!/usr/bin/env python3

from dns_tls_constants import *

def parse_query_name(data, dns_query=None, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''
    offset, pointer_present, query_name = 0, False, []

    # TODO: this could be problematic since we slice down data. from what i my limited brain understands at the moment,
    #  data should never be an emtpy byte string if non malformed. the last iteration would have a null byte which is
    #  what this condition is actually testing against for when to stop iteration.
    while data[0]:

        # adding 1 to section_len to account for itself
        section_len, data = data[0], data[1:]

        # pointer value check. this used to be a separate function, but it felt like a waste so merged it.
        # NOTE: is this a problem is we don't pass in the reference query? is it possible for a pointer to be present in
        # cases where this function is used for non primary purposes?
        if (192 & section_len == 192):

            # calculates the value of the pointer then uses value as original dns query index. this used to be a
            # separate function, but it felt like a waste so merged it. (-12 is to account for header data)
            name_ptr = (section_len << 8 | data[0]) & 16383 - 12
            data = dns_query[name_ptr:]

            # ensuring offset is only added once if multiple pointers are followed
            offset += 2 if not pointer_present else 0

            pointer_present = True

        else:
            # name len + integer value of initial length
            offset += section_len + 1 if not pointer_present else 0

            query_name.append(data[1:section_len + 1].decode())

            # slicing out processed section
            data = data[section_len + 1:]

    # increment offset to account for null byte if name did not contain a pointer
    offset += 1 if not pointer_present else 0

    return ('.'.join(query_name), offset) if qname else offset

def domain_stob(domain_name):
    # "if part" condition is there because a root query evals the empty string length to 0. this would be ok, but then
    # we would have to make a condition to detect that to prevent a redundant termination byte.
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.') if part
    ])

    return domain_bytes + b'\x00'

# will create dns header specific to response. default resource record count is 1
def build_dns_response_hdr(dns_id, record_count=1, *, rd=1, ad=0, cd=0, rc=0):
    qr, op, aa, tc, ra, zz = 1,0,0,0,1,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, record_count, 0, 0)

# will create dns header specific to request/query. default resource record count is 1, additional record count optional
def build_dns_query_hdr(dns_id, arc=0, *, cd):
    qr, op, aa, tc, rd, ra, zz, ad, rc = 0,0,0,0,1,0,0,0,0
    f = (qr << 15) | (op << 11) | (aa << 10) | (tc << 9) | (rd << 8) | \
        (ra <<  7) | (zz <<  6) | (ad <<  5) | (cd << 4) | (rc << 0)

    return dns_header_pack(dns_id, f, 1, 0, 0, arc)
