#!/usr/bin/env python3

from dns_tls_constants import *

def parse_query_name(data, dns_query=None, *, qname=False):
    '''parses dns name from sent in data. uses overall dns query to follow pointers. will return
    name and offset integer value if qname arg is True otherwise will only return offset.'''
    offset, contains_pointer, query_name = 0, False, []

    # TODO: this could be problematic since we slice down data. from what i my limited brain understands at the moment,
    #  data should never be an emtpy byte string if non malformed. the last iteration would have a null byte which is
    #  what this condition is actually testing against for when to stop iteration.
    #       // testing suggests this is fine for now
    while data[0]:

        # adding 1 to section_len to account for itself
        section_len, data = data[0], data[1:]

        # pointer value check. this used to be a separate function, but it felt like a waste so merged it.
        # NOTE: is this a problem is we don't pass in the reference query? is it possible for a pointer to be present in
        # cases where this function is used for non primary purposes?
        if (section_len & 192 == 192):

            # calculates the value of the pointer then uses value as original dns query index. this used to be a
            # separate function, but it felt like a waste so merged it. (-12 accounts for header not included)
            data = dns_query[((section_len << 8 | data[0]) & 16383) - 12:]

            contains_pointer = True

        else:
            # name len + integer value of initial length
            offset += section_len + 1 if not contains_pointer else 0

            query_name.append(data[:section_len].decode())

            # slicing out processed section
            data = data[section_len:]

    # increment offset +2 for pointer length or +1 for termination byte if name did not contain a pointer
    offset += 2 if contains_pointer else 1

    # evaluating qname for .local domain or non fqdn
    local_domain = True if len(query_name) == 1 or (query_name and query_name[-1] == 'local') else False

    if (qname):
        return offset, local_domain, '.'.join(query_name)

    return offset, local_domain

def domain_stob(domain_name):
    domain_bytes = byte_join([
        byte_pack(len(part)) + part.encode('utf-8') for part in domain_name.split('.')
    ])

    # root query (empty string) gets eval'd to length 0 and doesnt need a term byte. ternary will add term byte, if the
    # domain name is not a null value.
    return domain_bytes + b'\x00' if domain_name else domain_bytes

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
