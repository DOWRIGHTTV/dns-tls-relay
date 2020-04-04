#!/usr/bin/env python3

from struct import Struct
from enum import IntEnum
from collections import namedtuple

from advanced_tools import ByteContainer


KEEPALIVES_ENABLED = False

# general settings
MINIMUM_TTL = 300
DEFAULT_TTL = 3600
MAX_A_RECORD_COUNT = 3
HEARTBEAT_FAIL_LIMIT = 3
TOP_DOMAIN_COUNT = 20
KEEP_ALIVE_DOMAIN = 'duckduckgo.com'

NOT_VALID = -1
NULL_ADDR = (None, None)

# times
NO_DELAY = 0
MSEC = .001
FIVE_SEC = 5
THREE_MIN = 180
FIVE_MIN = 300

KEEPALIVE_INTERVAL = 8

# namedtuples
RELAY_CONN = namedtuple('relay_conn', 'remote_ip sock')
DNS_CACHE = namedtuple('dns_cache', 'ttl records')
CACHED_RECORD = namedtuple('cached_record', 'expire records top_domain')

# byte container
RESOURCE_RECORD = ByteContainer('resource_record', 'name qtype qclass ttl data')

# COMPILED STRUCTS
dns_header_unpack = Struct('!6H').unpack
dns_header_pack   = Struct('!6H').pack

resource_record_pack = Struct('!3HLH4s').pack

short_unpackf = Struct('!H').unpack_from

byte_pack = Struct('!B').pack
short_unpack = Struct('!H').unpack
short_pack   = Struct('!H').pack
long_pack    = Struct('!L').pack
long_unpack  = Struct('!L').unpack

double_short_unpack = Struct('!2H').unpack_from
double_short_pack   = Struct('!2H').pack


# enums
class PROTO(IntEnum):
    NOT_SET = 0
    TCP = 6
    DNS = 53
    DNS_TLS = 853


class DNS(IntEnum):
    ROOT = 0
    AR = 1
    NS = 2
    OPT = 41

    QUERY = 0
    KEEPALIVE = 69
    RESPONSE = 128