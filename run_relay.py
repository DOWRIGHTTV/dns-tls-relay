#!/usr/bin/env python3

import os, sys
import time
import argparse

from sys import argv
from ipaddress import IPv4Address

from basic_tools import Log
from dns_tls_relay import DNSRelay

# override for testing arguments
DISABLED = False

# addresses which the relay will receive dns requests
LISTENING_ADDRESSES = (
    '127.0.0.1',
)

# must support DNS over TLS (not https/443, tcp/853)
DEFAULT_SERVER_1 = '1.1.1.1'
DEFAULT_SERVER_2 = '1.0.0.1'
SERVERS = [DEFAULT_SERVER_1, DEFAULT_SERVER_2]

# this makes me feel cool. especially when i havent left the house in forever due to covid-19.
def display_banner():
    print('@@@@@@@    @@@@@@   @@@@@@@     @@@@@@@   @@@@@@@@  @@@        @@@@@@   @@@ @@@')
    print('@@@@@@@@  @@@@@@@@  @@@@@@@     @@@@@@@@  @@@@@@@@  @@@       @@@@@@@@  @@@ @@@')
    print('@@!  @@@  @@!  @@@    @@!       @@!  @@@  @@!       @@!       @@!  @@@  @@! !@@')
    print('!@!  @!@  !@!  @!@    !@!       !@!  @!@  !@!       !@!       !@!  @!@  !@! @!!')
    print('@!@  !@!  @!@  !@!    @!!       @!@!!@!   @!!!:!    @!!       @!@!@!@!   !@!@! ')
    print('!@!  !!!  !@!  !!!    !!!       !!@!@!    !!!!!:    !!!       !!!@!!!!    @!!! ')
    print('!!:  !!!  !!:  !!!    !!:       !!: :!!   !!:       !!:       !!:  !!!    !!:  ')
    print(':!:  !:!  :!:  !:!    :!:       :!:  !:!  :!:        :!:      :!:  !:!    :!:  ')
    print(' :::: ::  ::::: ::     ::       ::   :::   :: ::::   :: ::::  ::   :::     ::  ')
    print(':: :  :    : :  :      :         :   : :  : :: ::   : :: : :   :   : :     :   ')
    print('by DOWRIGHT | https://github.com/dowrighttv                    ^^^^ for fun ^_^')
    print('===============================================================================')
    time.sleep(.5)
    print('starting...')
    time.sleep(1)

def argument_validation():
    # forcing 2 servers for failover. technically not required, but would need to modify
    # data structure holding server data // 2 servers is standard anyways.
    if (len(SERVERS) != 2):
        raise ValueError('2 public resolvers must be specified if the server argument is used.')

    ip_validation = list(LISTENING_ADDRESSES)

    DNSRelay.dns_servers.primary['ip']   = SERVERS[0]
    DNSRelay.dns_servers.secondary['ip'] = SERVERS[1]

    ip_validation.extend(SERVERS)

    for addr in ip_validation:
        try:
            IPv4Address(addr)
        except:
            raise ValueError(f'argument {addr} is an invalid ip address.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Privacy proxy which converts DNS/UDP to TLS + local record caching.')
    parser.add_argument('--version', action='version', version='DoTrelay 9001')
    parser.add_argument('-i', '--ip-addrs', help='comma separated ips to listen on')
    parser.add_argument('-s', '--servers', help='comma separated ips of public DoT resolvers')
    parser.add_argument('-v', '--verbose', help='prints output to screen', action='store_true')

    args = parser.parse_args(argv[1:])

    l_addrs = args.ip_addrs
    servers = args.servers
    VERBOSE = args.verbose

    if (servers):
        SERVERS = tuple(servers.split(','))

    if (l_addrs):
        LISTENING_ADDRESSES = tuple(l_addrs.split(','))

    try:
        argument_validation()
    except ValueError as E:
        sys.stdout.err(E)
        os._exit(1)

    if (os.getuid() or DISABLED):
        sys.stdout.err('DNS over TLS Relay must be ran as root.')
        os._exit(1)


    display_banner()

    Log.setup(verbose=VERBOSE)
    DNSRelay.run(LISTENING_ADDRESSES)