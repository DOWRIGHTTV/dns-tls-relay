#!/usr/bin/env python3

import os
import sys
import time
import argparse

from ipaddress import IPv4Address

from dns_tls_constants import hard_out
from basic_tools import Log
from dns_tls_relay import DNSRelay

# override for testing arguments
DISABLED = False

# must support DNS over TLS (not https/443, tcp/853)
DEFAULT_SERVER_1 = '1.1.1.1'
DEFAULT_SERVER_2 = '1.0.0.1'

# this makes me feel cool. especially when i haven't left the house in forever due to covid-19.
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
    time.sleep(1)
    print('starting...')
    time.sleep(1)

if (__name__ == '__main__'):
    parser = argparse.ArgumentParser(description='Privacy proxy converting DNS/UDP to TLS w/ local record caching.')
    parser.add_argument('--version', action='version', version='v9001b')

    parser.add_argument('-l',
        metavar='IPA1 [IPA2...]', help='List of IP Addresses to listen for requests on',
        type=IPv4Address, nargs=2, default='127.0.0.1'
    )

    parser.add_argument('-r',
        metavar='IPA1 IPA2', help='List of (2) IP Addresses of desired public DoT resolvers',
        type=IPv4Address, nargs=2, default=[DEFAULT_SERVER_1, DEFAULT_SERVER_2]
    )

    parser.add_argument('-k', help='Enables TLS connection keepalives', type=int, choices=[4, 6, 8], default=0)
    parser.add_argument('-c', help='Prints running output to screen', action='store_true')
    parser.add_argument('-v', help='Prints information messages to screen', action='store_true')

    if (os.getuid() or DISABLED):
        print('DoTRelay must be ran as root.')
        hard_out()

    display_banner()

    args = parser.parse_args(sys.argv[1:])

    Log.setup(verbose=args.v)

    DNSRelay.dns_servers.primary['ip'] = f'{args.r[0]}'
    DNSRelay.dns_servers.secondary['ip'] = f'{args.r[1]}'

    DNSRelay.run(args.l, args.k)
