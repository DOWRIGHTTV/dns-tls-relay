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
    time.sleep(.5)

if (__name__ == '__main__'):

    if (os.getuid() or DISABLED):
        print('DoTRelay must be ran as root.')
        hard_out()

    parser = argparse.ArgumentParser(description='Privacy proxy to convert DNS:UDP to TLS w/ local record caching.')
    parser.add_argument('--version', action='version', version='v9001b')

    parser.add_argument('-l',
        metavar='ip_addr [ip_addr...]', help='List of IP Addresses to listen for requests on',
        type=IPv4Address, nargs=1, default='127.0.0.1'
    )

    parser.add_argument('-r',
        metavar='ip_addr', help='List of (2) IP Addresses of desired public DoT resolvers',
        type=IPv4Address, nargs=2, default=[DEFAULT_SERVER_1, DEFAULT_SERVER_2]
    )

    parser.add_argument('-k', help='Enables TLS connection keepalives', type=int, choices=[4, 6, 8], default=0)
    parser.add_argument('-c', help='Prints general messages to screen', action='store_true')
    parser.add_argument('-v', help='Prints informational messages to screen', action='store_true')

    args = parser.parse_args(sys.argv[1:])

    Log.setup(console=args.c, verbose=args.v)

    DNSRelay.dns_servers.primary['ip'] = f'{args.r[0]}'
    DNSRelay.dns_servers.secondary['ip'] = f'{args.r[1]}'

    display_banner()

    DNSRelay.run(args.l, args.k)
