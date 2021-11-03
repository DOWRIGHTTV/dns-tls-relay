#!/usr/bin/env python3

import os
import time
import argparse

from sys import argv
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

def argument_validation():
    # forcing 2 servers for failover. technically not required, but would need to modify
    # data structure holding server data // 2 servers is standard anyways.
    if (len(SERVERS) != 2):
        raise ValueError('2 public resolvers must be specified if the server argument is used.')

    ip_validation = [*LISTENER_IPS, *SERVERS]
    for addr in ip_validation:
        try:
            IPv4Address(addr)
        except:
            raise ValueError(f'argument {addr} is an invalid ip address.')

    DNSRelay.dns_servers.primary['ip']   = SERVERS[0]
    DNSRelay.dns_servers.secondary['ip'] = SERVERS[1]

if (__name__ == '__main__'):
    parser = argparse.ArgumentParser(description='Privacy proxy converting DNS/UDP to TLS w/ local record caching.')
    parser.add_argument('--version', action='version', version='v9001b')
    parser.add_argument('-l', '--listeners', help='comma separated ips to listen on')
    parser.add_argument('-r', '--resolvers', help='comma separated ips of public DoT resolvers')
    parser.add_argument('-v', '--verbose', help='prints output to screen', action='store_true')

    args = parser.parse_args(argv[1:])

    if (args.resolvers):
        SERVERS = tuple(args.resolvers.split(','))

    else:
        SERVERS = (DEFAULT_SERVER_1, DEFAULT_SERVER_2)

    if (args.listeners):
        LISTENER_IPS = tuple(args.listeners.split(','))

    else:
        LISTENER_IPS = ('127.0.0.1',)

    try:
        argument_validation()
    except ValueError as E:
        print(E)
        hard_out()

    if (os.getuid() or DISABLED):
        print('DNS over TLS Relay must be ran as root.')
        hard_out()

    display_banner()

    Log.setup(verbose=args.verbose)
    DNSRelay.run(LISTENER_IPS)
