#!/usr/bin/python3

import os, sys
import time
import struct
import ssl

from socket import socket, timeout, AF_INET, SOCK_DGRAM, SOCK_STREAM

DNS_SERVER = '1.1.1.1'
SERVER_ADDRESS = '192.168.5.135'

DNS_TLS_PORT = 853

MESSAGE = b'\x00+By\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x15advancedcombattracker\x03com\x00\x00\x01\x00\x01'

def Connect():
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((SERVER_ADDRESS, 0))
        sock.settimeout(3)

        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
        context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)

        secure_socket = context.wrap_socket(sock, server_hostname=DNS_SERVER)
        secure_socket.connect((DNS_SERVER, DNS_TLS_PORT))
    except Exception as E:
        print(f'CONNECT: {E}')
        secure_socket = None

    return secure_socket

def Main():
    while True:
        secure_socket = Connect()
        try:
            secure_socket.send(MESSAGE)

            data_from_server = secure_socket.recv(4096)
            if (not data_from_server):
                break
            print(data_from_server)
            print('RESPONSE RECIEVED')
            time.sleep(.5)
        except Exception as E:
            print(f'SEND: {E}')

    Main()

if __name__ == '__main__':
    Main()