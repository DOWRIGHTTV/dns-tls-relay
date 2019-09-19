#!/usr/bin/env python3

from types import SimpleNamespace

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