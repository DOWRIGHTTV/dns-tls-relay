#!/usr/bin/env python3

import json

from datetime import datetime, timezone

from dns_tls_constants import *

def load_cache(filename):
    if (not isinstance(filename, str)):
        raise TypeError('cache file must be a string.')

    try:
        with open(f'{filename}.json', 'r') as settings:
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

def looper(sleep_len):
    def decorator(loop_function):

        # pre process logic to optimize decorated functions with NO_DELAY set
        if (sleep_len):
            def wrapper(*args):
                while True:
                    loop_function(*args)

                    fast_sleep(sleep_len)

        else:
            def wrapper(*args):
                while True:
                    loop_function(*args)

        return wrapper
    return decorator


class Log:

    @classmethod
    def setup(cls, verbose):
        # define function to print log message. this will overload verbose function if enabled.
        if (verbose):

            @classmethod
            def func(cls, thing_to_print):
                write_log(f'[{cls.time()}]{thing_to_print}')

            # overloading verbose method with newly defined function.
            setattr(cls, 'verbose', func)

    @classmethod
    def console(cls, msg):
        write_log(f'[{cls.time()}]{msg}')

    @classmethod
    def error(cls, msg):
        write_log(f'[{cls.time()}]{msg}')

    @staticmethod
    # verbose method does nothing by default. if verbose is set on start this method will be overloaded with a proper
    # method to print log entry.
    def verbose(msg):
        pass

    @staticmethod
    def time(tz=timezone.utc):
        xt = datetime.now(tz).timetuple()

        return f'{xt.tm_mon}/{xt.tm_mday} {xt.tm_hour}:{xt.tm_min}:{xt.tm_sec}'
