#!/usr/bin/env python3

import threading

from copy import copy
from collections import deque

from basic_tools import Log
from dns_tls_constants import MSEC, ONE_SEC, fast_time, fast_sleep, byte_join


def bytecontainer(obj_name, field_names):
    '''named tuple like class factory for storing raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields. slots are
    being used to speed up attribute access.'''

    if not isinstance(field_names, list):
        field_names = field_names.split()

    len_fields = len(field_names)

    # NOTE: nonlocal to builtins/globals perf ratio is 4.5 to 7.8 (1.75x faster)
    _len = len
    _zip = zip
    _sum = sum
    _copy = copy
    _setattr = setattr
    _getattr = getattr
    _bytearray = bytearray

    class ByteContainer:

        __slots__ = (*field_names,)

        def __init__(self):
            for name in field_names:
                _setattr(self, name, b'')

        def __repr__(self):
            return f'{self.__class__.__name__}({obj_name}, {" ".join(field_names)})'

        def __str__(self):
            return byte_join([_getattr(self, name) for name in field_names])

        def __call__(self, *args):
            if (_len(args) != len_fields):
                raise TypeError(f'Expected {len_fields} arguments, got {_len(args)}')

            new_container = _copy(self)
            for name, value in _zip(field_names, args):
                _setattr(new_container, name, value)

            return new_container

        def __len__(self):
            ba = _bytearray()
            for name in field_names:
                ba += _getattr(self, name)

            return _len(ba)

        def __getitem__(self, position):
            return _getattr(self, f'{field_names[position]}')

        def __iter__(self):
            yield from [_getattr(self, x) for x in field_names]

        def __add__(self, other):
            ba = _bytearray()
            for name in field_names:
                ba += _getattr(self, name)

            return ba + other

        def __radd__(self, other):
            ba = _bytearray()
            for name in field_names:
                ba += _getattr(self, name)

            return other + ba

    container = ByteContainer()

    return container


class Initialize:
    '''class used to handle system module thread synchronization on process startup. this will ensure all
    threads have completed one loop before returning control to the caller. will block until condition is met.'''

    def __init__(self, name):
        self._Log  = Log
        self._name = name

        self._initial_time = fast_time()

        self.has_ran = False
        self._is_initializing = True
        self._thread_count = 0
        self._thread_ready = set()

    def wait_for_threads(self, *, count):
        '''will block until the checked in thread count has reach the sent in count.'''
        if (not self._is_initializing or self.has_ran):
            raise RuntimeError('run has already been called for this self.')

        self._thread_count = count

        self._Log.console(f'{self._name} setup waiting for threads: {count}.')

        # blocking until all threads check in by individually calling done method
        while not self._initial_load_complete:
            fast_sleep(ONE_SEC)

        self.has_ran = True
        self._is_initializing = False

        Log.console(f'[{self._name}] setup complete.')

    def done(self):
        '''inform the handler a thread has been initialized. using default thread name as dict key.'''
        if (not self._is_initializing): return

        self._thread_ready.add(threading.get_ident())

        Log.verbose(f'[{self._name}] thread check-in.')

    def wait_in_line(self, *, wait_for):
        '''blocking call to wait for all lower number threads to complete before checking in and returning.

            initialize = Initialize(*args, **kwargs)
            initialize.wait_in_line(wait_for=2)

        this call has the potential to deadlock. positions must be sequential to work as intended, but are not
        required to be called in order.

        '''
        if (not self._is_initializing): return

        while wait_for < len(self._thread_ready):
            fast_sleep(ONE_SEC)

    @property
    def _initial_load_complete(self):
        if (self._thread_count == len(self._thread_ready)):
            return True

        return False

def relay_queue(Log, name=None):
    '''decorator to add custom queue mechanism for any queue handling functions. This
    is a direct replacement for dynamic_looper for queues.

    example:
        @relay_queue(Log, name='Server')
        def some_func(job):
            process(job)

    '''
    def decorator(func):

        queue = deque()
        queue_add = queue.append
        queue_get = queue.popleft

        job_available = threading.Event()
        job_wait = job_available.wait
        job_clear = job_available.clear
        job_set = job_available.set

        def wrapper(*args):
            Log.system(f'{name}/relay_queue started.')

            while True:
                job_wait()

                # clearing job notification
                job_clear()

                # processing all available jobs
                while queue:
                    job = queue_get()
                    try:
                        func(*args, job)
                    except Exception as E:
                        Log.error(f'while processing a {name}/dnx_queue started job, {E}')

                        fast_sleep(MSEC)

        def add(job):
            '''adds job to work queue, then marks event indicating a job is available.'''

            queue_add(job)
            job_set()

        wrapper.add = add
        return wrapper

    return decorator
