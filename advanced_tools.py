#!/usr/bin/env python3

import time
import threading

from copy import copy
from collections import deque

from basic_tools import Log
from dns_tls_constants import fast_time, fast_sleep


def bytecontainer(obj_name, field_names):
    '''named tuple like class factory for storing raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields. slots are
    being used to speed up attribute access.'''

    if not isinstance(field_names, list):
        field_names = field_names.split()

    class ByteContainer:

        __slots__ = (
            '_obj_name', '_field_names', '_len_fields',
            *field_names
        )

        def __init__(self, obj_name, field_names):
            self._obj_name = obj_name
            self._field_names = field_names
            for name in field_names:
                setattr(self, name, '')

            self._len_fields = len(field_names)

        def __repr__(self):
            return f"{self.__class__.__name__}({self._obj_name}, '{' '.join(self._field_names)}')"

        def __str__(self):
            fast_get = self.__getattribute__
            fields = [f'{n}={fast_get(n)}' for n in self._field_names]

            return f"{self._obj_name}({', '.join(fields)})"

        def __call__(self, *args):
            if (len(args) != self._len_fields):
                raise TypeError(f'Expected {self._len_fields} arguments, got {len(args)}')

            new_container = copy(self)
            for name, value in zip(self._field_names, args):
                setattr(new_container, name, value)

            return new_container

        def __len__(self):
            fast_get = self.__getattribute__

            return sum([len(fast_get(field_name)) for field_name in self._field_names])

        def __getitem__(self, position):
            return getattr(self, f'{self._field_names[position]}')

        def __iter__(self):
            fast_get = self.__getattribute__

            yield from [fast_get(x) for x in self._field_names]

        # NOTE: consider removing this for direct access. this used to provide some input validation, but now that
        # it has been removed, the method call itself is pretty worthless.
        def update(self, field_name, new_value):
           setattr(self, field_name, new_value)

    return ByteContainer(obj_name, field_names)


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
            fast_sleep(1)

        self.has_ran = True
        self._is_initializing = False

        Log.console(f'[{self._name}] setup complete.')

    def done(self):
        '''inform the handler a thread has been initialized. using default thread name as dict key.'''
        if (not self._is_initializing): return

        self._thread_ready.add(threading.get_ident())

        Log.console(f'[{self._name}] thread checkin.')

    def wait_in_line(self, *, wait_for):
        '''blocking call to wait for all lower number threads to complete before checking in and returning.

            initialize = Initialize(*args, **kwargs)
            initialize.wait_in_line(wait_for=2)

        this call has the potential to deadlock. positions must be sequential work as intended, but are not
        required to be called in order.

        '''
        if (not self._is_initializing): return

        while wait_for < len(self._thread_ready):
            fast_sleep(1)

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
            Log.console(f'{name}/relay_queue started.')

            while True:
                job_wait()
                # clearing job notification
                job_clear()
                # processing all available jobs
                while queue:
                    job = queue_get()
                    try:
                        print(*args, job)
                        # TODO: see if we should just send in the queue reference and perform the pop in the called func. if
                        # we do this we would probably want it to be optional and use a conditional set on start to identify.
                        func(*args, job)
                    except Exception as E:
                        Log.console(f'error while processing a {name}/dnx_queue started job. | {E}')

                        fast_sleep(.001)

        def add(job):
            '''adds job to work queue, then marks event indicating a job is available.'''

            queue_add(job)
            job_set()

        wrapper.add = add
        return wrapper

    return decorator
