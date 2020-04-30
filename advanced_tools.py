#!/usr/bin/env python3

import time
import threading
import traceback

from copy import copy
from collections import deque

fast_sleep = time.sleep


class ByteContainer:
    '''named tuple like class for storing raw byte sections with named fields. calling
    len on the container will return sum of all bytes stored not amount of fields.'''

    __slots__ = (
        '_obj_name', '_field_names', '_byte_len',
        '__dict__' # needed due to variable field names.
    )

    def __init__(self, obj_name, field_names):
        self._obj_name = obj_name
        self._field_names = field_names.split()
        for name in self._field_names:
            setattr(self, name, '')

        self._byte_len = 0

    def __repr__(self):
        return f"{self.__class__.__name__}({self._obj_name}, '{' '.join(self._field_names)}')"

    def __str__(self):
        fields = [f'{n}={getattr(self, n)}' for n in self._field_names]

        return f"{self._obj_name}({', '.join(fields)})"

    def __call__(self, *args):
        if (len(args) != len(self._field_names)):
            raise TypeError(f'Expected {len(self._field_names)} arguments, got {len(args)}')

        new_container = copy(self)
        for name, value in zip(self._field_names, args):
            if (not isinstance(value, bytes)):
                raise TypeError('this container can only hold raw bytes.')

            new_container._byte_len += len(value)
            setattr(new_container, name, value)

        return new_container

    def __len__(self):
        return self._byte_len

    def __getitem__(self, position):
        return getattr(self, f'{self._field_names[position]}')

    def __iter__(self):
        yield from [getattr(self, x) for x in self._field_names]

    def update(self, field_name, new_value):
        if (field_name not in self._field_names):
            raise ValueError('field name does not exist.')

        if (not isinstance(new_value, bytes)):
            raise TypeError('this container can only hold raw bytes.')

        self._byte_len -= len(getattr(self, field_name))
        setattr(self, field_name, new_value)
        self._byte_len += len(new_value)


def relay_queue(Log, name=None):
    '''decorator to add custom queue mechanism for any queue handling functions. This
    is a direct replacement for dynamic_looper for queues.

    example:
        @dnx_queue(Log, name='Server')
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
            if (Log):
                Log.p(f'{name}/relay_queue started.')

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
                        traceback.print_exc()
                        if (Log):
                            Log.p(f'error while processing a {name}/relay_queue started job. | {E}')
                        fast_sleep(.001)

        def add(job):
            '''adds job to work queue, then marks event indicating a job is available.'''
            queue_add(job)
            job_set()

        wrapper.add = add
        return wrapper

    return decorator
