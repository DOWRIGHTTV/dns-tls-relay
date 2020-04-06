#!/usr/bin/env python3

import time
import threading

from copy import copy
from collections import deque


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


class DNXQueue:
    '''small class to provide a custom queue mechanism for any queue handling functions. This
    is a direct replacement for dyn_looper for queues. this is to be used as a decorator,
    but it requires an active instance prior to decoration.

    example:
        dnx_queue = DNXQueue(Log)

        @dnx_queue
        def some_func(job):
            process(job)
    '''
    __slots__ = (
        '_Log', '_queue', '_func', '_job_available'
    )

    def __init__(self, Log=None):
        self._Log = Log
        self._queue = deque()

        self._job_available = threading.Event()

    def __call__(self, func):
        self._func = func

        return self._looper

    def _looper(self, instance):
        '''waiting for job to become available. once available, the event will be reset
        and the decorated function will be called with the return of queue pop as an
        argument. runs forever.'''
        if (self._Log):
            self._Log.console(f'dnx queue handler started | {self.__class__.__name__}/{instance.__class__.__name__}')

        while True:
            self._job_available.wait()
            self._job_available.clear()

            try:
                job = self._queue.popleft()
                self._func(instance, job)
            except Exception as E:
                if (self._Log):
                    self._Log.console(f'error while trying processing task/job. | {E}')
                time.sleep(.001)

        return self._looper

    def add(self, job):
        '''adds job to work queue, then marks event indicating a job is available.'''
        self._queue.append(job)
        self._job_available.set()
