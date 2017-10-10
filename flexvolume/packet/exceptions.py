# Copyright (c) 2017 Karl Bunch <karlbunch@karlbunch.com>

""" Exceptions used by package """

class FSHandlerFatalError(Exception):
    """ Fatal Error """
    def __init__(self, message=None):
        self.message = message
        super(FSHandlerFatalError, self).__init__(message)

class FSHandlerFSTypeNotSupported(Exception):
    """ Unsupported fileystem type """
    def __init__(self, message=None):
        self.message = message
        super(FSHandlerFSTypeNotSupported, self).__init__(message)

class PipeExecError(Exception):
    """ Raised by pipe_exec when returncode != 0 """
    def __init__(self, message):
        self.message = message
        super(PipeExecError, self).__init__(message)

class OperationFailureError(Exception):
    """ Raised when an operation fails """
    def __init__(self, message):
        self.message = message
        super(OperationFailureError, self).__init__(message)
