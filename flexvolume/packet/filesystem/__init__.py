# Copyright (c) 2017 Karl Bunch <karlbunch@karlbunch.com>

""" Filesystem handler for flexvolume plugin """

from .. import exceptions

class FilesystemHandler(object):
    """ Base filesystem handler """
    def __init__(self):
        pass

    def mount(self, mount_dir, devices, options):
        """ Mount a filesystem on the provided devices to mount_dir with options """
        raise NotImplementedError

    def unmount(self, mount_dir):
        """ Unmount a filesystem from mount_dir """
        raise NotImplementedError

def get_handler(fs_type, log=None):
    """ Return the handler object """
    if fs_type.lower() == "zfs":
        from .zfs import FilesystemHandlerZFS
        return FilesystemHandlerZFS(log)

    raise exceptions.FSHandlerFSTypeNotSupported("%s fileystem type is not supported" % fs_type)
