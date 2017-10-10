# Copyright (c) 2017 Karl Bunch <karlbunch@karlbunch.com>

""" Support for zpool/zfs filesystems on top of packet blockstore volumes """

import sys
import logging
import subprocess
import collections
import time
import types
import yaml

from . import FilesystemHandler
from .. import exceptions

class _ZFSPool(object): # pylint: disable=too-few-public-methods
    """ Simple helper class for pool type """
    def __init__(self, pool_guid=None, pool_name=None, labels=None):
        self.guid = pool_guid
        self.name = pool_name

        if labels:
            self.labels = labels
        else:
            self.labels = []

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, str(self.__dict__))

class FilesystemHandlerZFS(FilesystemHandler):
    """ Implments zfs functions for a flexvolume """
    def __init__(self, logger=None, log_stream=None):
        if logger:
            self.log = logger
        else:
            handler = logging.StreamHandler(stream=log_stream or sys.stderr)
            handler.setFormatter(logging.Formatter('%(name)s %(process)d %(levelname)s %(message)s'))
            self.log = logging.getLogger("packet-volume-zfs")
            self.log.setLevel(logging.DEBUG)
            self.log.addHandler(handler)

        super(FilesystemHandlerZFS, self).__init__()

    def pipe_exec(self, cmd, log_stdout=False):
        """ Run command and capture stdout/stderr raise FSHandlerFatalError if returncode != 0 """
        self.log.debug("run: %s", str(cmd))

        result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        if log_stdout:
            self.log.info("run...: %s", str(cmd))

            for line in result.stdout.rstrip().decode('utf-8').split("\n"):
                self.log.info("stdout: %s", line)

            self.log.info("return: %d", result.returncode)

        if result.returncode != 0:
            raise exceptions.FSHandlerFatalError(
                "'{}' failed, returned {} - '{}'".format(" ".join(cmd), result.returncode, result.stdout.rstrip().decode('utf-8'))
            )

        return result

    def find_key(self, search_dict, search_key, path=""):
        """ walk dict and return all values where key == search_key """
        for key, value in search_dict.items():
            if isinstance(value, collections.abc.Mapping):
                yield from self.find_key(value, search_key, path=path + "." + key)
            else:
                if search_key == key:
                    yield path + "." + key, value

    def device_info(self, device):
        """ Get zfs device information """
        result = self.pipe_exec(["/sbin/zdb", "-l", device])

        lines = result.stdout.rstrip().decode('utf-8').split("\n")

        # Look for new blank volume
        if lines[1] == 'LABEL 0' and (lines[3] == 'failed to read label 0' or lines[3] == "failed to unpack label 0"):
            return None

        # zdb -l almost spits out yaml, we can break out the first label block and ask yaml to parse
        if lines[1] == "LABEL 0" and "version:" in lines[3]:
            label_block = []

            for line in lines[3:]:
                if line[0:5] == "-----":
                    break
                label_block.append(line)

            label = yaml.load("\n".join(label_block))

            if label != None:
                return types.SimpleNamespace(**label)

        self.log.error("Unable to parse output of zdb -l")

        count = -1
        for line in lines:
            count = count + 1
            self.log.error("zdb -l output: {:>5} {}".format(count, line))

        raise exceptions.FSHandlerFatalError("Failed to parse zdb -l output for device {}".format(device))

    def find_pool_using_devices(self, devices):
        """ Find a pool using the given block devices """
        labels = {}
        pool_guid = None
        pool_name = None
        for dev in devices:
            label = self.device_info(dev)

            if not label:
                self.log.info("%s does not have a ZFS label", dev)
            else:
                labels[dev] = label

                # Look for mismatched devices
                if pool_guid:
                    if label.pool_guid != pool_guid:
                        raise exceptions.FSHandlerFatalError("Device pool guid mismatch {} vs {}".format(label.pool_guid, pool_guid))
                else:
                    pool_guid = label.pool_guid
                    pool_name = label.name

        pool = _ZFSPool(pool_guid, pool_name, labels)

        self.log.debug("find_pool_using_devices returning %s", pool)

        return pool

    def find_pool_using_mount(self, target_mount_dir):
        """ Find a pool using the mount point """
        # Ask zfs for a list of zfs_name,mountpoint
        result = self.pipe_exec(["/sbin/zfs", "list", "-H", "-o", "name,mountpoint"])

        for line in result.stdout.rstrip().decode('utf-8').split("\n"):
            zfs_name, mount_dir = line.split()

            if mount_dir == target_mount_dir:
                pool = _ZFSPool(pool_name=zfs_name.split('/')[0])

                self.log.debug("find_pool_using_mount returning %s", pool)

                return pool

        return None

    def create_pool(self, devices, options):
        """ Create a fresh pool using provided devices and options """
        # New pool name, watch out for ZFS_MAX_DATASET_NAME_LEN(256)
        pool_name = "kubernetes-packet-volume-" + options.volumeName
        pool_name = pool_name[:255]

        # Should be empty volume(s) create zpool
        # TODO handle volumes > 2 (i.e. 4 would be mirror D0 D1 mirror D2 D3)
        # TODO handle raidz
        cmd = ["/sbin/zpool", "create", "-O", "canmount=noauto"]
        cmd = cmd + options.packet.zfs.createOptions.split(" ")
        cmd = cmd + [pool_name, options.packet.zfs.vdevType] + devices

        self.pipe_exec(cmd)

        self.log.info("Created pool %s", pool_name)

        return _ZFSPool(pool_name=pool_name)

    def import_pool(self, pool, options):
        """ import and existing pool """
        try:
            self.pipe_exec(["/sbin/zpool", "import", "-N", str(pool.guid)])
            self.log.info("imported pool %s (%s)", pool.name, pool.guid)
        except exceptions.FSHandlerFatalError as err:
            if not "a pool with that name already exists" in err.message:
                raise

            cfg = self.get_pool_config(pool)

            if cfg.pool_guid != pool.guid:
                raise exceptions.FSHandlerFatalError("failed to import pool, duplicate pool name conflict")
            else:
                self.log.info("Pool %s (%s) already imported as %s", pool.name, pool.guid, cfg.name)

        result = self.pipe_exec(["/sbin/zpool", "status", pool.name], log_stdout=True)

        lines = result.stdout.rstrip().decode('utf-8').split("\n")

        if "state: DEGRADED" in lines[1]:
            self.log.crtitcal("pool %s is DEGRADED", pool.name)

        if options.packet.zfs.snapshotOnMount:
            snapshot_name = "{}@mount-{}".format(pool.name, int(time.time()))

            self.log.info("Volume specifies packet.net/zfs/snapshotOnMount: true, creating snapshot: %s", snapshot_name)

            self.pipe_exec(["/sbin/zfs", "snapshot", "-r", snapshot_name])

            result = self.pipe_exec(["/sbin/zfs", "list", "-t", "snapshot", "-r", pool.name])

            count = -1
            self.log.info("snapshots for %s:", pool.name)

            for line in result.stdout.rstrip().decode('utf-8').split("\n"):
                count = count + 1
                if count > 0:
                    self.log.info("snapshot %2d for %s", count, line)
                else:
                    self.log.info("snapshot        %s", line)

            # TODO - Rotate/remove old snapshots?

        return pool

    def get_pool_config(self, pool):
        """ get pool configuration data """
        # Check to see if existing pool already imported with proper guid
        result = self.pipe_exec(["/sbin/zdb", "-C", pool.name])

        lines = result.stdout.rstrip().decode('utf-8').split("\n")

        cfg_dict = yaml.load("\n".join(lines[2:]))

        if cfg_dict != None:
            cfg = types.SimpleNamespace(**cfg_dict)

        self.log.debug("get_pool_config returning: %s", cfg)

        return cfg

    def export_pool(self, pool):
        """ export a pool """
        self.pipe_exec(["/sbin/zpool", "export", pool.name])

    def mount(self, mount_dir, devices, options):
        """ Import pool from given devices and mount to mount_dir """
        pool = self.find_pool_using_devices(devices)

        # Opps! The volumes don't match the number of labels, if this happens an admin will need to sort out the volumes
        # it's possible the volume.descriptions are out of sync etc.
        if pool.labels and len(pool.labels) != len(devices):
            raise exceptions.FSHandlerFatalError(
                "Found {} labels on {} devices, the volumes need to manually reconcilled".format(len(pool.labels), len(devices))
            )

        # If all the devices and labels match same pool guid then just import it.
        if len(pool.labels) == len(devices):
            if pool.guid is None:
                raise exceptions.FSHandlerFatalError("Devices all had labels but no pool guid?")
            else:
                self.import_pool(pool, options)
        elif pool.labels:
            raise exceptions.FSHandlerFatalError("Unexpected labels: {}".format(pool.labels))
        else:
            pool = self.create_pool(devices, options)

        # Mount pool filesystem to mount_dir
        self.pipe_exec(["/sbin/zfs", "set", "mountpoint=" + mount_dir, pool.name])

        try:
            self.pipe_exec(["/sbin/zfs", "mount", "-v", "-o", options.readwrite, pool.name])
        except exceptions.FSHandlerFatalError as err:
            if not "filesystem already mounted" in err.message:
                raise

            # Check maybe it's already on the right directory?
            mnt_pool = self.find_pool_using_mount(mount_dir)

            if mnt_pool is None or mnt_pool.name != pool.name:
                raise

            # Should be fine, unmount will clean up the mess later
            self.log.warning("Pool %s already mounted on %s, continuing anyway.", pool.name, mount_dir)

        return True

    def unmount(self, mount_dir):
        """ unmount mount_dir and export related pool """
        pool = self.find_pool_using_mount(mount_dir)

        if pool is None:
            # Not fatal, but not pretty either, the zfs pool won't be exported properly
            self.log.warning("Unable to find pool for directory %s, pool won't be exported!", mount_dir)
            return (False, [])

        self.pipe_exec(["/sbin/zfs", "unmount", pool.name])

        # Get the configure before exporting
        cfg = self.get_pool_config(pool)

        self.export_pool(pool)

        # Find the block devices for Volume so it can detach them
        block_devices = []

        if hasattr(cfg, 'vdev_tree'):
            # Looking for something like:
            # ".children[0].children[1].path" /dev/mapper/36001405c674c535efc84604b02ccc901
            for _, val in self.find_key(cfg.vdev_tree, 'path'):
                block_devices.append(val)
        else:
            self.log.warning("Unable to find vdev_tree for pool %s, can't find devices to detach!", pool.name)

        return (True, block_devices)
