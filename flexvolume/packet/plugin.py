# Copyright (c) 2017 Karl Bunch <karlbunch@karlbunch.com>

""" Implements a kubernetes flexvolume that uses packet volume (block store service) for volumes

    See https://github.com/kubernetes/community/blob/master/contributors/devel/flexvolume.md

    json_options from kubernetes/pkg/volume/flexvolume/driver-call.go:
        "kubernetes.io/fsType"              - Which flexvolume.packet.filesystem.{fsType} class to use for mount/unmount operations
        "kubernetes.io/readwrite"           - ro/rw - Mount option
        "kubernetes.io/secret"              - Not Used
        "kubernetes.io/fsGroup"             - Not Used
        "kubernetes.io/mountsDir"           - Not Used
        "kubernetes.io/pvOrVolumeName"      - Used to create filesystem assets (i.e. zpool name is derived from this)
        "kubernetes.io/pod.name"            - Not Used
        "kubernetes.io/pod.namespace"       - Not Used
        "kubernetes.io/pod.uid"             - Not Used
        "kubernetes.io/serviceAccount.name" - Not Used

    flexvolume.packet options:
        "packet.net/plan"                   - Name of the plan from config to use (i.e. Standard, Performance)
        "packet.net/numVolumes"             - Number of volumes you want to create/attach for the filesystem handler to use (i.e. Mirroring)
        "packet.net/sizeGb"                 - Size of the volumes in gigs

    flexvolume.packet.filesystem.zfs options:
        "packet.net/zfs/vdevType"           - vdev type to create (i.e. mirror, raidz)
        "packet.net/zfs/createOptions"      - zpool create options (e.g. "-o ashift=12 -O recordsize=16k")
        "packet.net/zfs/snapshotOnMount"    - Snapshot the volume on each mount (default: false)

"""

import glob
import json
import logging
import logging.handlers
import os
import subprocess
import time
import traceback
import types
from copy import deepcopy
from socket import gethostname
import yaml
import packet

from .filesystem import get_handler
from .exceptions import OperationFailureError, OperationInvalidOptionsError, PipeExecError

def Run(args):
    """ Run an operation output status json to stdout """
    return Plugin().run_operation(args[0], args[1:])

class Plugin(object):
    """ Implements the flexvolume plugin operations """

    def __init__(self, logger=None, log_stream=None):
        self.config = yaml.load(open(os.path.expanduser("/etc/kubernetes/flexvolume-packet.conf")))
        self.api_manager = None
        self.fs_handler = None

        if logger:
            self.log = logger
        else:
            if log_stream != None:
                handler = logging.StreamHandler(stream=log_stream)
            else:
                handler = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_DAEMON)

                handler.ident = 'packet-volume'

            handler.setFormatter(logging.Formatter('[%(process)d] %(levelname)s %(message)s'))

            self.log = logging.getLogger("packet-volume")
            self.log.setLevel(logging.DEBUG)
            self.log.addHandler(handler)

        self.log.debug("Starting packet-volume class")

    def get_manager(self):
        """ Get packet API manager """
        if self.api_manager:
            return self.api_manager

        self.api_manager = packet.Manager(auth_token=self.config['api']['token'])

        return self.api_manager

    # TODO Make this into a utility function at module level?
    def pipe_exec(self, cmd, log_stdout=False):
        """ Run command capturing stdout/stderr, raise exception if returncode != 0 """
        self.log.debug("run: %s", str(cmd))

        result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        if log_stdout:
            self.log.info("run...: %s", str(cmd))

            for line in result.stdout.rstrip().decode('utf-8').split("\n"):
                self.log.info("stdout: %s", line)

            self.log.info("return: %d", result.returncode)

        if result.returncode != 0:
            raise PipeExecError(
                "'{}' failed, returned {} - '{}'".format(" ".join(cmd), result.returncode, result.stdout.rstrip().decode('utf-8'))
            )

        return result

    # pylint: disable=too-many-arguments
    def response(self, status="Not supported", message=None, device=None, volume_name=None, attached=None, capabilities=None):
        """
        See kubernetes/pkg/volume/flexvolume/driver-call.go:192

        type DriverStatus struct {
                // Status of the callout. One of "Success", "Failure" or "Not supported".
                Status string `json:"status"`
                // Reason for success/failure.
                Message string `json:"message,omitempty"`
                // Path to the device attached. This field is valid only for attach calls.
                // ie: /dev/sdx
                DevicePath string `json:"device,omitempty"`
                // Cluster wide unique name of the volume.
                VolumeName string `json:"volumeName,omitempty"`
                // Represents volume is attached on the node
                Attached bool `json:"attached,omitempty"`
                // Returns capabilities of the driver.
                // By default we assume all the capabilities are supported.
                // If the plugin does not support a capability, it can return false for that capability.
                Capabilities map[string]bool
        }
        """
        resp = {}

        resp['status'] = status

        if message:
            resp['message'] = message

        if device:
            resp['device'] = device

        if volume_name:
            resp['volumeName'] = volume_name

        if attached:
            resp['attached'] = attached

        if capabilities:
            resp['capabilities'] = capabilities

        resp_json = json.dumps(resp)

        self.log.info("Response: %s", resp_json)

        print(resp_json)

        if status != "Success":
            return False

        return True

    def run_operation(self, operation, args):
        """ Run a single plugin operation """
        handler_name = 'op_' + operation

        if handler_name not in dir(self):
            return self.response(status="Not Supported", message="Unknown operation: {}".format(operation))

        handler = getattr(self, handler_name)

        if not callable(handler):
            return self.response(status="Not Supported", message="Invalid operation: {}".format(operation))

        try:
            start_time = time.time()

            result = handler(*args)

            delta_time = int(time.time() - start_time)

            if result:
                self.log.info("%s SUCCESS after %d second(s)", operation, delta_time)
            else:
                self.log.error("%s FAILED after %d second(s)", operation, delta_time)

            return result
        except OperationFailureError as op_err:
            return self.response(status="Failure", message=op_err.message)
        except OperationInvalidOptionsError as op_err:
            return self.response(status="Failure", message="Invalid flexVolume.options: %s" % op_err.message)
        except: # pylint: disable=bare-except
            self.log.info("Exception Calling %s(%s)\n%s", handler_name, args, traceback.format_exc())
            return self.response(status="Failure", message="Driver error, check syslog for details.")

    def parse_options(self, json_options): # pylint: disable=no-self-use
        """ Parse json options passed in from command line calls """
        opts = json.loads(json_options)

        numVolumes = 1

        if "packet.net/numVolumes" in opts:
            numVolumes = int(opts['packet.net/numVolumes'])

        zfs_options = {
            "vdevType": "",
            "createOptions": "-o ashift=12",
            "snapshotOnMount": False
        }

        if "packet.net/zfs/vdevType" in opts:
            zfs_options["vdevType"] = opts["packet.net/zfs/vdevType"]
        else:
            if numVolumes > 1:
                zfs_options["vdevType"] = "mirror"

        if "packet.net/zfs/createOptions" in opts:
            zfs_options["createOptions"] = opts["packet.net/zfs/createOptions"]

        if "packet.net/zfs/snapshotOnMount" in opts:
            if opts["packet.net/zfs/snapshotOnMount"] == "true":
                zfs_options["snapshotOnMount"] = True

        try:
            options = types.SimpleNamespace(**{
                "volumeName": opts["kubernetes.io/pvOrVolumeName"],
                "fsType": opts["kubernetes.io/fsType"],
                "readwrite": opts["kubernetes.io/readwrite"] if "kubernetes.io/readwrite" in opts else "rw",
                "packet": types.SimpleNamespace(**{
                    "sizeGb": int(opts["packet.net/sizeGb"]),
                    "plan": opts["packet.net/plan"] if "packet.net/plan" in opts else None,
                    "numVolumes": numVolumes,
                    "zfs": types.SimpleNamespace(**zfs_options)
                }),
            })
        except KeyError as err:
            raise OperationInvalidOptionsError("Missing required key: %s" % err)

        return options

    def op_init(self):
        """ Handle operation 'init' """
        cfg = deepcopy(self.config)
        cfg["api"].pop("token", None)

        self.log.info("init called")

        self.response(status="Success", capabilities={"attach": False}, message="Config: {}".format(cfg))

        return True

    def find_volumes(self, options, create=False):
        """ Find volumes needed for this operation """
        volumes = []

        self.log.debug("Getting list of volumes for project %s", self.config["project"]["id"])
        tm_start = time.time()

        # See if the volumes already exist, using volume description yaml look for option.volumeName
        for volume in self.get_manager().list_volumes(self.config["project"]["id"]):
            metadata = yaml.load(volume.description)

            if not isinstance(metadata, dict) or "volumeName" not in metadata:
                continue

            self.log.debug("Found volume %s @ %s = %s", volume.id, volume.facility.code, metadata)

            if metadata['volumeName'] == options.volumeName:
                if volume.facility.code == self.config["facility"]["code"]:
                    volumes.append(volume)
                else:
                    self.log.info("ERROR: Facility mis-match: volume %s facility is '%s' config facility is '%s'",
                                  volume.name, volume.facility, self.config["facility"]["code"])
                    return None

        self.log.debug("Received %s volumes in %.03f seconds", len(volumes), time.time() - tm_start)

        if volumes:
            return volumes

        # We didn't find the volumes should we create them?
        if not self.config['allowCreate'] or not create:
            return None

        # Attempt to create options.packet.numVolumes volumes
        self.log.info("Creating %s volumes with volumeName %s", options.packet.numVolumes, options.volumeName)

        # What plan should we use?
        plan = None

        if options.packet.plan:
            plan, = (i for i in self.config['plans'] if i['name'] == options.packet.plan)

        if plan is None:
            plan, = (i for i in self.config['plans'] if 'isDefault' in i and i['isDefault'])

        if plan is None:
            self.log.info("volume %s packet.net/plan not specified and config does not have a isDefault plan defined", options.volumeName)
            return None

        # Now create volumes via api
        for vol_num in range(0, options.packet.numVolumes):
            volumeOptions = {
                "project_id" : self.config["project"]["id"],
                "description": yaml.dump({
                    "volumeName": options.volumeName,
                    "volumeNum": vol_num + 1,
                    "numVolumes": options.packet.numVolumes,
                    "fsType": options.fsType
                    }),
                "plan"       : plan["id"],
                "size"       : options.packet.sizeGb,
                "facility"   : self.config["facility"]["id"]
            }

            self.log.info("Creating volume %s", volumeOptions)

            newVolume = self.get_manager().create_volume(**volumeOptions)

            self.log.info("Created volume %s (%s)", newVolume.name, newVolume.id)

            volumes.append(newVolume)

        if volumes:
            return volumes

        return None

    def find_device(self):
        """ Find our packet device (server/host) """
        # Search config first (faster, easier on packet's api servers)
        if "devices" in self.config:
            hostname = gethostname()

            for device in self.config["devices"]:
                if device["hostname"] == hostname:
                    return types.SimpleNamespace(**device)

        # Gather up all our mac addresses
        mac_addresses = []
        for file_name in glob.glob("/sys/class/net/e[tn][hs]*/address"):
            with open(file_name) as fobj:
                addr = fobj.readline().rstrip()

                if addr not in mac_addresses:
                    mac_addresses.append(addr)

        self.log.debug("Getting list of devices for project %s", self.config["project"]["id"])

        # Find a device that matches one of our mac addresses
        for device in self.get_manager().list_devices(self.config["project"]["id"]):
            if not hasattr(device, "network_ports"):
                continue

            for port in device.network_ports:
                if "mac" in port["data"]:
                    if port["data"]["mac"] in mac_addresses:
                        return device

        raise OperationFailureError("Unable to find device/host to attach volumes to.")

    # pylint: disable=too-many-branches
    def op_mount(self, mount_dir, json_options):
        """
        Mount the volume at the mount dir. This call-out defaults to
        bind mount for drivers which implement attach & mount-device
        call-outs. Called only from Kubelet.

        <driver executable> mount <mount dir> <json options>
        """

        options = self.parse_options(json_options)

        self.log.info("op_mount: mount_dir: %s options: %s", mount_dir, options)

        self.fs_handler = get_handler(options.fsType, log=self.log)

        # Find device first, if we don't have one might as well not create volumes etc.
        device = self.find_device()

        # Find/Create the volumes
        volumes = self.find_volumes(options, create=True)

        if volumes is None or not volumes:
            raise OperationFailureError("failed to find/create volumes with volumeName: {} in their description".format(options.volumeName))

        for volume in volumes:
            self.log.debug("%s (%s) %s", volume.name, volume.id, volume.description.rstrip())

        if len(volumes) != options.packet.numVolumes:
            raise OperationFailureError("Expected {} volume(s) but found {}.".format(options.packet.numVolumes, len(volumes)))

        # Have volumes, now we need to attach them to our device
        for volume in volumes:
            try:
                self.log.info("Attach %s to %s", volume.name, device.hostname)
                volume.attach(device.id)
            except packet.Error as err:
                if "already attached" in str(err):
                    self.log.info("Volume %s already attached to %s", volume.name, device.hostname)
                else:
                    self.log.info("API Failure: %s", err)
                    raise
            except: # pylint: disable=bare-except
                self.log.info("Exception Attaching volume %s to device %s - %s", volume.name, device.id, traceback.format_exc())
                raise OperationFailureError("Driver error, check syslog for details.")

        # Give blockstore some time to catchup (is there a better way? maybe pull metadata?)
        time.sleep(5)

        # Attach the volumes to block devices
        block_devices = []
        for volume in volumes:
            try:
                self.pipe_exec(["/usr/bin/packet-block-storage-attach", "-m", "queue", volume.name], log_stdout=True)
            except PipeExecError:
                raise OperationFailureError("/usr/bin/packet-block-storage-attach {} failed: {}".format(volume.name, traceback.format_exc()))

            # Find the device path, sometimes it ends up on /dev/mapper/volumeName others /dev/mapper/WWID
            dev_path = "/dev/mapper/{}".format(volume.name)

            if not os.path.islink(dev_path):
                # Look for /dev/mapper/{wwid}
                with open("/etc/multipath/bindings") as fobj:
                    for map_line in fobj.readlines():
                        map_volumeName, map_wwid = map_line.rstrip().split(" ")

                        if map_volumeName == volume.name:
                            self.log.info("Found %s wwid %s", map_volumeName, map_wwid)
                            dev_path = "/dev/mapper/{}".format(map_wwid)
                            break

            if not os.path.islink(dev_path):
                raise OperationFailureError("packet-block-storage-attach failed, did not find mapper link at {}".format(dev_path))

            block_devices.append(dev_path)

        # Give multipath some time to catchup (is there a better way here?)
        time.sleep(5)

        self.pipe_exec(["/sbin/multipath", "-l"], log_stdout=True)

        if self.fs_handler.mount(mount_dir, block_devices, options):
            return self.response(status="Success")

        raise OperationFailureError("mount failed")

    # pylint: disable=too-many-locals,too-many-statements
    def op_unmount(self, mount_dir):
        """
        Unmount the volume. This call-out defaults to bind mount for
        drivers which implement attach & mount-device call-outs. Called
        only from Kubelet.

        <driver executable> unmount <mount dir>
        """
        self.log.info("op_unmount: mount_dir: %s", mount_dir)

        # Search for fsType for this mount_dir
        fsType = None
        with open("/proc/mounts") as fobj:
            for line in fobj.readlines():
                entry = line.split()
                if entry[1] == mount_dir:
                    fsType = entry[2]
                    break

        if fsType is None:
            self.log.warning("Can't find fsType for %s volumes may be stuck attached to this host.", mount_dir)

        self.fs_handler = get_handler(fsType, log=self.log)

        status, block_devices = self.fs_handler.unmount(mount_dir)

        if not status:
            # If fs_handler.unmount returned False we try old fashioned os umount(8)
            # NOTE: This means the underlying volumes might not be detachable!
            try:
                self.pipe_exec(["/bin/umount", mount_dir], log_stdout=True)
            except PipeExecError:
                raise OperationFailureError("umount failed: {}".format(traceback.format_exc()))

        # Now try and detach the volumes
        self.log.info("Mapping Block device(s) to volumes: %s", ", ".join(block_devices))

        volume_names = []

        for dev_path in block_devices:
            if dev_path.startswith("/dev/mapper/volume"):
                volume_names.append(os.path.basename(dev_path))
            else:
                # Maybe it's a wwid
                wwid = os.path.basename(dev_path)

                with open("/etc/multipath/bindings") as fobj:
                    for map_line in fobj.readlines():
                        map_volumeName, map_wwid = map_line.rstrip().split(" ")

                        if map_wwid == wwid:
                            self.log.info("Found %s wwid %s", map_volumeName, map_wwid)
                            volume_names.append(map_volumeName)
                            break

        if not volume_names:
            raise OperationFailureError("Unable to determine volumes to detach, they're stuck attached to this host.")

        self.log.info("Detaching Volume(s): %s", ", ".join(volume_names))

        for volume_name in volume_names:
            try:
                self.pipe_exec(["/usr/bin/packet-block-storage-detach", volume_name], log_stdout=True)
            except PipeExecError:
                raise OperationFailureError("/usr/bin/packet-block-storage-detach failed: {}".format(traceback.format_exc()))

        self.log.info("Block devices detached.")

        # Have to give blockstore time to notice we logged out of the volume
        time.sleep(10)

        self.log.info("Detaching volumes from host.")

        for volume in self.get_manager().list_volumes(self.config["project"]["id"]):
            if volume.name in volume_names:
                # Appears the current python-packet library just detaches the volume from everything!!
                # TODO consider a PR to only detach from specific device
                for i in range(10, -1, -1):
                    try:
                        volume.detach()
                        self.log.info("Detached volume %s from host.", volume.name)
                        break
                    except packet.Error as err:
                        self.log.info("Retry #%d: Failed to detach %s: %s", i, volume.name, err)
                        if i:
                            time.sleep(10)
                        else:
                            raise

        # reset the wwids file to only include the current multipath devices
        self.pipe_exec(["/sbin/multipath", "-W"])

        return self.response(status="Success")

    def op_getvolumename(self, json_options):
        """
        Sort of broken in v1.6/v1.7/v1.8 just return Not supported
        We're using the mount/unmount operations to do all the heavy lifting anyway.
        """
        options = self.parse_options(json_options)

        self.log.info("op_getvolumename: options: %s", options)

        self.response(status="Not supported", message="Not yet")

        return True

    def op_attach(self, json_options, node_name):
        """
        Attach the volume specified by the given spec on the given
        host. On success, returns the device path where the device is
        attached on the node. Nodename param is only valid/relevant
        if "--enable-controller-attach-detach" Kubelet option is
        enabled. Called from both Kubelet & Controller manager.

        This call-out does not pass "secrets" specified in Flexvolume
        spec. If your driver requires secrets, do not implement this
        call-out and instead use "mount" call-out and implement attach
        and mount in that call-out.

        <driver executable> attach <json options> <node name>
        """
        self.log.info("op_attach: options: %s node: %s", json.loads(json_options), node_name)

        return self.response(status="Not supported", message="Not yet")

    def op_detach(self, device, node_name):
        """
        Detach the volume from the Kubelet node. Nodename param is only
        valid/relevant if "--enable-controller-attach-detach" Kubelet
        option is enabled. Called from both Kubelet & Controller manager.

        <driver executable> detach <mount device> <node name>
        """
        self.log.info("op_detach: device: %s node: %s", device, node_name)

        return self.response(status="Not supported", message="Not yet")

    def op_waitforattach(self, device, json_options):
        """
        Wait for the volume to be attached on the remote node. On
        success, the path to the device is returned. Called from both
        Kubelet & Controller manager. The timeout should be 10m.

        <driver executable> waitforattach <mount device> <json options>
        """
        self.log.info("op_waitforattach: device: %s options: %s", device, json.loads(json_options))

        return self.response(status="Not supported", message="Not yet")

    def op_isattached(self, json_options, node_name):
        """
        Check the volume is attached on the node. Called from both
        Kubelet & Controller manager.

        <driver executable> isattached <json options> <node name>
        """
        self.log.info("op_isattached: options: %s node: %s", json.loads(json_options), node_name)

        return self.response(status="Not supported", message="Not yet")

    def op_unmountdevice(self, device):
        """
        Unmounts the global mount for the device. This is called once
        all bind mounts have been unmounted. Called only from Kubelet.

        <driver executable> unmountdevice <mount device>
        """
        self.log.info("op_unmountdevice: device: %s", device)

        return self.response(status="Not supported", message="Not yet")
