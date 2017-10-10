#!/usr/bin/python3 -B
""" Run live test against flexvolume driver

    The module requires root permissions so it can attach volumes, create zpools, mount, umount

"""

import curses
import io
import json
import logging
import os
import subprocess
import sys
import time
import traceback
from contextlib import redirect_stdout, redirect_stderr
from socket import gethostname

# TODO convert to python unittest
class _PluginTestLiveError(Exception):
    def __init__(self, message=None):
        self.message = message
        super(_PluginTestLiveError, self).__init__(message)

# pylint: disable=no-member
class PluginTestLive(object):
    """ Run live test of Plugin() """
    def __init__(self, batch=False):
        curses.setupterm()

        colors = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"]

        setaf = curses.tigetstr("setaf")

        if setaf:
            for i, color in zip(range(len(colors)), colors):
                setattr(self, "set_" + color, curses.tparm(setaf, i).decode("utf-8"))

        self.set_sgr0 = curses.tigetstr("sgr0").decode("utf-8")

        handler = logging.StreamHandler(stream=sys.stderr)
        handler.ident = 'live-test'
        handler.setFormatter(logging.Formatter('%(module)s.%(funcName)s:%(lineno)d %(message)s'))
        self.log = logging.getLogger("live-test")
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(handler)
        self.log.addFilter(self)
        self.plugin = None
        self.batch = batch
        self.start_time = time.time()

    def pipe_exec(self, cmd, log_stdout=False):
        """ run cmd capture output """
        self.log.info("RUN...: %s", str(cmd))

        result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        if log_stdout:
            for line in result.stdout.rstrip().decode('utf-8').split("\n"):
                self.log.info("STDOUT: %s", line)

        return result

    def fail(self, msg):
        """ Log failure and return exception object """
        self.log.error(">FAIL<: %s", msg)

        return _PluginTestLiveError(msg)

    def test_operation(self, operation, args, expected_status):
        """ Test a plugin operation """
        _, stdout, stderr = self.capture_output(lambda: self.plugin.run_operation(operation, args))

        for line in stderr.rstrip().split("\n"):
            if line:
                self.log.info("STDERR: %s", line)

        result = json.loads(stdout)

        if result is None or result['status'] != expected_status:
            raise self.fail("{}, expected_status = {}, result = {}".format([operation, args], expected_status, result))

        return result

    def test_file_check_before_mount(self, mount_dir, options):
        """ Check for test file before mount """
        result = self.pipe_exec(["df", "--output=source", mount_dir], log_stdout=True)

        lines = result.stdout.rstrip().decode('utf-8').split("\n")

        if lines[1] == options.volumeName:
            self.log.warning("%s already mounted?", options.volumeName)
            return True

        test_path = mount_dir + "/test.txt"

        if os.path.isfile(test_path):
            raise self.fail("{} exists before mount!".format(test_path))

    def test_file_check_after_mount(self, mount_dir, options):
        """ Check for test file after mount """
        result = self.pipe_exec(["df", "--output=source", mount_dir], log_stdout=True)

        lines = result.stdout.rstrip().decode('utf-8').split("\n")

        pool_name = "kubernetes-packet-volume-" + options.volumeName

        assert lines[1] == pool_name

        # Test creating a file
        test_path = mount_dir + "/test.txt"

        try:
            count = 0
            with open(test_path, "a+") as test_fh:
                print("%s %s Hello from tester" % (int(time.time()), gethostname()), file=test_fh)
                test_fh.seek(0)
                for line in test_fh.readlines():
                    count = count + 1
                    self.log.info("%s:%d - %s", test_path, count, line.rstrip())

        except IOError:
            raise self.fail("Failed to create {}".format(test_path))

    def test_file_check_after_umount(self, mount_dir, options):
        """ Check for test file after unmuont """
        result = self.pipe_exec(["df", "--output=source", mount_dir], log_stdout=True)

        lines = result.stdout.rstrip().decode('utf-8').split("\n")

        pool_name = "kubernetes-packet-volume-" + options.volumeName

        assert lines[1] != pool_name

        test_path = mount_dir + "/test.txt"

        if os.path.isfile(test_path):
            raise self.fail("{} still exists after umount!".format(test_path))

    def test_pause_input(self, prompt): # pylint: disable=no-self-use
        """ Pause for user input (for manual inspection) """
        if self.batch:
            self.log.info("** Skipped **")
            return

        pause_time = time.time()
        input(prompt)
        self.start_time += (time.time() - pause_time)

    def capture_output(self, func): # pylint: disable=no-self-use
        """ Run a function capturing stderr/stdout """

        out = io.StringIO()
        err = io.StringIO()
        ret_val = None

        with redirect_stderr(err):
            with redirect_stdout(out):
                ret_val = func()

        return (ret_val, out.getvalue(), err.getvalue())

    def filter(self, record):
        """ logging filter for simple coloring """
        color = self.set_white

        if record.levelname == "ERROR":
            color = self.set_red

        if record.levelname == "DEBUG":
            color = self.set_blue

        if record.levelname == "INFO":
            color = self.set_yellow

        if record.levelname == "WARNING":
            color = self.set_magenta

        delta_time = int(time.time() - self.start_time)

        record.msg = "".join([color, "(%ds) " % delta_time, record.msg, self.set_sgr0])

        return True

    def banner(self, src, color=None):
        import zlib
        import base64
        print("".join([color or self.set_green, zlib.decompress(base64.b64decode(src)).decode("ascii"), self.set_sgr0]))

    def run(self):
        """ Run tests """
        if os.geteuid() != 0:
            self.log.error("Live test requires root so it can use ZFS commands and mount/umount")
            self.log.error("See the %s class in %s for details of what the test does", self.__class__.__name__, __file__)
            sys.exit(126)

        json_options = """{
		"kubernetes.io/fsType":"zfs",
		"kubernetes.io/pod.name":"fv-packet-zfs-test",
		"kubernetes.io/pod.namespace":"default",
		"kubernetes.io/pod.uid":"2fcb0a1a-ab51-11e7-930b-a23ebe066c72",
		"kubernetes.io/pvOrVolumeName":"fv-packet-zfs-test1",
		"kubernetes.io/readwrite":"rw",
		"kubernetes.io/serviceAccount.name":"default",
		"packet.net/sizeGb":"20",
		"packet.net/numVolumes":"2",
		"packet.net/zfs/vdevType":"mirror",
		"packet.net/zfs/createOptions":"-o ashift=13 -O recordsize=16k",
		"packet.net/zfs/snapshotOnMount":"true",
		"packet.net/retainVolumes":"false"
	}"""

        try:
            json.loads(json_options)
            json_options = json_options.replace("\n", "").replace("\t", "").rstrip()
        except Exception: # pylint: disable=broad-except
            print("unit_test setup error, invalid json: {}".format(traceback.format_exc()))
            sys.exit(1)

        from flexvolume.packet import plugin

        self.plugin = plugin.Plugin(logger=self.log)

        options = self.plugin.parse_options(json_options)

        assert options != None

        device = self.plugin.find_device()

        assert device != None

        print("Device: {} ({})".format(device.hostname, device.id))

        tests = [
            ("test_operation", "init", [], "Success"),
            ("test_operation", "getvolumename", [json_options], "Not supported"), # Expected because in v1.8 flexvolume attach is a bit broken
            ("test_file_check_before_mount", "/mnt", options),
            ("test_operation", "mount", ["/mnt", json_options], "Success"),
            ("test_file_check_after_mount", "/mnt", options),
            ("test_pause_input", "Press <ENTER> to continue: "),
            ("test_operation", "unmount", ["/mnt"], "Success"),
            ("test_file_check_after_umount", "/mnt", options),
        ]

        for step in tests:
            print("#" * 80)
            print("## " + str(step))
            print("#" * 80)
            func = getattr(self, step[0])

            try:
                result = func(*step[1:])
            except _PluginTestLiveError:
                print(">> TEST FAILURE AT: {}".format(step))
                self.banner('eJxTVgYDBSCAEEA2mAFhg+UgFBdMGKQSpgGuFIVGUquMwDjVQh2gDBNFVosqx4XuNGLcgNVcAmoR3kanATIcJtU=', color=self.set_red)
                return 127

            print("{}PASS: {}, result = {}{}".format(self.set_green, step, result, self.set_sgr0))
            print("#" * 80, end="\n\n")

        self.banner("eJxTUAYBBQUgUgCTUD6MVlZGZsDEuWDK8dMK6OJc2MUVcNNcCmgOxFABdReaAxVQlOO2CN06cj2GHm7EhSMAhYkw2A==")

        return 0

if __name__ == "__main__":
    sys.path.append(os.path.normpath(os.path.dirname(__file__) + "../../../../"))

    batch = False

    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        batch = True

    sys.exit(PluginTestLive(batch=batch).run())
