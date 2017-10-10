# Copyright (c) 2017 Karl Bunch <karlbunch@karlbunch.com>

""" Simple defs for command line entry points

    Kubernetes expects the command line script to be in:

    /usr/libexec/kubernetes/kubelet-plugins/volume/exec/packet~flexvolume/flexvolume
"""

import sys

def run_plugin():
    """ Run flexvolume plugin """
    from flexvolume.packet.plugin import Run
    Run(sys.argv[1:])
