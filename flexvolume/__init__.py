#!/usr/bin/python3
"""
Run the plugin

Kubernetes expects this file to be on nodes at:

    /usr/libexec/kubernetes/kubelet-plugins/volume/exec/packet~flexvolume/flexvolume

"""

import sys
from .packet import run_plugin

if __name__ == '__main__':
    sys.exit(run_plugin())
