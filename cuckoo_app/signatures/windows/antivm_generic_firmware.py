# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VMFirmware(Signature):
    name = "antivm_firmware"
    #description = "Detects Virtual Machines through their custom firmware"
    description = u"利用自定义固件检测虚拟机"
    severity = 3
    ttp = ["T1497"]
    categories = ["anti-vm"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "NtQuerySystemInformation"

    def on_call(self, call, process):
        if call["flags"]["information_class"] == "SystemFirmwareTableInformation":
            self.mark_call()
            return True
