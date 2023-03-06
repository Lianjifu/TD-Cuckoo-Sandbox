# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiSandboxIdleTime(Signature):
    name = "antisandbox_idletime"
    #description = "Looks for the Windows Idle Time to determine the uptime" 
    description = u"侦听窗口空心时间确定正常运行时间"
    severity = 3
    ttp = ["T1497.002"]
    categories = ["anti-sandbox"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "NtQuerySystemInformation"

    def on_call(self, call, processs):
        if call["flags"]["information_class"] == \
                "SystemProcessorPerformanceInformation":
            self.mark_call()
            return True
