# -*- coding:utf-8 -*-
# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex

from lib.cuckoo.common.abstracts import Signature

class AppLockerBypass(Signature):
    name = "applocker_bypass"
    #description = "Powershell script bypasses AppLocker by calling regsvr32"
    description = u"powershell脚本通过调用regsvr32绕过软件锁"
    severity = 3
    ttp = ["T1059.001"]
    categories = ["applocker", "bypass"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "ApplockerBypass":
            return

        args = shlex.split(match.string("cmdline"))
        for idx, arg in enumerate(args):
            if arg.startswith("/i:") and len(arg) != 3:
                self.mark_config({
                    "family": "Powershell-based AppLocker Bypass",
                    "url": arg[3:],
                })
                return True
