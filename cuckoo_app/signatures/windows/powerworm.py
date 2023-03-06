# -*- coding:utf-8 -*-
# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Powerworm(Signature):
    name = "powerworm"
    #description = "The Powerworm powershell script has been detected"
    description = u"检测到Powerworn Powershell恶意脚本"
    severity = 5
    ttp = ["T1059.001"]
    categories = ["script", "malware", "powershell", "worm"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowerWorm":
            return

        self.mark_config({
            "family": "PowerWorm",
            "url": match.string("payload", 0),
        })
        return True
