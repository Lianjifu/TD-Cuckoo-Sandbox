# -*- coding:utf-8 -*-
# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Powerfun(Signature):
    name = "powerfun"
    #description = "The Powerfun powershell script has been detected (shellcode injector)"
    description = u"Powerfun Powershell脚本恶意执行（shellcode注入器）"
    severity = 5
    ttp = ["T1055"]
    categories = ["script", "malware", "injector"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "Powerfun":
            return

        self.mark_config({
            "family": "Powerfun injector",
        })
        return True
