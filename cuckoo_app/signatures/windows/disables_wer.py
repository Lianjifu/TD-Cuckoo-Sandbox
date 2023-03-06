# -*- coding:utf-8 -*-
# Copyright (C) 2015 Kevin Ross, Updated 2016 for Cukoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesWER(Signature):
    name = "disables_wer"
    #description = "Attempts to disable Windows Error Reporting"
    description = u"尝试禁用Windows错误报告"
    severity = 3
    ttp = ["T1484.001"]
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\Windows\\ Error\\ Reporting\\\\Disabled$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
