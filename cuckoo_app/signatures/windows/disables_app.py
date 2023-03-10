# -*- coding:utf-8 -*-
# Copyright (C) 2015 Kevin Ross, Updated 2016 For Cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesAppLaunch(Signature):
    name = "disables_app_launch"
    #description = "Modifies system policies to prevent the launching of specific applications or executables"
    description = u"修改系统策略以防止启动特定的应用程序或可执行文件"
    severity = 3
    ttp = ["T1484.001"]
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\DisallowRun$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
