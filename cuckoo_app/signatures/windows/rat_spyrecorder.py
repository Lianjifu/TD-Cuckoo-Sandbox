# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Spyrecorder(Signature):
    name = "spyrecorder"
    #description = "Creates known Spy Recorder files, registry keys and/or mutexes"
    description = u"创建已知的间谍记录器文件、注册表键以及互斥器"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["rat"]
    families = ["spyrecorder"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Spy\\ Monitor\\ Screen\\ Recorder",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
