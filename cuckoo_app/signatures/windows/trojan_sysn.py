# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TrojanSysn(Signature):
    name = "trojan_sysn"
    #description = "Creates known Sysn Trojan Files, Registry Keys and/or Mutexes"
    description = u"创建已知的Sysn木马文件、注册表项以及互斥锁"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["trojan"]
    families = ["sysn"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*Stirfeld",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
