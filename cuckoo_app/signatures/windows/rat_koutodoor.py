# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Koutodoor(Signature):
    name = "rat_koutodoor"
    #description = "Creates known Koutodoor Trojan files, registry keys and/or mutexes"
    description = u"创建已知的koutodoor木马文件、注册表密钥以及互斥器"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["rat"]
    families = ["koutodoor"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        ".*ksdrv",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
